package main

import (
	"encoding/binary"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hkwi/gopenflow/ofp4"
	"github.com/yosisa/gof"
	"github.com/yosisa/gof/nxm"
)

var gwMAC = net.HardwareAddr{0xfe, 0xed, 0xde, 0xad, 0xbe, 0xef}

type vxlanHandler struct {
	gof.NopFancyHandler
	w           *gof.Writer
	pm          vxlanPortMap
	vteps       map[uint32]map[uint32]net.IP
	gateways    map[uint32]*Gateway
	pb          packetBuffer
	vxlanPort   uint32
	suppressARP bool
	bgp         *GoBGP
	watchOnce   sync.Once
	m           sync.Mutex
}

func (h *vxlanHandler) Features(w *gof.Writer, d ofp4.SwitchFeatures) {
	h.w = w
	write(w, &gof.MultipartRequest{Type: ofp4.OFPMP_PORT_DESC})
	if h.gateways == nil {
		return
	}
	write(w, &gof.FlowMod{
		Priority:     100,
		Matches:      gof.Matches(gof.EthDst(gwMAC)),
		Instructions: gof.Instructions(gof.GotoTable(1)),
	})
	write(w, &gof.FlowMod{
		TableID:      1,
		Instructions: gof.Instructions(gof.ApplyActions(gof.Output(ofp4.OFPP_CONTROLLER))),
	})
}

func (h *vxlanHandler) MultipartReply(w *gof.Writer, d ofp4.MultipartReply) {
	var resetOnce sync.Once
	parsePortInfo(d, func(p ofp4.Port) {
		resetOnce.Do(func() {
			h.pm.Reset()
		})
		name := gof.PortName(p.Name())
		port := p.PortNo()
		if strings.Contains(name, "vxlan") {
			h.vxlanPort = port
			write(w, &gof.FlowMod{
				Priority: 110,
				Matches:  gof.Matches(gof.InPort(port), gof.EthDst(gwMAC)),
			})
			return
		}
		n, err := strconv.ParseUint(name[1:len(name)-1], 10, 32)
		if err != nil {
			return
		}
		h.pm.Add(&vxlanPortDesc{Port: port, VNI: uint32(n)})

		write(w, &gof.FlowMod{
			Priority:     10,
			Matches:      gof.Matches(gof.TunnelID(n)),
			Instructions: gof.Instructions(gof.ApplyActions(gof.Output(port))),
		})
	})

	h.watchOnce.Do(func() {
		go h.bgp.WatchRIB(h)
		h.pm.Each(func(p *vxlanPortDesc) {
			if err := h.bgp.ModMulticast(p.VNI, false); err != nil {
				log.Printf("Failed to advertise multicast route of vni %d: %v", p.VNI, err)
			}
		})
	})

	for vni, gw := range h.gateways {
		desc := h.pm.FindByVNI(vni)
		if desc == nil {
			continue
		}
		write(w, arpReplyFlow(1, desc.Port, gwMAC, gw.Address))
	}
}

func (h *vxlanHandler) PacketIn(w *gof.Writer, d ofp4.PacketIn) {
	discard := true
	defer func() {
		if discard {
			write(w, &gof.PacketOut{BufferID: d.BufferId()})
		}
	}()

	oxm, err := gof.ParseOXMFields(d.Match().OxmFields())
	if err != nil {
		log.Printf("PacketIn: Failed to parse OXM fields: %v", err)
		return
	}
	p := oxm.InPort()
	if p == nil {
		log.Print("PacketIn: Port not found")
		return
	}

	desc := h.pm.FindByPort(p.Port)
	if desc == nil {
		return
	}
	gw, ok := h.gateways[desc.VNI]
	if !ok || len(gw.ConnectedTo) == 0 {
		return
	}

	pkt := gopacket.NewPacket(d.Data(), layers.LayerTypeEthernet, gopacket.NoCopy)
	ip, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip == nil {
		return
	}

	discard = false
	for _, vni := range gw.ConnectedTo {
		arp, err := makeARPRequest(h.gateways[vni].Address, ip.DstIP)
		if err != nil {
			log.Print("Failed to make arp request: %v", err)
			continue
		}

		var actions []gof.ActionMarshaler
		d := h.pm.FindByVNI(vni)
		if d != nil {
			actions = append(actions, gof.Output(d.Port))
		}
		vteps := h.vteps[vni]
		if len(vteps) > 0 {
			actions = append(actions, gof.SetField(gof.TunnelID(uint64(vni))))
			for _, vtep := range vteps {
				actions = append(actions, gof.SetField(nxm.TunnelIPv4Dst(vtep)), gof.Output(h.vxlanPort))
			}
		}
		write(h.w, &gof.PacketOut{
			BufferID: ofp4.OFP_NO_BUFFER,
			Actions:  actions,
			Data:     arp,
		})
	}
	h.pb.Add(p.Port, ip.DstIP, d.BufferId())
}

func (h *vxlanHandler) AddMulticastRoute(etag uint32, ip net.IP, nexthop net.IP) {
	log.Printf("AddMulticastRoute: etag=%d ip=%v nexthop=%v", etag, ip, nexthop)
	if isLocalHop(nexthop) {
		return
	}

	h.m.Lock()
	defer h.m.Unlock()
	if h.vteps == nil {
		h.vteps = make(map[uint32]map[uint32]net.IP)
	}
	vteps := h.vteps[etag]
	if vteps == nil {
		vteps = make(map[uint32]net.IP)
		h.vteps[etag] = vteps
	}
	vteps[binary.BigEndian.Uint32(nexthop.To4())] = nexthop
	h.updateBUM()
}

func (h *vxlanHandler) DeleteMulticastRoute(etag uint32, ip net.IP, nexthop net.IP) {
	log.Printf("DeleteMulticastRoute: etag=%d ip=%v nexthop=%v", etag, ip, nexthop)
	if isLocalHop(nexthop) {
		return
	}

	h.m.Lock()
	defer h.m.Unlock()
	if vteps, ok := h.vteps[etag]; ok {
		delete(vteps, binary.BigEndian.Uint32(nexthop))
		if len(vteps) == 0 {
			delete(h.vteps, etag)
		}
	}
	h.updateBUM()
}

func (h *vxlanHandler) updateBUM() {
	h.pm.Each(func(p *vxlanPortDesc) {
		vteps := h.vteps[p.VNI]
		if vteps == nil {
			return
		}
		actions := gof.Actions(gof.SetField(gof.TunnelID(uint64(p.VNI))))
		for _, ip := range vteps {
			actions = append(actions, gof.SetField(nxm.TunnelIPv4Dst(ip)), gof.Output(h.vxlanPort))
		}
		write(h.w, &gof.FlowMod{
			Priority:     5,
			Matches:      gof.Matches(gof.InPort(p.Port)),
			Instructions: gof.Instructions(gof.ApplyActions(actions...)),
		})
	})
}

func (h *vxlanHandler) AddMacIPRoute(etag uint32, mac net.HardwareAddr, ip net.IP, nexthop net.IP) {
	log.Printf("AddMacIPRoute: etag=%d mac=%v ip=%v nexthop=%v", etag, mac, ip, nexthop)
	if h.vxlanPort == 0 {
		log.Print("AddMacIPRoute: vxlan port not configured")
		return
	}
	isLocal := isLocalHop(nexthop)
	desc := h.pm.FindByVNI(etag)
	if !isLocal && desc != nil {
		write(h.w, &gof.FlowMod{
			Priority: 10,
			Matches:  gof.Matches(gof.InPort(desc.Port), gof.EthDst(mac)),
			Instructions: gof.Instructions(gof.ApplyActions(
				gof.SetField(gof.TunnelID(uint64(etag))),
				gof.SetField(nxm.TunnelIPv4Dst(nexthop)),
				gof.Output(h.vxlanPort),
			)),
		})
	}
	if ip == nil {
		return
	}

	if !isLocal && h.suppressARP {
		write(h.w, arpReplyFlow(0, desc.Port, mac, ip))
	}
	if gw, ok := h.gateways[etag]; ok {
		actions := gof.Actions(gof.SetField(gof.EthDst(mac)), gof.SetField(gof.EthSrc(gwMAC)))
		if isLocal {
			actions = append(actions, gof.Output(desc.Port))
		} else {
			actions = append(actions,
				gof.SetField(gof.TunnelID(uint64(etag))),
				gof.SetField(nxm.TunnelIPv4Dst(nexthop)),
				gof.Output(h.vxlanPort),
			)
		}
		for _, vni := range gw.ConnectedTo {
			d := h.pm.FindByVNI(vni)
			if d == nil {
				continue
			}
			write(h.w, &gof.FlowMod{
				TableID:      1,
				Priority:     10,
				Matches:      gof.Matches(gof.InPort(d.Port), gof.EthType(gof.EthTypeIP), gof.IPv4Dst(ip)),
				Instructions: gof.Instructions(gof.ApplyActions(actions...)),
			})
			h.pb.Flush(d.Port, ip, h.w, actions)
		}
	}
}

func (h *vxlanHandler) DeleteMacIPRoute(etag uint32, mac net.HardwareAddr, ip net.IP, nexthop net.IP) {
	log.Printf("DeleteMacIPRoute: etag=%d mac=%v ip=%v nexthop=%v", etag, mac, ip, nexthop)
	isLocal := isLocalHop(nexthop)
	desc := h.pm.FindByVNI(etag)
	if !isLocal && desc != nil {
		write(h.w, deleteFlow(0, gof.InPort(desc.Port), gof.EthDst(mac)))
	}
	if ip == nil {
		return
	}

	if !isLocal && h.suppressARP {
		write(h.w, deleteFlow(0, gof.InPort(desc.Port), gof.EthType(gof.EthTypeARP), gof.ARPTpa(ip)))
	}
	if gw, ok := h.gateways[etag]; ok {
		for _, vni := range gw.ConnectedTo {
			d := h.pm.FindByVNI(vni)
			if d == nil {
				continue
			}
			write(h.w, deleteFlow(1, gof.InPort(d.Port), gof.EthType(gof.EthTypeIP), gof.IPv4Dst(ip)))
		}
	}
}

func deleteFlow(table uint8, ms ...gof.MatchMarshaler) *gof.FlowMod {
	return &gof.FlowMod{
		TableID:  table,
		Command:  ofp4.OFPFC_DELETE,
		OutPort:  ofp4.OFPP_ANY,
		OutGroup: ofp4.OFPG_ANY,
		Matches:  ms,
	}
}

func arpReplyFlow(table uint8, port uint32, mac net.HardwareAddr, ip net.IP) *gof.FlowMod {
	return &gof.FlowMod{
		TableID:  table,
		Priority: 15,
		Matches: gof.Matches(
			gof.InPort(port),
			gof.EthType(gof.EthTypeARP),
			gof.ARPOp(gof.ARPOpRequest),
			gof.ARPTpa(ip),
		),
		Instructions: gof.Instructions(gof.ApplyActions(
			gof.SetField(gof.ARPOp(gof.ARPOpReply)),
			nxm.NXRegMove(nxm.NXM_OF_ETH_SRC, nxm.NXM_OF_ETH_DST, 48),
			gof.SetField(gof.EthSrc(mac)),
			nxm.NXRegMove(nxm.NXM_NX_ARP_SHA, nxm.NXM_NX_ARP_THA, 48),
			nxm.NXRegMove(nxm.NXM_OF_ARP_SPA, nxm.NXM_OF_ARP_TPA, 32),
			gof.SetField(gof.ARPSha(mac)),
			gof.SetField(gof.ARPSpa(ip)),
			gof.Output(ofp4.OFPP_IN_PORT),
		)),
	}
}

type vxlanPortDesc struct {
	Port uint32
	VNI  uint32
}

type vxlanPortMap struct {
	portToDesc map[uint32]*vxlanPortDesc
	vniToDesc  map[uint32]*vxlanPortDesc
	m          sync.RWMutex
}

func (m *vxlanPortMap) Add(p *vxlanPortDesc) {
	m.m.Lock()
	defer m.m.Unlock()
	if m.portToDesc == nil {
		m.portToDesc = make(map[uint32]*vxlanPortDesc)
	}
	if m.vniToDesc == nil {
		m.vniToDesc = make(map[uint32]*vxlanPortDesc)
	}
	m.portToDesc[p.Port] = p
	m.vniToDesc[p.VNI] = p
}

func (m *vxlanPortMap) Reset() {
	m.m.Lock()
	defer m.m.Unlock()
	m.portToDesc = nil
	m.vniToDesc = nil
}

func (m *vxlanPortMap) FindByPort(port uint32) *vxlanPortDesc {
	m.m.RLock()
	defer m.m.RUnlock()
	return m.portToDesc[port]
}

func (m *vxlanPortMap) FindByVNI(vni uint32) *vxlanPortDesc {
	m.m.RLock()
	defer m.m.RUnlock()
	return m.vniToDesc[vni]
}

func (m *vxlanPortMap) Each(f func(*vxlanPortDesc)) {
	m.m.RLock()
	defer m.m.RUnlock()
	for _, p := range m.portToDesc {
		f(p)
	}
}
