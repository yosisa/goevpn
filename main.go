package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hkwi/gopenflow/ofp4"
	"github.com/spf13/viper"
	"github.com/yosisa/gof"
	"github.com/yosisa/gof/nxm"
)

var gwMAC = net.HardwareAddr{0xfe, 0xed, 0xde, 0xad, 0xbe, 0xef}

type PortDesc struct {
	Port     uint32
	IP       net.IP
	TunnelID uint64
	NextHop  net.IP
}

type Gateway struct {
	Address     net.IP
	ConnectedTo []uint32
}

type Handler struct {
	Timeout      uint16
	macTable     map[uint32]map[string]*PortDesc
	vteps        map[uint32]map[uint32]net.IP
	ports        map[string]uint32
	pnameToVNI   map[string]uint32
	portToVNI    map[uint32]uint32
	vniToPorts   map[uint32][]uint32
	vniToGateway map[uint32]*Gateway
	buffered     map[uint32]map[string][]uint32
	vxlanPort    uint32
	suppressARP  bool
	bgp          *GoBGP
	runOnce      sync.Once
	m            sync.Mutex
	w            *gof.Writer
}

func NewHandler() *Handler {
	return &Handler{
		macTable:     make(map[uint32]map[string]*PortDesc),
		vteps:        make(map[uint32]map[uint32]net.IP),
		ports:        make(map[string]uint32),
		pnameToVNI:   make(map[string]uint32),
		portToVNI:    make(map[uint32]uint32),
		vniToPorts:   make(map[uint32][]uint32),
		vniToGateway: make(map[uint32]*Gateway),
		buffered:     make(map[uint32]map[string][]uint32),
	}
}

func (h *Handler) Features(w *gof.Writer, d ofp4.SwitchFeatures) {
	h.w = w
	h.write(w, &gof.MultipartRequest{Type: ofp4.OFPMP_PORT_DESC})
	h.write(w, &gof.FlowMod{
		Priority: 10,
		Matches:  gof.Matches(gof.EthType(gof.EthTypeARP)),
		Instructions: gof.Instructions(
			gof.ApplyActions(gof.Output(ofp4.OFPP_CONTROLLER)),
			gof.GotoTable(1),
		),
	})
	h.write(w, &gof.FlowMod{
		Instructions: gof.Instructions(gof.GotoTable(1)),
	})
	h.write(w, &gof.FlowMod{
		TableID:      1,
		Priority:     10,
		Matches:      gof.Matches(gof.InPort(h.vxlanPort)),
		Instructions: gof.Instructions(gof.GotoTable(2)),
	})
	h.write(w, &gof.FlowMod{
		TableID:      1,
		Instructions: gof.Instructions(gof.ApplyActions(gof.Output(ofp4.OFPP_CONTROLLER))),
	})
	h.write(w, &gof.FlowMod{
		TableID:      2,
		Instructions: gof.Instructions(gof.ApplyActions(gof.Output(ofp4.OFPP_CONTROLLER))),
	})
	h.runOnce.Do(func() {
		go h.bgp.WatchRIB()
	})
}

func (h *Handler) PacketIn(w *gof.Writer, d ofp4.PacketIn) {
	port, vni, _, err := h.getPortAndVNI(d.Match().OxmFields())
	if err != nil {
		log.Printf("PacketIn: %v", err)
		return
	}

	var actions []gof.ActionMarshaler
	var doNothing bool
	defer func() {
		if !doNothing {
			h.write(w, &gof.PacketOut{
				BufferID: d.BufferId(),
				InPort:   port,
				Actions:  actions,
			})
		}
	}()

	pkt := gopacket.NewPacket(d.Data(), layers.LayerTypeEthernet, gopacket.NoCopy)
	eth, _ := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth == nil {
		log.Print("PacketIn: Failed to decode packet")
		return
	}
	log.Printf("PacketIn: table=%d in_port=%d vni=%d eth_src=%v eth_dst=%v", d.TableId(), port, vni, eth.SrcMAC, eth.DstMAC)

	h.m.Lock()
	defer h.m.Unlock()

	macTable, ok := h.macTable[vni]
	if !ok {
		macTable = make(map[string]*PortDesc)
		h.macTable[vni] = macTable
	}

	if port != h.vxlanPort {
		h.learnLocalMAC(macTable, port, vni, eth.SrcMAC, pkt)
	}

	if d.TableId() == 0 {
		return // table 0 used for sniffing, no need to forward.
	}

	if bytes.Equal(eth.DstMAC, gwMAC) {
		doNothing = h.gatewayAction(port, vni, d.BufferId(), eth.SrcMAC, pkt)
	} else if desc, ok := macTable[eth.DstMAC.String()]; ok {
		actions = h.installForwardEntry(port, vni, eth.DstMAC, desc)
	} else {
		actions = h.makeForwardAction(vni, port)
	}
}

func (h *Handler) getPortAndVNI(b []byte) (port uint32, vni uint32, oxm *gof.OXMFields, err error) {
	oxm, err = gof.ParseOXMFields(b)
	if err != nil {
		err = fmt.Errorf("Failed to parse OXM fields: %v", err)
		return
	}

	p := oxm.InPort()
	if p == nil {
		err = fmt.Errorf("Port not found")
		return
	}
	port = p.Port

	if port != h.vxlanPort {
		h.m.Lock()
		defer h.m.Unlock()

		var ok bool
		if vni, ok = h.portToVNI[port]; !ok {
			err = fmt.Errorf("VNI not configured for port %d", port)
		}
	} else {
		v := oxm.TunnelID()
		if v == nil {
			err = fmt.Errorf("Failed to get tunnel id")
		}
		vni = uint32(v.ID)
	}
	return
}

func (h *Handler) learnLocalMAC(table map[string]*PortDesc, port uint32, vni uint32, src net.HardwareAddr, pkt gopacket.Packet) {
	mac := src.String()
	desc, ok := table[mac]
	if !ok {
		desc = &PortDesc{}
		table[mac] = desc
		h.write(h.w, &gof.FlowMod{
			TableID:      1,
			Priority:     1,
			IdleTimeout:  h.Timeout,
			Flags:        ofp4.OFPFF_SEND_FLOW_REM,
			Matches:      gof.Matches(gof.InPort(port), gof.EthSrc(src)),
			Instructions: gof.Instructions(gof.GotoTable(2)),
		})
		h.modPath(src, nil, vni, false)
	}
	desc.Port = port

	arp, _ := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	if arp == nil {
		return
	}
	sha, spa := net.HardwareAddr(arp.SourceHwAddress), net.IP(arp.SourceProtAddress)
	if !bytes.Equal(src, sha) {
		return // Invalid packet?
	}
	if bytes.Equal(desc.IP, spa) {
		return
	}

	if desc.IP != nil {
		// Remove old entry
		h.modPath(sha, desc.IP, vni, true)
	}
	desc.IP = spa
	h.modPath(sha, spa, vni, false)
}

func (h *Handler) gatewayAction(port uint32, vni uint32, bufid uint32, src net.HardwareAddr, pkt gopacket.Packet) (keepPacket bool) {
	gw, ok := h.vniToGateway[vni]
	if !ok || len(gw.ConnectedTo) == 0 {
		return false
	}

	ip, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip != nil {
		for _, nei := range gw.ConnectedTo {
			req, err := makeARPRequest(h.vniToGateway[nei].Address, ip.DstIP)
			if err != nil {
				log.Print("Failed to make arp request: %v", err)
				continue
			}
			h.write(h.w, &gof.PacketOut{
				BufferID: ofp4.OFP_NO_BUFFER,
				InPort:   port,
				Actions:  h.makeForwardAction(nei, port),
				Data:     req,
			})
		}
		ipstr := ip.DstIP.String()
		buffered, ok := h.buffered[vni]
		if !ok {
			buffered = make(map[string][]uint32)
			h.buffered[vni] = buffered
		}
		buffered[ipstr] = append(buffered[ipstr], bufid)
		return true
	}

	arp, _ := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	if arp != nil && arp.Operation == layers.ARPReply {
		for _, nei := range gw.ConnectedTo {
			ip := net.IP(arp.SourceProtAddress)
			actions := gof.Actions(
				gof.SetField(gof.EthDst(src)),
				gof.SetField(gof.EthSrc(gwMAC)),
				gof.Output(port),
			)
			for _, m := range h.vniPortMatches(nei) {
				h.write(h.w, &gof.FlowMod{
					TableID:  2,
					Priority: 20,
					Matches: gof.Matches(
						m,
						gof.EthType(gof.EthTypeIP),
						gof.EthDst(gwMAC),
						gof.IPv4Dst(ip),
					),
					Instructions: gof.Instructions(gof.ApplyActions(actions...)),
				})
			}
			h.sendBufferedPackets(nei, ip, actions)
		}
	}
	return false
}

func (h *Handler) makeForwardAction(vni uint32, inPort uint32) (actions []gof.ActionMarshaler) {
	for _, pno := range h.vniToPorts[vni] {
		if pno != inPort {
			actions = append(actions, gof.Output(pno))
		}
	}
	if inPort != h.vxlanPort {
		for _, vtep := range h.vteps[vni] {
			actions = append(actions,
				gof.SetField(gof.TunnelID(uint64(vni))),
				gof.SetField(nxm.TunnelIPv4Dst(vtep)),
				gof.Output(h.vxlanPort),
			)
		}
	}
	return
}

func (h *Handler) sendBufferedPackets(vni uint32, ip net.IP, actions []gof.ActionMarshaler) {
	buffered, ok := h.buffered[vni]
	if !ok {
		return
	}

	ipstr := ip.String()
	for _, bufid := range buffered[ipstr] {
		h.write(h.w, &gof.PacketOut{
			BufferID: bufid,
			Actions:  actions,
		})
	}
	delete(buffered, ipstr)
}

func (h *Handler) installForwardEntry(port uint32, vni uint32, dst net.HardwareAddr, desc *PortDesc) (actions []gof.ActionMarshaler) {
	var match gof.MatchMarshaler
	if port == h.vxlanPort {
		match = gof.TunnelID(uint64(vni))
	} else {
		match = gof.InPort(port)
	}

	if desc.NextHop == nil {
		actions = gof.Actions(gof.Output(desc.Port))
		h.write(h.w, &gof.FlowMod{
			TableID:      2,
			Priority:     10,
			Matches:      gof.Matches(match, gof.EthDst(dst)),
			Instructions: gof.Instructions(gof.ApplyActions(actions...)),
		})
	} else {
		actions = gof.Actions(
			gof.SetField(gof.TunnelID(desc.TunnelID)),
			gof.SetField(nxm.TunnelIPv4Dst(desc.NextHop)),
			gof.Output(desc.Port),
		)
		h.write(h.w, &gof.FlowMod{
			TableID:      2,
			Priority:     5,
			Matches:      gof.Matches(match, gof.EthDst(dst)),
			Instructions: gof.Instructions(gof.ApplyActions(actions...)),
		})
	}
	return actions
}

func (h *Handler) FlowRemoved(w *gof.Writer, d ofp4.FlowRemoved) {
	_, vni, oxm, err := h.getPortAndVNI(d.Match().OxmFields())
	if err != nil {
		log.Printf("FlowRemoved: %v", err)
		return
	}
	src := oxm.EthSrc()
	if src == nil {
		return
	}
	h.modPath(src.Addr, nil, vni, true)
	mac := src.Addr.String()

	h.m.Lock()
	defer h.m.Unlock()

	matches := gof.Matches(gof.TunnelID(uint64(vni)))
	for _, pno := range h.vniToPorts[vni] {
		matches = append(matches, gof.InPort(pno))
	}
	for _, m := range matches {
		h.write(w, &gof.FlowMod{
			TableID:  2,
			Command:  ofp4.OFPFC_DELETE,
			OutPort:  ofp4.OFPP_ANY,
			OutGroup: ofp4.OFPG_ANY,
			Matches:  gof.Matches(m, gof.EthDst(src.Addr)),
		})
	}

	macTable, ok := h.macTable[vni]
	if !ok {
		log.Print("FlowRemoved: mac table does not exist")
	}
	desc, ok := macTable[mac]
	if !ok {
		log.Print("FlowRemoved: PortDesc not defined for %s", mac)
		return
	}
	delete(macTable, mac)

	if desc.IP == nil {
		return
	}
	h.modPath(src.Addr, desc.IP, vni, true)

	if gw, ok := h.vniToGateway[vni]; ok {
		for _, nei := range gw.ConnectedTo {
			for _, m := range h.vniPortMatches(nei) {
				h.write(w, &gof.FlowMod{
					TableID:  2,
					Command:  ofp4.OFPFC_DELETE,
					OutPort:  ofp4.OFPP_ANY,
					OutGroup: ofp4.OFPG_ANY,
					Matches: gof.Matches(
						m,
						gof.EthDst(gwMAC),
						gof.EthType(gof.EthTypeIP),
						gof.IPv4Dst(desc.IP),
					),
				})
			}
		}
	}
}

func (h *Handler) MultipartReply(w *gof.Writer, d ofp4.MultipartReply) {
	if d.Type() != ofp4.OFPMP_PORT_DESC {
		return
	}
	body := d.Body()

	portToVNI := make(map[uint32]uint32)
	vniToPorts := make(map[uint32][]uint32)
	for i := 0; i < len(body); i += 64 {
		port := ofp4.Port(body[i:])
		no := port.PortNo()
		if no == ofp4.OFPP_LOCAL {
			continue
		}
		vni, ok := h.pnameToVNI[gof.PortName(port.Name())]
		if ok {
			portToVNI[no] = vni
			vniToPorts[vni] = append(vniToPorts[vni], no)
		}
	}
	h.m.Lock()
	defer h.m.Unlock()
	h.portToVNI = portToVNI
	h.vniToPorts = vniToPorts

	for vni, gw := range h.vniToGateway {
		for _, m := range h.vniPortMatches(vni) {
			h.write(w, &gof.FlowMod{
				TableID:  2,
				Priority: 20,
				Matches: gof.Matches(
					m,
					gof.EthType(gof.EthTypeARP),
					gof.ARPOp(gof.ARPOpRequest),
					gof.ARPTpa(gw.Address),
				),
				Instructions: gof.Instructions(gof.ApplyActions(
					gof.SetField(gof.ARPOp(gof.ARPOpReply)),
					nxm.NXRegMove(nxm.NXM_OF_ETH_SRC, nxm.NXM_OF_ETH_DST, 48),
					gof.SetField(gof.EthSrc(gwMAC)),
					nxm.NXRegMove(nxm.NXM_NX_ARP_SHA, nxm.NXM_NX_ARP_THA, 48),
					nxm.NXRegMove(nxm.NXM_OF_ARP_SPA, nxm.NXM_OF_ARP_TPA, 32),
					gof.SetField(gof.ARPSha(gwMAC)),
					gof.SetField(gof.ARPSpa(gw.Address)),
					gof.Output(ofp4.OFPP_IN_PORT),
				)),
			})
		}
	}
}

func (h *Handler) AddMacIPRoute(etag uint32, mac net.HardwareAddr, ip net.IP, nexthop net.IP) {
	log.Printf("AddMacIPRoute: etag=%d mac=%v ip=%v nexthop=%v", etag, mac, ip, nexthop)
	h.m.Lock()
	defer h.m.Unlock()
	macTable, ok := h.macTable[etag]
	if !ok {
		macTable = make(map[string]*PortDesc)
		h.macTable[etag] = macTable
	}

	macTable[mac.String()] = &PortDesc{
		Port:     h.vxlanPort,
		IP:       ip,
		TunnelID: uint64(etag),
		NextHop:  nexthop,
	}
	if ip == nil {
		return
	}
	if h.suppressARP {
		for _, m := range h.vniPortMatches(etag) {
			h.write(h.w, &gof.FlowMod{
				TableID:  2,
				Priority: 20,
				Matches: gof.Matches(
					m,
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
			})
		}
	}
	if gw, ok := h.vniToGateway[etag]; ok {
		for _, nei := range gw.ConnectedTo {
			actions := gof.Actions(
				gof.SetField(gof.EthDst(mac)),
				gof.SetField(gof.EthSrc(gwMAC)),
				gof.SetField(gof.TunnelID(uint64(etag))),
				gof.SetField(nxm.TunnelIPv4Dst(nexthop)),
				gof.Output(h.vxlanPort),
			)
			for _, m := range h.vniPortMatches(nei) {
				h.write(h.w, &gof.FlowMod{
					TableID:  2,
					Priority: 20,
					Matches: gof.Matches(
						m,
						gof.EthType(gof.EthTypeIP),
						gof.EthDst(gwMAC),
						gof.IPv4Dst(ip),
					),
					Instructions: gof.Instructions(gof.ApplyActions(actions...)),
				})
			}
			h.sendBufferedPackets(nei, ip, actions)
		}
	}
}

func (h *Handler) DeleteMacIPRoute(etag uint32, mac net.HardwareAddr, ip net.IP, nexthop net.IP) {
	log.Printf("DeleteMacIPRoute: etag=%d mac=%v ip=%v nexthop=%v", etag, mac, ip, nexthop)
	h.m.Lock()
	defer h.m.Unlock()
	macTable, ok := h.macTable[etag]
	if !ok {
		macTable = make(map[string]*PortDesc)
		h.macTable[etag] = macTable
	}

	delete(macTable, mac.String())
	h.write(h.w, &gof.FlowMod{
		TableID:  2,
		Command:  ofp4.OFPFC_DELETE,
		OutPort:  ofp4.OFPP_ANY,
		OutGroup: ofp4.OFPG_ANY,
		Matches:  gof.Matches(gof.EthDst(mac)),
	})
	if ip == nil {
		return
	}
	if h.suppressARP {
		for _, m := range h.vniPortMatches(etag) {
			h.write(h.w, &gof.FlowMod{
				TableID:  2,
				Command:  ofp4.OFPFC_DELETE,
				OutPort:  ofp4.OFPP_ANY,
				OutGroup: ofp4.OFPG_ANY,
				Matches:  gof.Matches(m, gof.EthType(gof.EthTypeARP), gof.ARPTpa(ip)),
			})
		}
	}
	if gw, ok := h.vniToGateway[etag]; ok {
		for _, nei := range gw.ConnectedTo {
			for _, m := range h.vniPortMatches(nei) {
				h.write(h.w, &gof.FlowMod{
					TableID:  2,
					Command:  ofp4.OFPFC_DELETE,
					OutPort:  ofp4.OFPP_ANY,
					OutGroup: ofp4.OFPG_ANY,
					Matches: gof.Matches(
						m,
						gof.EthDst(gwMAC),
						gof.EthType(gof.EthTypeIP),
						gof.IPv4Dst(ip),
					),
				})
			}
		}
	}
}

func (h *Handler) AddMulticastRoute(etag uint32, ip net.IP, nexthop net.IP) {
	log.Printf("AddMulticastRoute: etag=%d ip=%v nexthop=%v", etag, ip, nexthop)
	h.m.Lock()
	defer h.m.Unlock()
	vteps, ok := h.vteps[etag]
	if !ok {
		vteps = make(map[uint32]net.IP)
		h.vteps[etag] = vteps
	}
	vteps[binary.BigEndian.Uint32(nexthop)] = nexthop
}

func (h *Handler) DeleteMulticastRoute(etag uint32, ip net.IP, nexthop net.IP) {
	log.Printf("DeleteMulticastRoute: etag=%d ip=%v nexthop=%v", etag, ip, nexthop)
	h.m.Lock()
	defer h.m.Unlock()
	if vteps, ok := h.vteps[etag]; ok {
		delete(vteps, binary.BigEndian.Uint32(nexthop))
	}
}

func (h *Handler) write(w *gof.Writer, m gof.Marshaler) {
	b := m.Marshal()
	w.WriteBytes(b)
	switch v := m.(type) {
	case *gof.FlowMod:
		log.Printf("FlowMod: %s", ofp4.FlowMod(b))
	case *gof.PacketOut:
		if len(v.Actions) == 0 {
			return
		}
		ss := make([]string, len(v.Actions))
		for i, a := range v.Actions {
			ss[i] = ofp4.ActionHeader(a.MarshalAction()).String()
		}
		log.Printf("PacketOut: %v", strings.Join(ss, ","))
	case *gof.MultipartRequest:
		log.Printf("MultipartRequest: type=%d", v.Type)
	}
}

func (h *Handler) modPath(mac net.HardwareAddr, ip net.IP, vni uint32, withdraw bool) {
	if err := h.bgp.ModPath(mac, ip, vni, withdraw); err != nil {
		log.Printf("Failed to mod path: mac=%v ip=%v vni=%d withdraw=%v err=%v", mac, ip, vni, withdraw, err)
	}
}

func (h *Handler) vniPortMatches(vni uint32) (matches []gof.MatchMarshaler) {
	for _, p := range h.vniToPorts[vni] {
		matches = append(matches, gof.InPort(p))
	}
	return
}

func makeARPRequest(src, dst net.IP) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       gwMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   gwMAC,
		SourceProtAddress: src.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dst.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func main() {
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal(err)
	}
	var ports []*ConfigPort
	if err := viper.UnmarshalKey("ports", &ports); err != nil {
		log.Fatal(err)
	}

	h := NewHandler()
	bgp := NewGoBGP(viper.GetString("gobgp.addr"), uint16(viper.GetInt("gobgp.as")), h)
	if err := bgp.Connect(); err != nil {
		log.Fatal(err)
	}
	if err := bgp.RegisterVTEP(); err != nil {
		log.Fatal(err)
	}
	h.bgp = bgp

	h.Timeout = uint16(viper.GetInt("idle-timeout"))
	h.vxlanPort = uint32(viper.GetInt("vxlan-port"))
	h.suppressARP = viper.GetBool("suppress-arp")

	advertised := make(map[uint32]struct{})
	for _, port := range ports {
		h.pnameToVNI[port.Name] = port.VNI
		if _, ok := advertised[port.VNI]; !ok {
			advertised[port.VNI] = struct{}{}
			if err := bgp.ModMulticast(port.VNI, false); err != nil {
				log.Fatal(err)
			}
		}
	}

	var gateway ConfigGateway
	if err := viper.UnmarshalKey("gateway", &gateway); err != nil {
		log.Fatal(err)
	}
	if gateway.Enable {
		for _, gws := range gateway.Groups {
			vnis := make([][]uint32, len(gws))
			for i, gw := range gws {
				for j := 0; j < len(gws); j++ {
					if j == i {
						continue
					}
					vnis[j] = append(vnis[j], gw.VNI)
				}
			}

			for i, gw := range gws {
				ip := net.ParseIP(gw.Address)
				if ip == nil {
					log.Fatal("Invalid gateway address: %s", gw.Address)
				}
				h.vniToGateway[gw.VNI] = &Gateway{
					Address:     ip,
					ConnectedTo: vnis[i],
				}
			}
		}
	}

	ctrl := gof.Controller{
		Addr:         viper.GetString("listen"),
		Handler:      h,
		WriteTimeout: 5 * time.Second,
		Concurrency:  5,
	}
	if err := ctrl.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
