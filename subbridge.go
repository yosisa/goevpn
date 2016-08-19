package main

import (
	"bytes"
	"log"
	"net"
	"regexp"
	"strconv"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hkwi/gopenflow/ofp4"
	"github.com/yosisa/gof"
)

var patchPortPattern = regexp.MustCompile(`^p(\d+)d$`)

type subBridgeHandler struct {
	gof.NopFancyHandler
	IdleTimeout  uint16
	vni          uint32
	upstreamPort uint32
	macip        map[string]net.IP
	m            sync.Mutex
	bgp          *GoBGP
}

func (h *subBridgeHandler) Features(w *gof.Writer, d ofp4.SwitchFeatures) {
	write(w, &gof.MultipartRequest{Type: ofp4.OFPMP_PORT_DESC})
	write(w, &gof.FlowMod{
		Priority: 10,
		Matches:  gof.Matches(gof.EthType(gof.EthTypeARP)),
		Instructions: gof.Instructions(
			gof.ApplyActions(gof.Output(ofp4.OFPP_CONTROLLER)),
			gof.GotoTable(1),
		),
	})
	write(w, &gof.FlowMod{
		Instructions: gof.Instructions(gof.GotoTable(1)),
	})
	write(w, &gof.FlowMod{
		TableID: 1,
		Instructions: gof.Instructions(gof.ApplyActions(
			gof.Output(ofp4.OFPP_NORMAL),
			gof.Output(ofp4.OFPP_CONTROLLER),
		)),
	})
}

func (h *subBridgeHandler) MultipartReply(w *gof.Writer, d ofp4.MultipartReply) {
	parsePortInfo(d, func(p ofp4.Port) {
		name := gof.PortName(p.Name())
		if m := patchPortPattern.FindStringSubmatch(name); m != nil {
			n, err := strconv.ParseUint(m[1], 10, 32)
			if err != nil {
				return
			}
			h.vni = uint32(n)
			h.upstreamPort = p.PortNo()
		}
	})
	if h.upstreamPort == 0 {
		return
	}
	write(w, &gof.FlowMod{
		TableID:      1,
		Priority:     10,
		Matches:      gof.Matches(gof.InPort(h.upstreamPort)),
		Instructions: gof.Instructions(gof.ApplyActions(gof.Output(ofp4.OFPP_NORMAL))),
	})
}

func (h *subBridgeHandler) PacketIn(w *gof.Writer, d ofp4.PacketIn) {
	// Discard
	write(w, &gof.PacketOut{BufferID: d.BufferId()})
	if h.vni == 0 {
		log.Printf("PacketIn: VNI not configured")
		return
	}

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

	if p.Port == h.upstreamPort {
		return
	}

	pkt := gopacket.NewPacket(d.Data(), layers.LayerTypeEthernet, gopacket.NoCopy)
	eth, _ := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth == nil {
		log.Print("PacketIn: Failed to decode packet")
		return
	}
	log.Printf("PacketIn: table=%d in_port=%d eth_src=%v eth_dst=%v", d.TableId(), p.Port, eth.SrcMAC, eth.DstMAC)

	h.learnLocalMAC(w, eth.SrcMAC, pkt)
}

func (h *subBridgeHandler) learnLocalMAC(w *gof.Writer, src net.HardwareAddr, pkt gopacket.Packet) {
	h.m.Lock()
	defer h.m.Unlock()
	if h.macip == nil {
		h.macip = make(map[string]net.IP)
	}

	mac := src.String()
	ip, ok := h.macip[mac]
	if !ok {
		h.macip[mac] = nil
		write(w, &gof.FlowMod{
			TableID:      1,
			Priority:     5,
			IdleTimeout:  h.IdleTimeout,
			Flags:        ofp4.OFPFF_SEND_FLOW_REM,
			Matches:      gof.Matches(gof.EthSrc(src)),
			Instructions: gof.Instructions(gof.ApplyActions(gof.Output(ofp4.OFPP_NORMAL))),
		})
		h.modPath(src, nil, h.vni, false)
	}

	arp, _ := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	if arp == nil {
		return
	}
	sha, spa := net.HardwareAddr(arp.SourceHwAddress), net.IP(arp.SourceProtAddress)
	if !bytes.Equal(src, sha) {
		return // Invalid packet?
	}
	if bytes.Equal(ip, spa) {
		return
	}

	if ip != nil {
		// Remove old entry
		h.modPath(sha, ip, h.vni, true)
	}
	h.macip[mac] = spa
	h.modPath(sha, spa, h.vni, false)
}

func (h *subBridgeHandler) FlowRemoved(W *gof.Writer, d ofp4.FlowRemoved) {
	if h.vni == 0 {
		log.Printf("FlowRemoved: VNI not configured")
		return
	}

	oxm, err := gof.ParseOXMFields(d.Match().OxmFields())
	if err != nil {
		log.Printf("FlowRemoved: Failed to parse OXM fields: %v", err)
		return
	}

	src := oxm.EthSrc()
	if src == nil {
		log.Printf("FlowRemoved: eth src not found")
		return
	}

	h.modPath(src.Addr, nil, h.vni, true)

	mac := src.Addr.String()
	h.m.Lock()
	defer h.m.Unlock()
	ip, ok := h.macip[mac]
	if ok {
		delete(h.macip, mac)
	}
	if ip != nil {
		h.modPath(src.Addr, ip, h.vni, true)
	}
}

func (h *subBridgeHandler) modPath(mac net.HardwareAddr, ip net.IP, vni uint32, withdraw bool) {
	if err := h.bgp.ModPath(mac, ip, vni, withdraw); err != nil {
		log.Printf("Failed to mod path: mac=%v ip=%v vni=%d withdraw=%v err=%v", mac, ip, vni, withdraw, err)
	}
}
