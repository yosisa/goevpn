package main

import (
	"log"
	"net"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hkwi/gopenflow/ofp4"
	"github.com/yosisa/gof"
)

func write(w *gof.Writer, m gof.Marshaler) {
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

func parsePortInfo(d ofp4.MultipartReply, f func(ofp4.Port)) {
	if d.Type() != ofp4.OFPMP_PORT_DESC {
		return
	}
	body := d.Body()

	for i := 0; i < len(body); i += 64 {
		p := ofp4.Port(body[i:])
		if p.PortNo() != ofp4.OFPP_LOCAL {
			f(p)
		}
	}
}

type packetBuffer struct {
	m map[uint32]map[string][]uint32
	l sync.Mutex
}

func (b *packetBuffer) Add(port uint32, dst net.IP, bufid uint32) {
	b.l.Lock()
	defer b.l.Unlock()
	if b.m == nil {
		b.m = make(map[uint32]map[string][]uint32)
	}
	bufs, ok := b.m[port]
	if !ok {
		bufs = make(map[string][]uint32)
		b.m[port] = bufs
	}
	ip := dst.String()
	bufs[ip] = append(bufs[ip], bufid)
}

func (b *packetBuffer) Flush(port uint32, dst net.IP, w *gof.Writer, actions []gof.ActionMarshaler) {
	b.l.Lock()
	defer b.l.Unlock()
	bufs, ok := b.m[port]
	if !ok {
		return
	}
	ip := dst.String()
	for _, bufid := range bufs[ip] {
		write(w, &gof.PacketOut{BufferID: bufid, Actions: actions})
	}
	delete(bufs, ip)
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
