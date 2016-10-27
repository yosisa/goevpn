package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet/bgp"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const localHop = "0.0.0.0"

var evpnTable = &api.Table{
	Type:   api.Resource_GLOBAL,
	Family: uint32(bgp.RF_EVPN),
}

type BGPHandler interface {
	AddMacIPRoute(uint32, net.HardwareAddr, net.IP, net.IP)
	DeleteMacIPRoute(uint32, net.HardwareAddr, net.IP, net.IP)
	AddMulticastRoute(uint32, net.IP, net.IP)
	DeleteMulticastRoute(uint32, net.IP, net.IP)
}

type GoBGP struct {
	Addr     string
	Timeout  time.Duration
	AS       uint16
	client   api.GobgpApiClient
	routerID string
}

func NewGoBGP(addr string, as uint16) *GoBGP {
	return &GoBGP{
		Addr: addr,
		AS:   as,
	}
}

func (g *GoBGP) Connect() error {
	opts := []grpc.DialOption{grpc.WithBlock(), grpc.WithInsecure()}
	if g.Timeout != 0 {
		opts = append(opts, grpc.WithTimeout(g.Timeout))
	}
	conn, err := grpc.Dial(g.Addr, opts...)
	if err != nil {
		return err
	}
	g.client = api.NewGobgpApiClient(conn)

	resp, err := g.client.GetServer(context.Background(), &api.GetServerRequest{})
	if err != nil {
		return err
	}
	g.routerID = resp.Global.RouterId
	return nil
}

func (g *GoBGP) RegisterVTEP() (err error) {
	path := &api.Path{
		Nlri: mustSerialize(bgp.NewIPAddrPrefix(uint8(32), g.routerID)),
		Pattrs: mustSerializeAll(
			bgp.NewPathAttributeNextHop(localHop),
			bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		),
	}
	_, err = g.client.AddPath(context.Background(), &api.AddPathRequest{
		Resource: api.Resource_GLOBAL,
		Path:     path,
	})
	return
}

func (g *GoBGP) ModVRF(vni uint32, withdraw bool) error {
	rdstr := g.rd(vni)
	rd, err := bgp.ParseRouteDistinguisher(rdstr)
	if err != nil {
		return fmt.Errorf("Failed to parse rd: %v", err)
	}
	rt, err := bgp.ParseRouteTarget(g.rt(vni))
	if err != nil {
		return fmt.Errorf("Failed to parse rt: %v", err)
	}
	rts := mustSerializeAll(rt)
	vrf := &api.Vrf{
		Name:     rdstr,
		Rd:       mustSerialize(rd),
		ImportRt: rts,
		ExportRt: rts,
	}

	if !withdraw {
		_, err = g.client.AddVrf(context.Background(), &api.AddVrfRequest{Vrf: vrf})
		if err != nil && strings.HasSuffix(err.Error(), "already exists") {
			err = nil
		}
	} else {
		_, err = g.client.DeleteVrf(context.Background(), &api.DeleteVrfRequest{Vrf: vrf})
	}
	return err
}

func (g *GoBGP) ModPath(mac net.HardwareAddr, ip net.IP, vni uint32, withdraw bool) error {
	adv := &bgp.EVPNMacIPAdvertisementRoute{
		ESI: bgp.EthernetSegmentIdentifier{
			Type: bgp.ESI_ARBITRARY,
		},
		MacAddressLength: 48,
		MacAddress:       mac,
		Labels:           []uint32{vni},
		ETag:             vni,
	}
	if ip != nil {
		adv.IPAddressLength = 32
		adv.IPAddress = ip
	}
	nlri := bgp.NewEVPNNLRI(bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT, 0, adv)
	ext := bgp.NewOpaqueExtended(true)
	ext.SubType = bgp.EC_SUBTYPE_ENCAPSULATION
	ext.Value = &bgp.EncapExtended{bgp.TUNNEL_TYPE_VXLAN}

	var err error
	path := &api.Path{IsWithdraw: withdraw}
	path.Pattrs, err = serializeAll(
		bgp.NewPathAttributeMpReachNLRI(localHop, []bgp.AddrPrefixInterface{nlri}),
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{ext}),
	)
	if err != nil {
		return err
	}
	return g.addPath(path, vni)
}

func (g *GoBGP) ModMulticast(vni uint32, withdraw bool) error {
	ip := net.ParseIP(g.routerID)
	etag := &bgp.EVPNMulticastEthernetTagRoute{
		RD:              bgp.RouteDistinguisherInterface(nil),
		IPAddressLength: 32,
		IPAddress:       ip,
		ETag:            vni,
	}
	nlri := bgp.NewEVPNNLRI(bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG, 0, etag)
	tunid := &bgp.IngressReplTunnelID{Value: ip}

	var err error
	path := &api.Path{IsWithdraw: withdraw}
	path.Pattrs, err = serializeAll(
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		bgp.NewPathAttributeMpReachNLRI(localHop, []bgp.AddrPrefixInterface{nlri}),
		bgp.NewPathAttributePmsiTunnel(bgp.PMSI_TUNNEL_TYPE_INGRESS_REPL, false, 0, tunid),
	)
	if err != nil {
		return err
	}
	return g.addPath(path, vni)
}

func (g *GoBGP) addPath(path *api.Path, vni uint32) error {
	for {
		_, err := g.client.AddPath(context.Background(), &api.AddPathRequest{
			Resource: api.Resource_VRF,
			VrfId:    g.rd(vni),
			Path:     path,
		})
		if err == nil || path.IsWithdraw || !strings.HasSuffix(err.Error(), "not found") {
			return err
		}
		if err = g.ModVRF(vni, false); err != nil {
			return err
		}
	}
}

func (g *GoBGP) GetRIB(h BGPHandler) error {
	resp, err := g.client.GetRib(context.Background(), &api.GetRibRequest{Table: evpnTable})
	if err != nil {
		return err
	}
	for _, dst := range resp.Table.Destinations {
		if err = g.handleRIBEntry(h, dst); err != nil {
			return err
		}
	}
	return nil
}

func (g *GoBGP) WatchRIB(h BGPHandler) error {
	if err := g.GetRIB(h); err != nil {
		return err
	}

	stream, err := g.client.MonitorRib(context.Background(), evpnTable)
	if err != nil {
		return err
	}
	for {
		dst, err := stream.Recv()
		if err != nil {
			return err
		}
		if err = g.handleRIBEntry(h, dst); err != nil {
			return err
		}
	}
}

func (g *GoBGP) handleRIBEntry(h BGPHandler, dst *api.Destination) error {
	path := findBestPath(dst)
	afi, safi := bgp.RouteFamilyToAfiSafi(bgp.RouteFamily(path.Family))
	nlri, err := bgp.NewPrefixFromRouteFamily(afi, safi)
	if err != nil {
		return err
	}
	evpn, ok := nlri.(*bgp.EVPNNLRI)
	if !ok {
		return nil
	}
	if err = evpn.DecodeFromBytes(path.Nlri); err != nil {
		return err
	}

	nexthop, err := findNextHop(path)
	if err != nil {
		return err
	}
	if nexthop == nil {
		return nil
	}

	switch v := evpn.RouteTypeData.(type) {
	case *bgp.EVPNMacIPAdvertisementRoute:
		if !path.IsWithdraw {
			h.AddMacIPRoute(v.ETag, v.MacAddress, v.IPAddress, nexthop)
		} else {
			h.DeleteMacIPRoute(v.ETag, v.MacAddress, v.IPAddress, nexthop)
		}
	case *bgp.EVPNMulticastEthernetTagRoute:
		if !path.IsWithdraw {
			h.AddMulticastRoute(v.ETag, v.IPAddress, nexthop)
		} else {
			h.DeleteMulticastRoute(v.ETag, v.IPAddress, nexthop)
		}
	}
	return nil
}

func (g *GoBGP) rd(vni uint32) string {
	return fmt.Sprintf("%s:%d", g.routerID, vni)
}

func (g *GoBGP) rt(vni uint32) string {
	return fmt.Sprintf("%d:%d", g.AS, vni)
}

func findBestPath(dst *api.Destination) *api.Path {
	for _, p := range dst.Paths {
		if p.Best {
			return p
		}
	}
	return dst.Paths[0]
}

func findNextHop(path *api.Path) (net.IP, error) {
	for _, attr := range path.Pattrs {
		p, err := bgp.GetPathAttribute(attr)
		if err != nil {
			return nil, err
		}
		err = p.DecodeFromBytes(attr)
		if err != nil {
			return nil, err
		}

		if p.GetType() == bgp.BGP_ATTR_TYPE_MP_REACH_NLRI {
			v := p.(*bgp.PathAttributeMpReachNLRI)
			if len(v.Value) != 1 {
				return nil, fmt.Errorf("Found multiple route in mp_reach_nlri")
			}
			return v.Nexthop, nil
		}
	}
	return nil, nil
}

type serializer interface {
	Serialize() ([]byte, error)
}

func serializeAll(s ...serializer) ([][]byte, error) {
	var err error
	out := make([][]byte, len(s))
	for i, v := range s {
		out[i], err = v.Serialize()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func mustSerialize(s serializer) []byte {
	b, err := s.Serialize()
	if err != nil {
		panic(err)
	}
	return b
}

func mustSerializeAll(s ...serializer) [][]byte {
	out, err := serializeAll(s...)
	if err != nil {
		panic(err)
	}
	return out
}

func isLocalHop(nexthop net.IP) bool {
	return nexthop.String() == localHop
}
