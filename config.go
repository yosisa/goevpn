package main

import (
	"log"
	"net"

	"github.com/spf13/viper"
)

func init() {
	viper.SetConfigName("goevpn")
	viper.AddConfigPath("/etc/goevpn")
	viper.AddConfigPath("$HOME/.goevpn")
	viper.AddConfigPath(".")

	viper.SetDefault("listen", ":6653")
	viper.SetDefault("idle-timeout", 300)
	viper.SetDefault("gobgp.addr", "127.0.0.1:50051")
	viper.SetDefault("gobgp.as", 65000)
}

type ConfigPort struct {
	Name string
	VNI  uint32
}

type ConfigGateway struct {
	Enable bool
	Groups [][]struct {
		VNI     uint32
		Address string
	}
}

type Gateway struct {
	Address     net.IP
	ConnectedTo []uint32
}

func getGateways() map[uint32]*Gateway {
	var gateway ConfigGateway
	if err := viper.UnmarshalKey("gateway", &gateway); err != nil {
		log.Printf("Failed to unmarshal gateway: %v", err)
	}
	if !gateway.Enable {
		return nil
	}
	out := make(map[uint32]*Gateway)
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
				log.Printf("Invalid gateway address: %s", gw.Address)
				return nil
			}
			out[gw.VNI] = &Gateway{
				Address:     ip,
				ConnectedTo: vnis[i],
			}
		}
	}
	return out
}
