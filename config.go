package main

import "github.com/spf13/viper"

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
