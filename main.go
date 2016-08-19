package main

import (
	"log"
	"time"

	"github.com/spf13/viper"
	"github.com/yosisa/gof"
)

func main() {
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal(err)
	}
	var ports []*ConfigPort
	if err := viper.UnmarshalKey("ports", &ports); err != nil {
		log.Fatal(err)
	}

	bgp := NewGoBGP(viper.GetString("gobgp.addr"), uint16(viper.GetInt("gobgp.as")))
	if err := bgp.Connect(); err != nil {
		log.Fatal(err)
	}
	if err := bgp.RegisterVTEP(); err != nil {
		log.Fatal(err)
	}

	vh := &vxlanHandler{
		bgp:         bgp,
		suppressARP: viper.GetBool("suppress-arp"),
		gateways:    getGateways(),
	}

	mux := new(gof.DatapathMux)
	mux.Handle(1, gof.FancyHandle(vh))

	idleTimeout := uint16(viper.GetInt("idle-timeout"))
	mux.SetDefault(gof.AutoInstantiate(func(dpid uint64) gof.Handler {
		sbh := new(subBridgeHandler)
		sbh.bgp = bgp
		sbh.IdleTimeout = idleTimeout
		return gof.FancyHandle(sbh)
	}))

	ctrl := gof.Controller{
		Addr:         viper.GetString("listen"),
		Handler:      mux,
		WriteTimeout: 5 * time.Second,
		Concurrency:  5,
	}
	if err := ctrl.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
