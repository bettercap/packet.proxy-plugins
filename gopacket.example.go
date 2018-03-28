package main

import (
	"github.com/bettercap/bettercap/log"

	"github.com/chifflier/nfqueue-go/nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func OnPacket(payload *nfqueue.Payload) int {
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)
	log.Info("%s", packet.Dump())
	payload.SetVerdict(nfqueue.NF_ACCEPT)
	return 0
}
