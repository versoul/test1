package main

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type (
	Version uint16
)

const (
	VerSSL30 Version = 0x300
	VerTLS10 Version = 0x301
	VerTLS11 Version = 0x302
	VerTLS12 Version = 0x303
	VerTLS13 Version = 0x304
)

var VersionReg = map[Version]string{
	VerSSL30: "SSL 3.0",
	VerTLS10: "TLS 1.0",
	VerTLS11: "TLS 1.1",
	VerTLS12: "TLS 1.2",
	VerTLS13: "TLS 1.3",
}

var (
	snapshot_len int32         = 1024
	timeout      time.Duration = 30 * time.Second
)

func (v Version) String() string {
	if name, ok := VersionReg[v]; ok {
		return name
	}
	return fmt.Sprintf("%#v (unknown)", v)
}

func sniffDevice(deviceName string) {
	fmt.Println("Start Device - " + deviceName)

	handle, err := pcap.OpenLive(deviceName, snapshot_len, false, timeout)
	if err != nil {
		log.Println(err)
		return
	}
	defer handle.Close()

	var filter string = "tcp and port 443"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if !tcp.SYN && !tcp.FIN && !tcp.RST && (tcp.ACK && len(tcp.LayerPayload()) != 0) {
				if dta, ok := readData(packet); ok {
					fmt.Println(dta)
					hub.broadcastMessage(dta)
				}
			}
		}
	}
}

func readData(packet gopacket.Packet) (string, bool) {
	var (
		ipSrc         string
		tcpSrc        string
		ipDst         string
		tcpDst        string
		tcpOptionsLen string
		packetInfo    string
	)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		payload := tcp.LayerPayload()
		packetType := payload[0]

		if len(payload) <= 5 {
			return "", false
		}
		handshakeType := payload[5]
		if packetType == uint8(22) {
			version := Version(payload[1])<<8 | Version(payload[2])
			if handshakeType == 1 {
				packetInfo = "Client Hello " + version.String()
			} else {
				packetInfo = "Server Hello " + version.String()
			}
		} else {
			return "", false
		}
		tcpSrc = tcp.SrcPort.String()
		tcpDst = tcp.DstPort.String()
		tcpOptionsLen = strconv.Itoa(len(tcp.Options))
	}
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		ipSrc = ip.SrcIP.String()
		ipDst = ip.DstIP.String()
	}

	return ipSrc + ", " + tcpSrc + ", " + ipDst + ", " + tcpDst + ", Options_len(" + tcpOptionsLen + "), " + packetInfo, true
}
