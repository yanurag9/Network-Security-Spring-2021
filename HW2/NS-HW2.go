package main

import (
	"fmt"
	"flag"
	"log"
	"encoding/hex"
	"os"
	"strings"
)

import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/layers"

func main() {


	readFromFileFlag  := flag.String("r","none","Location of the PCAP file to read entries from.")

	interfaceName  := flag.String("i","none","Name of the device to spectate data for.")

	containsFilterKeyword  := flag.String("s","","A string used to filter out the packets")

	bpfFilterStrings := os.Args[1:]

	flag.Parse()

	bpfFilterString := ""

	for j := 0; j <= len(bpfFilterStrings)-1 ; j++ {
        if(strings.Contains(bpfFilterStrings[j],"-r") || strings.Contains(bpfFilterStrings[j],"-s") || strings.Contains(bpfFilterStrings[j],"-i")){
			bpfFilterStrings[j] = ""
			bpfFilterStrings[j+1] = ""
			j = j+1;
		}else{
			bpfFilterString = bpfFilterString + bpfFilterStrings[j] + " "
		}
    }

	if(*readFromFileFlag != "none"){
		readPacketsFromFile(*readFromFileFlag, bpfFilterString, *containsFilterKeyword)
	}else if (*interfaceName != "none"){
		if(checkIfDeviceExists(*interfaceName)){
			liveCapture(*interfaceName,bpfFilterString, *containsFilterKeyword)
		}else{
			fmt.Println("The entered" + *interfaceName + "device does not exist. Below listed are the available devices")
			printAllDeviceDetails();
		}
	}else{
		liveCapture(getFirstDevice(), bpfFilterString, *containsFilterKeyword)
	}
}

func checkIfDeviceExists(deviceName string) bool{ 

	devices, err := pcap.FindAllDevs()
    if err != nil {
        log.Fatal(err)
    }
    for _, device := range devices {
        if(deviceName == device.Name){
			return true;
		}
    }
	return false
}

func getFirstDevice() string{
	devices, err := pcap.FindAllDevs()
    if err != nil {
        log.Fatal(err)
    }
	return devices[0].Name;
}

func printAllDeviceDetails(){
	devices, err := pcap.FindAllDevs()
    if err != nil {
        log.Fatal(err)
    }
    
    for _, device := range devices {
        fmt.Println( "Device Name: ", device.Name)
        fmt.Println( "Description: ", device.Description)
        fmt.Println( "Devices addresses: ", device.Description)
        for _, address := range device.Addresses {
            fmt.Println("  IP address: ", address.IP)
            fmt.Println("  Subnet mask: ", address.Netmask)
        }
    }
}

func liveCapture(deviceName string ,bpfFilterString string, containsFilterKeyword string){

	handle, err := pcap.OpenLive(deviceName, int32(1600), false, pcap.BlockForever)

	if err != nil {
		log.Fatal(err)
	}else {
		defer handle.Close()
		if(bpfFilterString != ""){
			err = handle.SetBPFFilter(bpfFilterString)
			if err != nil {
				log.Fatal(err)
			}
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			printPacketDetails(packet, containsFilterKeyword)
		}
	  }
}

func readPacketsFromFile( fileName string, bpfFilterString string, containsFilterKeyword string){

	handle, err := pcap.OpenOffline(fileName);

	if err != nil {
		log.Fatal(err)
	}else {
		if(bpfFilterString != ""){
			err = handle.SetBPFFilter(bpfFilterString)
			if err != nil {
				log.Fatal(err)
			}
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			printPacketDetails(packet, containsFilterKeyword)
		}
	}
}

func printPacketDetails(packet gopacket.Packet, containsFilterKeyword string){

	timeStamp := ""
	srcMac := ""
	dstMac := "" 
	typeOfReq := ""
	packetLength := 0
	srcIP := ""
	dstIP := ""
	protocolType := ""
	srcPort := ""
	dstPort := ""
	TCPTrueFlagsString := ""
	payloadInBytes := []byte("")

	//fmt.Println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------.")

	ethernetLayer := packet.Layer(layers.LayerTypeEthernet);
	if ethernetLayer != nil {
		
        ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

		timeStamp = packet.Metadata().Timestamp.String();
		srcMac = ethernetPacket.SrcMAC.String()
		dstMac = ethernetPacket.DstMAC.String()
		typeOfReq = "0x" + hex.EncodeToString(ethernetPacket.BaseLayer.Contents[12:14])
		packetLength = packet.Metadata().Length
		payloadInBytes = (ethernetPacket.BaseLayer.Payload)

		//fmt.Println(packet)
    }


	// Ip layer data fetching
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer != nil {
        ip, _ := ipLayer.(*layers.IPv4)

		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		protocolType = ip.Protocol.String()
    }

	// If using TCP 
    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer != nil {

        tcp, _ := tcpLayer.(*layers.TCP)

        //FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS

		srcPort = tcp.SrcPort.String()
		dstPort = tcp.DstPort.String()

		if(tcp.SYN == true) {
			TCPTrueFlagsString = (TCPTrueFlagsString +  "SYN ")
		}
		if(tcp.ACK == true) {
			TCPTrueFlagsString = (TCPTrueFlagsString +  "ACK ")
		}
		if(tcp.FIN == true) {
			TCPTrueFlagsString = (TCPTrueFlagsString +  "FIN ")
		}
		if(tcp.RST == true) {
			TCPTrueFlagsString = (TCPTrueFlagsString +  "RST ")
		}
		if(tcp.PSH == true) {
			TCPTrueFlagsString = (TCPTrueFlagsString +  "PSH ")
		}
		if(tcp.URG == true) {
			TCPTrueFlagsString = (TCPTrueFlagsString +  "URG ")
		}
		if(tcp.ECE == true) {
			TCPTrueFlagsString = (TCPTrueFlagsString +  "ECE ")
		}
		if(tcp.CWR == true) {
			TCPTrueFlagsString = (TCPTrueFlagsString +  "CWR ")
		}
		if(tcp.NS == true) {
			TCPTrueFlagsString = (TCPTrueFlagsString +  "NS")
		}
    }

	//If using UDP
	udpLayer := packet.Layer(layers.LayerTypeUDP)
    if udpLayer != nil {
        udp, _ := udpLayer.(*layers.UDP)
		
		srcPort = udp.SrcPort.String()
		dstPort = udp.DstPort.String()
    }

	//If using ICMP
	/*icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
    if udpLayer != nil {
        icmp, _ := icmpLayer.(*layers.ICMPv4)
		
    }*/

    if err := packet.ErrorLayer(); err != nil {
        fmt.Println("Error during parsing", err)
    }

	if(protocolType == ""){
		protocolType = ""
	}

	stringToPrint  := ""
	if(srcIP!="" && srcPort!=""){
		stringToPrint = (timeStamp + " " + srcMac + " -> " + dstMac + " type " + typeOfReq + " len " + fmt.Sprint(packetLength) + " " + srcIP + ":" + srcPort + " -> "+ dstIP+ ":" + dstPort + " " + protocolType + " " + TCPTrueFlagsString)
	}else if(srcIP!=""){
		stringToPrint = (timeStamp + " " + srcMac + " -> " + dstMac + " type " + typeOfReq + " len " + fmt.Sprint(packetLength) + " " + srcIP + " -> " + dstIP + " " + protocolType + " " +  TCPTrueFlagsString)
	}else{
		stringToPrint = (timeStamp + " " + srcMac + " -> " + dstMac + " type " + typeOfReq + " len " + fmt.Sprint(packetLength) + " " + protocolType)
	}
	
	if(containsFilterKeyword!="none" && strings.Contains(string(payloadInBytes), containsFilterKeyword)){
		fmt.Println(stringToPrint)
		fmt.Println(hex.Dump(payloadInBytes))
	}else if(containsFilterKeyword=="none"){
		fmt.Println(stringToPrint)
		fmt.Println(hex.Dump(payloadInBytes))
	}
	
}

