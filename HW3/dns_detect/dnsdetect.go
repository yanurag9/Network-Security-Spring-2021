package main

import (
	"fmt"
	"flag"
	"log"
	"os"
	"strings"
	"reflect"
	"sort"
	"strconv"
)

import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/layers"

type DNSPacket struct {

	//Needs to match : src IP , dst IP , UDP src dest ports, 53 port , 
	//matching txid 16 bit, Matching question section

    timestamp string
	timeInSeconds int64
    transID uint16
	srcIP string
	destIP string
	srcPort string
	destPort string 
	questions []string
	answers []string
}

func main() {

	readFromFileFlag  := flag.String("r","none","Location of the PCAP file to read entries from.")

	interfaceName  := flag.String("i","none","Name of the device to spectate data for.")

	bpfFilterStrings := os.Args[1:]

	flag.Parse()

	bpfFilterString := ""

	for j := 0; j <= len(bpfFilterStrings)-1 ; j++ {
        if(strings.Contains(bpfFilterStrings[j],"-r") || strings.Contains(bpfFilterStrings[j],"-i")){
			bpfFilterStrings[j] = ""
			bpfFilterStrings[j+1] = ""
			j = j+1;
		}else{
			bpfFilterString = bpfFilterString + bpfFilterStrings[j] + " "
		}
    }

	if(*readFromFileFlag != "none"){
		checkDNSSpoofingForFile(*readFromFileFlag, bpfFilterString)
	}else if (*interfaceName != "none"){
		if(checkIfDeviceExists(*interfaceName)){
			liveCapture(*interfaceName,bpfFilterString)
		}else{
			fmt.Println("The entered" + *interfaceName + "device does not exist. Below listed are the available devices. In the meanwhile using the default device.")
			printAllDeviceDetails();
			fmt.Println("Using default device : " + getFirstDevice())
			liveCapture(getFirstDevice(), bpfFilterString)
		}
	}else{
		fmt.Println("Using default device : " + getFirstDevice())
		liveCapture(getFirstDevice(), bpfFilterString)
	}
}

func liveCapture(deviceName string ,bpfFilterString string){

	var tempPacketsList[] DNSPacket;

	handle, err := pcap.OpenLive(deviceName, int32(1600), false, pcap.BlockForever)

	if err != nil {
		log.Fatal(err)
	}else {
		defer handle.Close()
		var appendFilter string = "udp and src port 53"
		if(bpfFilterString != ""){
			appendFilter = appendFilter + " and " + bpfFilterString
		}
		err = handle.SetBPFFilter(appendFilter)
		if err != nil {
			log.Fatal(err)
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			mostRecentPacket := createDNSPacketObjforPacket(packet)
			mostRecentPacketTime := mostRecentPacket.timeInSeconds
			tempPacketsList = append(tempPacketsList, mostRecentPacket)

			//Remove older packetsFrom Array
			positionToRemoveTill := 0;
			for position, packetInArray := range tempPacketsList{
				if(mostRecentPacketTime - packetInArray.timeInSeconds <= 5){
					positionToRemoveTill = position
					break
				}
			}
			
			tempPacketsList = tempPacketsList[positionToRemoveTill:]
			//fmt.Println("element in Array" , len(tempPacketsList) , " | start : " , tempPacketsList[0].timeInSeconds , " | end : ", tempPacketsList[len(tempPacketsList)-1].timeInSeconds)

			//Then Check for DNS Spoofing
			checkDuplicateResponses(mostRecentPacket , tempPacketsList)
		}
	  }
}


func checkDNSSpoofingForFile(fileName string, bpfFilterString string){

	var tempPacketsList[] DNSPacket;

	handle, err := pcap.OpenOffline(fileName);

	if err != nil {
		log.Fatal(err)
	}else {
		var appendFilter string = "udp and src port 53"
		if(bpfFilterString != ""){
			appendFilter = appendFilter + " and " + bpfFilterString
		}
		err = handle.SetBPFFilter(appendFilter)
		if err != nil {
			log.Fatal(err)
		}
		
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			mostRecentPacket := createDNSPacketObjforPacket(packet)
			mostRecentPacketTime := mostRecentPacket.timeInSeconds
			tempPacketsList = append(tempPacketsList, mostRecentPacket)

			//Remove older packetsFrom Array
			positionToRemoveTill := 0;
			for position, packetInArray := range tempPacketsList{
				if(mostRecentPacketTime - packetInArray.timeInSeconds <= 5){
					positionToRemoveTill = position
					break
				}
			}
			
			tempPacketsList = tempPacketsList[positionToRemoveTill:]
			//fmt.Println("element in Array" , len(tempPacketsList) , " | start : " , tempPacketsList[0].timeInSeconds , " | end : ", tempPacketsList[len(tempPacketsList)-1].timeInSeconds)

			//Then Check for DNS Spoofing
			checkDuplicateResponses(mostRecentPacket , tempPacketsList)

		}
	}
}

func checkDuplicateResponses(mostRecentPacket DNSPacket, tempPacketsList []DNSPacket){
	printPacketDescFlag := 1;
	for _, packetInArray := range tempPacketsList {
		numberOfDuplicateRequests := 0;
		if(mostRecentPacket.transID == packetInArray.transID && checkOtherDetails(mostRecentPacket, packetInArray)){
			numberOfDuplicateRequests++;
			if(numberOfDuplicateRequests == 1 && printPacketDescFlag == 1){
				printPacketDescFlag = 0;
				fmt.Println()
				fmt.Println(mostRecentPacket.timestamp, " DNS poisining attempt")
				txid := "0x" + strconv.FormatInt(int64(mostRecentPacket.transID),16)
				fmt.Println("TXID " ,  txid , " ", mostRecentPacket.questions)
				fmt.Println("Answer1 " , mostRecentPacket.answers)
				fmt.Println("Answer2 " , packetInArray.answers) 
			}else{
				fmt.Println("Answer", numberOfDuplicateRequests+1 , " " , packetInArray.answers) 
			}
		}
		
	}
}

func checkOtherDetails(mostRecentPacket DNSPacket, duplicatePacketSuspect DNSPacket) bool{
	similarityCounter := 0
	if(mostRecentPacket.srcIP == duplicatePacketSuspect.srcIP){
		similarityCounter++;
	}
	if(mostRecentPacket.destIP == duplicatePacketSuspect.destIP){
		similarityCounter++;
	}
	if(mostRecentPacket.srcPort == duplicatePacketSuspect.srcPort){
		similarityCounter++;
	}
	if(mostRecentPacket.destPort == duplicatePacketSuspect.destPort){
		similarityCounter++;
	}
	if(len(mostRecentPacket.questions) == len(duplicatePacketSuspect.questions)){
		sort.Strings(mostRecentPacket.questions)
		sort.Strings(duplicatePacketSuspect.questions)
		if(reflect.DeepEqual(mostRecentPacket.questions, duplicatePacketSuspect.questions)){
			similarityCounter++;
		}
	}
	
	if(similarityCounter == 5){
		sort.Strings(mostRecentPacket.answers)
		sort.Strings(duplicatePacketSuspect.answers)
		if(reflect.DeepEqual(mostRecentPacket.answers, duplicatePacketSuspect.answers)){
			return false
		}else{
			return true
		}
	}else{
		return false
	}
}

func createDNSPacketObjforPacket(packet gopacket.Packet) DNSPacket{
	
	var packetObj DNSPacket;
	
	packetObj.timestamp = packet.Metadata().Timestamp.String()
	packetObj.timeInSeconds = packet.Metadata().Timestamp.Unix()

	// Ip layer data fetching
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer != nil {
        ip4, _ := ipLayer.(*layers.IPv4)
		if(ip4!=nil){
			packetObj.srcIP = ip4.SrcIP.String()
			packetObj.destIP = ip4.DstIP.String()
		}
		ip6, _ := ipLayer.(*layers.IPv6)
		if(ip6!=nil){
			packetObj.srcIP = ip6.SrcIP.String()
			packetObj.destIP = ip6.DstIP.String()
		}
    }

	//If using UDP
	udpLayer := packet.Layer(layers.LayerTypeUDP)
    if udpLayer != nil {
        udp, _ := udpLayer.(*layers.UDP)

		packetObj.srcPort = udp.SrcPort.String()
		packetObj.destPort = udp.DstPort.String()
    }

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	dns, _ := dnsLayer.(*layers.DNS)
	packetObj.transID = dns.ID
	for _, question := range dns.Questions {
		if(question.Name != nil){
			packetObj.questions = append(packetObj.questions, string(question.Name))
		}
	}
	for _, answer := range dns.Answers {
		if(answer.IP != nil){
			packetObj.answers = append(packetObj.answers, (answer.IP.String()))
		}
	}
	
	/*fmt.Println("Obj : ", packetObj.transID, " | ",packetObj.timeInSeconds,
	 " | ",packetObj.srcIP, " | ",packetObj.srcPort,
	 " |  ",packetObj.destIP, " |  ",packetObj.destPort,
	 " |  ",packetObj.questions, " |  ", packetObj.answers)*/
	 
	return packetObj
}


//------------------------------------------------------------------------------------------------------------------------------------


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
    fmt.Println( "Device names :")
    for _, device := range devices {
        fmt.Println( device.Name)
        /*fmt.Println( "Description: ", device.Description)
        fmt.Println( "Devices addresses: ", device.Description)
        for _, address := range device.Addresses {
            fmt.Println("  IP address: ", address.IP)
            fmt.Println("  Subnet mask: ", address.Netmask)
			fmt.Println("  device ", device)
        }*/
    }
}

