//encrypted

package main

import (
	"fmt"
	"flag"
	"log"
	"net"
	"os"
	"io"
	"strings"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io/ioutil"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
	"bufio"
)

var localServerHost = "0.0.0.0:"
var remoteServerHost = ""
var passPhrase = ""

func main() {

	listenport  := flag.String("l","none","Reverse-proxy mode: listen for inbound connections on <listenport> and relay them to <destination>:<port>")

	passPhraseFile  := flag.String("p","none","Use the ASCII text passphrase contained in <pwdfile>")

	flag.Parse()

	fullInputString := os.Args[1:]

	destinationAndPort := ""

	for j := 0; j <= len(fullInputString)-1 ; j++ {
        if(strings.Contains(fullInputString[j],"-l") || strings.Contains(fullInputString[j],"-p")){
			fullInputString[j] = ""
			fullInputString[j+1] = ""
			j = j+1;
		}else{
			destinationAndPort = destinationAndPort + fullInputString[j] + " "
		}
    }

	remoteServerHost = strings.Split(destinationAndPort," ")[0]+ ":" + strings.Split(destinationAndPort," ")[1]
	
	fmt.Println("Listen To port : ", *listenport)
	fmt.Println("Sending it to target : ", remoteServerHost )
	fmt.Println("Password file name : ", *passPhraseFile)

	passPhraseString := ""
	if (*passPhraseFile != "none"){
		passPhraseString = readPassPhraseFromFile(*passPhraseFile)
		passPhraseString := strings.Split(passPhraseString, "\n")[0]
		fmt.Println("Password obtained from file is : ", passPhraseString)
	}else{
		fmt.Println("Failed to retreive password from file. Please retry")
	}
	passPhrase = passPhraseString

	if(passPhraseString == ""){
		log.Fatal("Failed to retreive password from file. Please retry")
	}else if(*listenport != "none" && destinationAndPort != ""){
		localServerHost = localServerHost + *listenport
	
		ln, err := net.Listen("tcp", localServerHost)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Port forwarding server up and listening on ", localServerHost)
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go handleConnection(conn)
		}
	}else{
		client_PBC_conn, err := net.Dial("tcp", remoteServerHost)
		if err != nil {
			log.Print(err)
			return
		}
		go clientToPB(client_PBC_conn)
		PBToClient(client_PBC_conn)
	}

}

func clientToPB(client_PBC_conn net.Conn){
	defer client_PBC_conn.Close()
	for{
		var buf  = make([]byte ,1000000)
		reader := bufio.NewReader(os.Stdin)
		n, _ := reader.Read(buf)

		encyptedByteArray := encrypt(buf[:n],passPhrase)
		_, err := client_PBC_conn.Write(encyptedByteArray)
		if(err != nil){
			log.Print(err)
			return
		}	
	}
}


func PBToClient(client_PBC_conn net.Conn){
	defer client_PBC_conn.Close()
	for{
		var read_buf = make([]byte ,1000000)
		n, err := client_PBC_conn.Read(read_buf)
		if(err != nil){
			log.Print(err)
			return
		}
		plainText := decrypt(read_buf[:n],passPhrase)
		os.Stdout.Write(plainText)
	}
}

func handleConnection(conn net.Conn) {
	upstream, err := net.Dial("tcp", remoteServerHost)
	if err != nil {
		log.Print(err)
		return
	}
	server_Routine(conn, upstream)
}

func server_Routine(conn net.Conn, upstream net.Conn){

	defer conn.Close()
	defer upstream.Close()
	
	go readFromConn(conn, upstream)
	readFromupStream(conn, upstream)
	
}

func readFromConn(conn net.Conn, upstream net.Conn){
	for{
		var buf = make([]byte,1000000)
		n, err0 := conn.Read(buf)
		
		if(err0 != nil){
			log.Print("readFromupStream err0 - ",err0)
			return
		}

		decryptedByteArray :=  decrypt(buf[:n],passPhrase)
		log.Print("Input from client: -" , string(decryptedByteArray))

		_, err1 := upstream.Write(decryptedByteArray)
		if(err1 != nil){
			log.Print("readFromupStream err1 - ",err1)
		}
	}
}

func readFromupStream(conn net.Conn, upstream net.Conn){
	
	for{
		var returnbuf = make([]byte,1000000)
		n2, err2 := upstream.Read(returnbuf)
		
		if(err2 != nil){
			log.Print("readFromupStream err2 - ",err2)
			return
		}

		log.Print("Response from server: " , string(returnbuf[:]))
		
		encryptedByteArray := encrypt(returnbuf[:n2], passPhrase)
		_, err3 := conn.Write(encryptedByteArray)
		if(err3 != nil){
			log.Print("readFromupStream err3 - ", err3)
		}
	}
}

func encrypt(data []byte, passphrase string) []byte {
	
	kdf_key := pbkdf2.Key([]byte(passphrase), make([]byte, 8)	, 1000, 32, sha256.New)	
	
	block, _ := aes.NewCipher(kdf_key)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic("Encryption error 1 - on gsm" + err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic("Encryption error 2 - on readfull" + err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	kdf_key := pbkdf2.Key([]byte(passphrase), make([]byte, 8)	, 1000, 32, sha256.New)	

	block, err := aes.NewCipher(kdf_key)
	if err != nil {
		panic("Decryption error 1 - on new Cipher" + err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic("Decryption error 2 - on new GCM" + err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic("Decryption error 3 - on open" + err.Error())
	}

	return plaintext
}

func readPassPhraseFromFile(fileName string) string{ 

	dat, err := ioutil.ReadFile(fileName)
	if(err != nil){
		fmt.Println((err))
		fmt.Println("Please provide a valid password file")
		return ""
	}
	passPhraseAsString := string(dat);
	return passPhraseAsString
}