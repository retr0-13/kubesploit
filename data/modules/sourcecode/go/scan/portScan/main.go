package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func isPortOpen(host string, port int) (bool, error) {
	isOpen := false
	timeout := time.Second

	portStr := strconv.Itoa(port)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, portStr), timeout)
	if err != nil {
		//fmt.Println("Connecting error:", Err)
	}
	if conn != nil {
		defer conn.Close()
		isOpen = true
	}

	return isOpen, err
}

var KNOWN_PORTS = map[int]string{
	27017: "mongodb",
	28017: "mongodb web admin",
	21:    "ftp",
	22:    "SSH",
	23:    "telnet",
	25:    "SMTP",
	69:    "tftp",
	80:    "http",
	88:    "kerberos",
	109:   "pop2",
	110:   "pop3",
	123:   "ntp",
	137:   "netbios",
	139:   "netbios",
	443:   "https",
	445:   "Samba",
	631:   "cups",
	5800:  "VNC remote desktop",
	194:   "IRC",
	118:   "SQL service?",
	150:   "SQL-net?",
	1433:  "Microsoft SQL server",
	1434:  "Microsoft SQL monitor",
	3306:  "MySQL",
	3396:  "Novell NDPS Printer Agent",
	3535:  "SMTP (alternate)",
	554:   "RTSP",
	9160:  "Cassandra [ http://cassandra.apache.org/ ]",
	2379:  "ETCD server port, kubernetes database",
	4194:  "cAdvisor, container metrics",
	6443:  "Kubernetes API port",
	6666:  "ETCD server port, kubernetes database",
	6782:  "weave, metrics and endpoints",
	6783:  "weave, metrics and endpoints",
	6784:  "weave, metrics and endpoints",
	8443:  "kube-apiserver, Kubernetes API port",
	8080:  "Possible Insecure API port",
	9099:  "calico-felix, Health check server for Calico",
	10250: "kubelet HTTPS API which allows full node access",
	10255: "kubelet unauthenticated read-only HTTP port: pods, runningpods and node state. Should be deprecated",
	10256: "Kube proxy health check server",
}

type PortInfo struct {
	IsPortOpen bool
	Port       int
	PortDescription string
	Err        error
}

func scanPorts(ipAddress string, ports map[int]string, concurrencyLimit int) []PortInfo {
	// make a slice to hold the results we're expecting
	var openPorts []PortInfo

	// this buffered channel will block at the concurrency limit
	semaphoreChan := make(chan struct{}, concurrencyLimit)

	// this channel will not block and collect the http request results
	resultsChan := make(chan *PortInfo)

	// make sure we close these channels when we're done with them
	defer func() {
		close(semaphoreChan)
		close(resultsChan)
	}()

	// keen an index and loop through every Url we will send a request to
	for port, portDescription := range ports {

		// start a go routine with the index and Url in a closure
		go func(ipAddress string, port int, portDescription string) {

			// this sends an empty struct into the semaphoreChan which
			// is basically saying add one to the limit, but when the
			// limit has been reached block until there is room
			semaphoreChan <- struct{}{}

			var err error
			isOpen := false

			isOpen, err = isPortOpen(ipAddress, port)

			result := &PortInfo{isOpen, port,portDescription, err}

			// now we can send the PortInfo struct through the resultsChan
			resultsChan <- result
			// once we're done it's we read from the semaphoreChan which
			// has the effect of removing one from the limit and allowing
			// another goroutine to start
			<-semaphoreChan

		}(ipAddress, port, portDescription)
	}

	// start listening for any results over the resultsChan
	// once we get a PortInfo append it to the PortInfo slice
	var count int
	for {
		result := <-resultsChan
		count += 1

		if result.IsPortOpen {
			openPorts = append(openPorts, *result)
		}

		// if we've reached the expected amount of urls then stop
		if count == len(ports) {
			break
		}
	}

	// now we're done we return the results
	return openPorts
}

// In the JSON
//var arg1ArrayOfAddresses = []string{"127.0.0.1"}
//var arg1ArrayOfAddresses []string

func mainfunc(inputAddresses string) {
	concurrencyLimit := 15
	fmt.Printf("[*] Scanning for open ports (%d threads)\n", concurrencyLimit)
	time.Sleep(1)
	inputAddresses = strings.TrimSpace(inputAddresses)

	// must declare it and not with ":=" because it will cause bug with Yaegi which will not identify it
	var inputArrayOfAddresses []string
	inputArrayOfAddresses = strings.Split(inputAddresses, ";")

	if len(inputAddresses) < 1 {
		inputArrayOfAddresses = append(inputArrayOfAddresses, "127.0.0.1")
	}

	args := inputArrayOfAddresses
	for _, ip := range args {
		fmt.Printf("[*] Scanning IP: %s\n", ip)
		if strings.ContainsAny(strings.ToLower(ip), "a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p | q | r | s | t | u | v | w | x | y | z"){
			addr,err := net.LookupIP(ip)
			if err != nil {
				fmt.Println("[*] Unknown host")
				continue
			} else {
				if len(addr) > 0 {
					ip = addr[0].String()
				}else {
					fmt.Println("[*] Unknown IP")
					continue
				}
			}
		}
		portsStatus := scanPorts(ip, KNOWN_PORTS, concurrencyLimit)

		for _, portInfo := range portsStatus{
			if portInfo.IsPortOpen {
				fmt.Printf("    %d: %s\n", portInfo.Port, portInfo.PortDescription)
			}
		}
	}


	/*jsonByteData, err := json.Marshal(portsStatus)
	if err != nil {
		log.Fatal("Cannot encode to JSON ", err)
	}

	fmt.Println(string(jsonByteData))*/
}

/*
func main(){
	mainfunc("example.com;example.com")
}
*/