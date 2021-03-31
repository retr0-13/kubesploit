package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
)

func getIPAddresses(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	lenIPs := len(ips)
	var ipAddresses []string

	switch {
	case lenIPs < 2:
		ipAddresses = ips

	default:
		// Shouldn't be panic here because we are checking the lenIPs before
		ipAddresses = ips[1 : len(ips)-1]
	}

	return ipAddresses, nil
}

//  http://play.golang.org/p/m8TNTtygK0
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func mainfunc(cidr string, threadsStr string, intervalsPrint string) {
	var numberOfThreads int
	var err error
	if threadsStr == "" {
		fmt.Println("[*] Using default settings: 100 threads")
		numberOfThreads = 100
	} else {
		numberOfThreads, err = strconv.Atoi(threadsStr)
		if err != nil {
			fmt.Println("[*] Using default settings: 100 threads")
			numberOfThreads = 100
		}
	}

	if cidr == "" {
		cidr = "10.96.0.0/12"
		fmt.Println("[*] Using default settings: CIDR: 10.96.0.0/12")
	}

	fmt.Printf("[*] Scanning for kubernetes services\n[*] CIDR: %s\n[*] Threads: %s\n", cidr, strconv.Itoa(numberOfThreads))

	ipAddresses, err := getIPAddresses(cidr)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("[*] Scanning %d IP addresses\n", len(ipAddresses))
	fmt.Printf("[*] Threads: %d\n", numberOfThreads)

	//var hostsMap map[string][]string
	//l := sync.Mutex{}

	sem := make(chan bool, numberOfThreads)

	count := 0
	var interval int
	interval, err = strconv.Atoi(intervalsPrint)
	if err != nil {
		interval = 10000
		fmt.Printf("[*] Printing every %s addresses\n", interval)
	} else {
		fmt.Printf("[*] Printing every %s addresses\n", interval)
	}

	for _, ip := range(ipAddresses) {

		sem <- true

		go func(ip string) {
			//fmt.Printf("Checking IP: %s\n", ip)
			count += 1
			if count % interval == 0 {
				fmt.Printf("[*] Scan: %d addresses till now...\n", count)
			}

			host, err := net.LookupAddr(ip)

			if err != nil {
				//log.Fatal(err)
				//fmt.Println("Error")
			} else {
				fmt.Printf("[*] %s -> %s\n", ip, host)
			}
			/*if err == nil {
				l.Lock()
				hostsMap[ip] = hosts
				fmt.Printf("added %s\n", hosts)
				l.Unlock()
			}*/

			<- sem
		}(ip)
	}

	for i := 0; i < cap(sem); i++ {
		sem <- true
	}
	fmt.Println("[*] Done")
}

/*
func main(){
	mainfunc("10.96.0.0/16", "100", "100")
}
*/