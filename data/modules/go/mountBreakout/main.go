package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func extractDeviceType() (string,error) {
	var err error
	var device string

	foundUUID := false
	dat, err := ioutil.ReadFile("/proc/cmdline")
	if err == nil {
		cmdline := string(dat)
		splittedCmdLine := strings.Split(cmdline, " ")

		var uuid string

		// extracting the UUID of the device
		for _, splitLine := range splittedCmdLine {
			if strings.HasPrefix(splitLine, "root=UUID"){
				uuid = splitLine[10:]
				foundUUID = true
			}
		}

		if foundUUID {
			cmd := exec.Command("blkid")
			stdout, err := cmd.Output()

			if err == nil {
				//fmt.Println(string(stdout))
				lines := strings.Split(string(stdout), "\n")
				for _, line := range lines{
					if strings.Contains(line, uuid) {
						deviceSplitted := strings.Split(line, ":")
						device = deviceSplitted[0]
					}
				}
			}
		}
	}

	return device,err
}

// devices:
// /dev/sda1
// /dev/xvda1
func mainfunc(device string, useBruteforce string){
	var err error
	var devices []string
	if device == "" {
		if useBruteforce == "true" {

			fmt.Println("[*] Using brute force on known devices [\"/dev/sda1\", \"/dev/xvda1\"]")
			devices = append(devices, "/dev/sda1")
			devices = append(devices, "/dev/xvda1")
		} else {
			device,err = extractDeviceType()
			if device == "" || err != nil {
				fmt.Println("[*] Didn't find device name, using brute force on known devices [\"/dev/sda1\", \"/dev/xvda1\"]")
				devices = append(devices, "/dev/sda1")
				devices = append(devices, "/dev/xvda1")
			} else {
				devices = append(devices, device)
			}
		}
	} else {
		devices = append(devices, device)
	}

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

	for _, deviceName := range devices {
		fmt.Printf("[*] Trying to mount \"%s\" to \"%s\"\n", deviceName, dirPath)
		cmd := exec.Command("mount", deviceName, dirPath)
		_, err = cmd.Output()
		if err != nil {
			fmt.Println(err.Error())
		} else {
			fmt.Printf("[*] Mounted successfuly \"%s\" to \"%s\"\n", deviceName, dirPath)
			fmt.Printf("[*] Host folder is in: \"%s\"\n", dirPath)
		}
	}
}


func main(){
	mainfunc("", "false")
   // mainfunc("/dev/sda1", "false")
   // mainfunc("", "true")
}