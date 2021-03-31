/*
Kubesploit is a post-exploitation command and control framework built on top of Merlin by Russel Van Tuyl.
This file is part of Kubesploit.
Copyright (c) 2021 CyberArk Software Ltd. All rights reserved.

Kubesploit is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Kubesploit is distributed in the hope that it will be useful for enhancing organizations' security.
Kubesploit shall not be used in any malicious manner.
Kubesploit is distributed AS-IS, WITHOUT ANY WARRANTY; including the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Kubesploit.  If not, see <http://www.gnu.org/licenses/>.
*/

package minidump

import (
	"fmt"
	"strconv"
)

// Parse is the initial entry point for all extended modules. All validation checks and processing will be performed here
// The function input types are limited to strings and therefore require additional processing
func Parse(options map[string]string) ([]string, error) {
	// Convert PID to integer
	if options["pid"] != "" && options["pid"] != "0" {
		_, errPid := strconv.Atoi(options["pid"])
		if errPid != nil {
			return nil, fmt.Errorf("there was an error converting the PID to an integer:\r\n%s", errPid.Error())
		}
	}

	command, errCommand := GetJob(options["process"], options["pid"], options["tempLocation"])
	if errCommand != nil {
		return nil, fmt.Errorf("there was an error getting the minidump job:\r\n%s", errCommand.Error())
	}

	return command, nil
}

// GetJob returns a string array containing the commands, in the proper order, to be used with agents.AddJob
func GetJob(process string, pid string, tempLocation string) ([]string, error) {
	return []string{"Minidump", process, pid, tempLocation}, nil
}
