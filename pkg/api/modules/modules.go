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

package modules

import (
	// Standard
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	// Merlin
	"kubesploit/pkg/agents"
	agentAPI "kubesploit/pkg/api/agents"
	"kubesploit/pkg/api/messages"
	"kubesploit/pkg/modules"
)

// GetModuleListCompleter return a tab completer of available modules for CLI interactions
func GetModuleListCompleter() func(string) []string {
	return modules.GetModuleList()
}

// GetModule returns a module object based on it's JSON file location
func GetModule(modulePath string) (messages.UserMessage, modules.Module) {
	module, err := modules.Create(modulePath)
	if err != nil {
		return messages.ErrorMessage(err.Error()), modules.Module{}
	}
	return messages.UserMessage{Error: false}, module
}

// RunModule executes the provided module
func RunModule(module modules.Module) []messages.UserMessage {
	var returnMessages []messages.UserMessage
	if module.GoInterpreter == true || module.GoInterpreterProgress == true {
		for index, command := range module.Commands {
			if content, err := ioutil.ReadFile(command); err == nil {
				module.Commands[index] = string(content)
			}
		}
	}

	r, err := modules.Run(module)
	if err != nil {
		returnMessages = append(returnMessages, messages.ErrorMessage(err.Error()))
		return returnMessages
	}
	if len(r) <= 0 {
		err := fmt.Errorf("the %s module did not return a command to task an agent with", module.Name)
		returnMessages = append(returnMessages, messages.ErrorMessage(err.Error()))
		return returnMessages
	}

	// TODO Move all of this logic to the modules.Run() function
	// ALL Agents
	if strings.ToLower(module.Agent.String()) == "ffffffff-ffff-ffff-ffff-ffffffffffff" {
		if len(agents.Agents) <= 0 {
			err := fmt.Errorf("there are 0 available agents, no jobs were created")
			returnMessages = append(returnMessages, messages.ErrorMessage(err.Error()))
			return returnMessages
		}
		for id := range agents.Agents {
			// Make sure OS platform match
			if !strings.EqualFold(agents.Agents[id].Platform, module.Platform) {
				m := fmt.Sprintf("Module platform %s does not match agent %s platform %s. Skipping job...",
					module.Platform, id, agents.Agents[id].Platform)
				um := messages.UserMessage{
					Error:   false,
					Level:   messages.Note,
					Message: m,
					Time:    time.Now().UTC(),
				}
				returnMessages = append(returnMessages, um)
				continue
			}
			switch strings.ToLower(module.Type) {
			case "standard":
				if module.GoInterpreter{
					returnMessages = append(returnMessages, agentAPI.CMDGO(id, r))
				} else if module.GoInterpreterProgress{
					returnMessages = append(returnMessages, agentAPI.CMDGOPROG(id, r))
				} else {
				        // Standard modules use the `cmd` message type that must be in position 0
					returnMessages = append(returnMessages, agentAPI.CMD(id, append([]string{"cmd"}, r...)))
				}
			case "extended":
				// Was using Method: r[0]
				job, err := agents.AddJob(id, r[0], r[1:])
				if err != nil {
					returnMessages = append(returnMessages, messages.ErrorMessage(err.Error()))
				} else {
					returnMessages = append(returnMessages, messages.JobMessage(id, job))
				}
			default:
				err := fmt.Errorf("invalid module type: %s", module.Type)
				returnMessages = append(returnMessages, messages.ErrorMessage(err.Error()))
				return returnMessages
			}
		}
		return returnMessages
	}
	// Single Agent
	switch strings.ToLower(module.Type) {
	case "standard":
		if module.GoInterpreter{
			returnMessages = append(returnMessages, agentAPI.CMDGO(module.Agent, r))
		} else if module.GoInterpreterProgress{
			returnMessages = append(returnMessages, agentAPI.CMDGOPROG(module.Agent, r))
		} else {
		        // Standard modules use the `cmd` message type that must be in position 0
			returnMessages = append(returnMessages, agentAPI.CMD(module.Agent, append([]string{"cmd"}, r...)))
		}
	case "extended":
		job, err := agents.AddJob(module.Agent, r[0], r[1:])
		if err != nil {
			returnMessages = append(returnMessages, messages.ErrorMessage(err.Error()))
		} else {
			returnMessages = append(returnMessages, messages.JobMessage(module.Agent, job))
		}
		return returnMessages
	default:
		err := fmt.Errorf("invalid module type: %s", module.Type)
		returnMessages = append(returnMessages, messages.ErrorMessage(err.Error()))
		return returnMessages
	}
	return returnMessages
}
