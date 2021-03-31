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
	// Standard
	"flag"
	"os"

	// 3rd Party
	"github.com/fatih/color"

	// Merlin
	"kubesploit/pkg"
	"kubesploit/pkg/banner"
	"kubesploit/pkg/cli"
	"kubesploit/pkg/logging"
)

// Global Variables
var build = "nonRelease"

func main() {
	logging.Server("Starting Kubesploit Server version " + kubesploitVersion.Version + ", Merlin version " + kubesploitVersion.Version + " build " + kubesploitVersion.Build)

	flag.Usage = func() {
		color.Blue("#################################################")
		color.Blue("#\t\tKubeSploit SERVER\t\t\t#")
		color.Blue("#################################################")
		color.Blue("Version: " + kubesploitVersion.Version)
		color.Blue("Merlin Version: " + kubesploitVersion.MerlinVersion)
		color.Blue("Build: " + build)
		color.Yellow("KubeSploit Server does not take any command line arguments")
		color.Yellow("Visit the Merlin wiki for additional information: https://merlin-c2.readthedocs.io/en/latest/")
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	color.Blue(banner.KubesploitBanner)
	color.Blue("\t\tVersion: %s", kubesploitVersion.Version)
	color.Blue("\t\tMerlin version: %s", kubesploitVersion.MerlinVersion)
	color.Blue("\t\tBuild: %s", build)
	color.Blue("\t\tGitHub: %s", "https://github.com/cyberark/kubesploit")

	// Start Merlin Command Line Interface
	cli.Shell()
}
