package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type KubernetesVersion struct {
	Major string `json:"major"`
	Minor string `json:"minor"`
	GitVersion string `json:"gitVersion"`
}

type Version struct {
	Major int
	Minor int
	Patch int
	Raw   string
}

type CVE struct {
	FixedVersions []Version
	Description string
	CVENumber string
}


var KNOWN_KUBERNETES_CVES = []CVE{
	struct {
		FixedVersions []Version
		Description   string
		CVENumber     string
	}{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 11,
				Patch: 8,
				Raw: "1.11.8",
			},
			{
				Major: 1,
				Minor: 12,
				Patch: 6,
				Raw: "1.12.6",
			},
			{
				Major: 1,
				Minor: 13,
				Patch: 4,
				Raw: "1.13.4",
			},
		},
		Description: "Kubernetes API DoS Vulnerability.",
		CVENumber: "CVE-2019-1002100",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 10,
				Patch: 11,
				Raw: "1.10.11",
			},
			{
				Major: 1,
				Minor: 11,
				Patch: 5,
				Raw: "1.11.5",
			},
			{
				Major: 1,
				Minor: 12,
				Patch: 3,
				Raw: "1.12.3",
			},
		},
		Description: "Allow an unauthenticated user to perform privilege escalation and gain full admin privileges on a cluster.",
		CVENumber: "CVE-2018-1002105",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 7,
				Patch: 0,
				Raw: "1.7.0",
			},
			{
				Major: 1,
				Minor: 8,
				Patch: 0,
				Raw: "1.8.0",
			},
			{
				Major: 1,
				Minor: 9,
				Patch: 0,
				Raw: "1.9.0",
			},
			{
				Major: 1,
				Minor: 10,
				Patch: 0,
				Raw: "1.10.0",
			},
			{
				Major: 1,
				Minor: 11,
				Patch: 0,
				Raw: "1.11.0",
			},
			{
				Major: 1,
				Minor: 12,
				Patch: 0,
				Raw: "1.12.0",
			},
			{
				Major: 1,
				Minor: 13,
				Patch: 9,
				Raw: "1.13.9",
			},
			{
				Major: 1,
				Minor: 14,
				Patch: 5,
				Raw: "1.14.5",
			},
			{
				Major: 1,
				Minor: 15,
				Patch: 2,
				Raw: "1.15.2",
			},
		},
		Description: "Allowing users to read, modify, or delete cluster-wide custom resources \neven if they have RBAC permissions that extend only to namespace resources.",
		CVENumber: "CVE-2019-11247",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 13,
				Patch: 12,
				Raw: "1.13.12",
			},
			{
				Major: 1,
				Minor: 14,
				Patch: 8,
				Raw: "1.14.8",
			},
			{
				Major: 1,
				Minor: 15,
				Patch: 5,
				Raw: "1.15.5",
			},
			{
				Major: 1,
				Minor: 16,
				Patch: 2,
				Raw: "1.16.2",
			},
		},
		Description: "Kubernetes billion laughs attack vulnerability that allows an attacker to perform a Denial-of-Service (DoS) \nattack on the Kubernetes API server by uploading a maliciously crafted YAML file.",
		CVENumber: "CVE-2019-11253",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 15,
				Patch: 10,
				Raw: "1.15.10",
			},
			{
				Major: 1,
				Minor: 16,
				Patch: 7,
				Raw: "1.16.7",
			},
			{
				Major: 1,
				Minor: 17,
				Patch: 3,
				Raw: "1.17.3",
			},
		},
		Description: "The Kubernetes API Server component in versions 1.1-1.14, and versions prior to 1.15.10, 1.16.7 " +
			"\nand 1.17.3 allows an authorized user who sends malicious YAML payloads to cause the kube-apiserver to consume excessive CPU cycles while parsing YAML.",
		CVENumber: "CVE-2019-11254",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 16,
				Patch: 11,
				Raw: "1.16.11",
			},
			{
				Major: 1,
				Minor: 17,
				Patch: 7,
				Raw: "1.17.7",
			},
			{
				Major: 1,
				Minor: 18,
				Patch: 4,
				Raw: "1.18.4",
			},
			{
				Major: 1,
				Minor: 16,
				Patch: 2,
				Raw: "1.16.2",
			},
		},
		Description: "The kubelet and kube-proxy were found to contain security issue \nwhich allows adjacent hosts to reach TCP and UDP services bound to 127.0.0.1 running on the node or in the node's network namespace." +
			"\nSuch a service is generally thought to be reachable only by other processes on the same host, \nbut due to this defeect, could be reachable by other hosts on the same LAN as the node, or by containers running on the same node as the service.",
		CVENumber: "CVE-2020-8558",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 16,
				Patch: 13,
				Raw: "1.16.13",
			},
			{
				Major: 1,
				Minor: 17,
				Patch: 9,
				Raw: "1.17.9",
			},
			{
				Major: 1,
				Minor: 18,
				Patch: 6,
				Raw: "1.18.6",
			},
		},
		Description: "The Kubernetes kube-apiserver is vulnerable to an unvalidated redirect on proxied upgrade requests" +
			" \nthat could allow an attacker to escalate privileges from a node compromise to a full cluster compromise.",
		CVENumber: "CVE-2020-8559",
	},
}

func printCVE(cve CVE){
	fmt.Printf("[*] ID: %s\n", cve.CVENumber)
	fmt.Printf("[*] Description: %s\n", cve.Description)
	var rawVersions strings.Builder
	fixedVersions := cve.FixedVersions
	for i, version := range(fixedVersions){
		if i == len(cve.FixedVersions) - 1{
			rawVersions.WriteString(version.Raw)
		} else {
			rawVersions.WriteString(version.Raw + ", ")
		}
	}
	fmt.Printf("[*] Fixed versions: %s\n", rawVersions.String())
}

func exportVersionFromKubernetesCluster(address string) Version {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableCompression: true,
		MaxIdleConns:       10,
		IdleConnTimeout:    20 * time.Second,
	}

	client := &http.Client{Transport: tr}


	resp, err := client.Get(address)
	if err != nil {
		log.Fatal("Failed with error: %s", err.Error())
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	var kubeVersion KubernetesVersion
	err = json.Unmarshal(body, &kubeVersion)

	if err != nil {
		log.Fatal("Failed to parse JSON error: %s", err.Error())
	}

	/*
		Support EKS version, example:
		  "major": "1",
		  "minor": "14+",
		  "gitVersion": "v1.14.9-eks-f459c0",
	*/

	newVersion := strings.Split(kubeVersion.GitVersion, ".")
	majorStr := strings.TrimPrefix(newVersion[0], "v")
	majorInt, err := strconv.Atoi(majorStr)
	if err != nil {
		log.Fatal("Failed to parse major version with error: %s", err.Error())
	}

	minorStr := strings.TrimSuffix(newVersion[1], "+")
	minorInt, err := strconv.Atoi(minorStr)
	if err != nil {
		log.Fatal("Failed to parse minor version with error: %s", err.Error())
	}

	patchSplitted := strings.Split(newVersion[2], "-")
	patchInt, err := strconv.Atoi(patchSplitted[0])
	if err != nil {
		log.Fatal("Failed to parse patch version with error: %s", err.Error())
	}

	return Version{
		Major: majorInt,
		Minor: minorInt,
		Patch: patchInt,
		Raw:   kubeVersion.GitVersion,
	}
}

func checkForVulnerabilitiesBaseOnVersion(currentVersion Version){
	vulnerable := false
	isSmallerThanAll := 0
	knownCVEs := KNOWN_KUBERNETES_CVES
	for _, cve := range knownCVEs {
		fixedVersions := cve.FixedVersions
		for _, cveVersion := range fixedVersions {
			if currentVersion.Major == cveVersion.Major {
				if currentVersion.Minor == cveVersion.Minor {
					if currentVersion.Patch < cveVersion.Patch {
						vulnerable = true
					}
					break
				} else if currentVersion.Minor < cveVersion.Minor{
					isSmallerThanAll += 1
					if isSmallerThanAll == len(cve.FixedVersions){
						vulnerable = true
						break
					}
				}
			}
		}

		if vulnerable {
			printCVE(cve)
			fmt.Println()
		}
	}
}

func mainfunc(urlInput string) {
	// The Run() function in ../pkg/modules/modules.go might return the URL with spaces, need to clean it
	urlInput = strings.TrimSpace(urlInput)
	urlInput = urlInput + "/version"

	fmt.Printf("[*] Scanning Kubernetes cluster: %s\n", urlInput)
	currentVersion := exportVersionFromKubernetesCluster(urlInput)

	fmt.Printf("[*] Current cluster version: %s\n\n", currentVersion.Raw)
	/*
		currentVersion = Version{
			Major: 1,
			Minor: 11,
			Patch: 3,
		}
	*/

	checkForVulnerabilitiesBaseOnVersion(currentVersion)
	fmt.Println("[*] Done")
}
