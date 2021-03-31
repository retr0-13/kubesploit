# Modules Mitigations
<table>
  <tbody>
	<tr>
	  <th>Module </th>
	  <th align="center">Description</th>
	  <th align="center">Mitigation</th>
	</tr>
	<tr>
	  <td>
		 Mount Container Breakout
	  </td>
	  <td align="left">         
		  Can be exploit on privileged containers or containers with privilege to mount.  <br>
		  Creates mount from the container to the host and has access to the host files.  <br>
	  </td>
	  <td align="left" >Reduce container privileges. Prevent creation of privileged containers or with the permissions to mount.</td>
	</tr>
	<tr>
	  <td>
		 docker.sock Breakout
	  </td>
	  <td align="left">         
		  Can be exploit on containers with docker.sock mounted.  <br>
		  It uses docker.sock to create new vulnerable (privileged, with mounts, etc.) container and escape to the host.  <br>
	  </td>
	  <td align="left" >Prevent creating containers with docker.sock mounted.</td>
	</tr>	
	<tr>
	  <td>
		 runC (CVE-2019-5736) Breakout
	  </td>
	  <td align="left">         
		  This module exploit vulnerable runC to escape to the host.  <br>
	  </td>
	  <td align="left" >Make sure to have updated runC version (>1.0.0-rc6).</td>
	</tr>	
    <tr>
      <td>
         Kubelet attack
      </td>
      <td align="left">         
          Some Kubernetes cluster might have nodes with Kubelet open for anonymous requests. <br>
          This module exploit this by listing the pods vulnerable for RCE, run commands inside them and scan the service account tokens from all the pods. <br>
      </td>
      <td align="left" >Make sure that all the kubelets have the config file `/var/lib/kubelet/config.yaml` with the following: <br> 
       1. No allowing anonymous request: `authentication: anonymous: enabled: false`.  <br>
       2. Preventing authorization to anyone: `authorization: mode:` NOT set with AlwaysAllow. <br>
       </td>
    </tr>	
    
  </tbody>
</table>