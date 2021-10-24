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
      <tr>
      <td>
         Pod Escape Using Log Mounts
      </td>
      <td align="left">         
          A pod running as root and with a mount point to the node’s /var/log directory can expose the entire contents of its host filesystem to any user who has access to its logs. <br>
      </td>
      <td align="left" ><br> 
       1. Don't run as root inside the container. Use a different user or user namespaces. The root in the container is the same as on host unless remapped with user namespaces.   <br>
       2. Don’t deploy pods with a writeable hostPath to /var/log. <br>
          Another option related to 2: Don’t allow volume mounts from the /var/log path 
       </td>
    </tr>	
      <tr>
      <td>
         cGroup breakout
      </td>
      <td align="left">         
          Abusing the Linux cgroup v1 release agent feature to escape container to the host. <br>
      </td>
      <td align="left" ><br> 
       1. Don't run as root inside the container. Use a different user or user namespaces. By default of docker containers, root in the container is the same as on host unless remapped with user namespaces.  <br>
       2. Adjust seccomp, AppArmor (or SELinux) profiles to restrict the actions and syscalls available for the container to the minimum required. <br>
       3. Don't mount cGroup v1 virtual file system as read-write. privileged containers mount cGroup v1 as read-write. <br>
       4. Drop all capabilities (--cap-drop=all) and enable only those that are required (--cap-add=...). In our case dont add cap_sys_admin capabilty.
       </td>
    </tr>
      <tr>
      <td>
         Kernel module breakout
      </td>
      <td align="left">         
          Break out of the container by abusing the SYS_MODULE capability, which allow to  Load and unload kernel modules. <br>
      </td>
      <td align="left" ><br> 
       1. Drop all capabilities (--cap-drop=all) and enable only those that are required (--cap-add=...). In our case dont add cap_sys_module capabilty.
       </td>
    </tr>	

</tbody>
</table>

