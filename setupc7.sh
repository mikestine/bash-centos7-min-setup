#!/usr/bin/env bash
###############################################################################
# setupc7.sh
# by Mike Stine, 20190103
# This script configures a newly installed Centos7, then prepares itself to be
# turns it into a VM Template for cloning.  See Main Function at bottom.
###############################################################################
function setupc7::setHostname() {
  local newHostname
  newHostname="${1:-}"  
  printf "\n***Changing Hostname from $(hostname) to ${newHostname}***\n\n"
  # Remove any hostname from network config
  sed -i -r "/^HOSTNAME=\S*$/d" /etc/sysconfig/network
  # Set hostname in system control
  hostnamectl set-hostname "$newHostname"
  hostnamectl set-hostname "$newHostname" --pretty
  hostnamectl set-hostname "$newHostname" --static
  hostnamectl set-hostname "$newHostname" --transient
  hostnamectl
  printf "Restarting Network\n"
  service network restart
}
###############################################################################
function setupc7::upgradeOS() {
  printf "\n***Update Operating System***\n\n"
  yum update -y && yum upgrade -y
}
###############################################################################
function setupc7::installApps() {
  printf "\n***Installing Apps***\n\n"
  yum install -y open-vm-tools
  systemctl restart vmtoolsd
  
  yum install -y yum-utils
  yum install -y yum-plugin-remove-with-leaves
  yum install -y vim-enhanced
	yum install -y links
	yum install -y wget
	yum install -y unzip
	yum install -y bzip2
	yum install -y nano
	yum install -y rsync
  yum install -y telnet
  yum install -y nmap
  yum install -y lsof
  yum install -y lshw
  yum install -y iotop
  yum install -y tcpdump
  yum install -y iperf3
  yum install -y mtr
  yum install -y bind-utils
  yum install -y bind-libs
  yum install -y strace
  yum install -y dstat
  yum install -y setserial
  yum install -y smartmontools
  yum install -y sysstat
  yum install -y psmisc
  yum install -y rng-tools
  yum install -y gcc 
  yum install -y make 
  yum install -y perl 
  yum install -y python 
  yum install -y kernel-headers 
  yum install -y kernel-devel
  yum install -y epel-release
	yum install -y p7zip
	yum install -y ntfs-3g
	yum install -y hping3
  yum install -y htop
	yum install -y bash-completion bash-completion-extras
}
###############################################################################
function setupc7::disableFirewallD() {
    printf "\n***Disable Firewalld***\n\n"
    systemctl stop firewalld
    systemctl disable firewalld
}
###############################################################################
function setupc7::disableSELinux() {
  printf "\n***Disable SELinux***\n\n"
	/usr/sbin/setenforce 0
	sed -i -r 's/^#?(SELINUX=)(enforcing|permissive|disabled)/\1disabled/' /etc/selinux/config
  sestatus
}
###############################################################################
function setupc7::enableChrony() {
  printf "\n***Enable Chrony***\n\n"
  
  # install chrony
  yum install -y chrony
  
  # Enable chrony service at boot
  systemctl enable chronyd
  
  # start chrony service
  systemctl start chronyd
  
  # backup chrony config
  cp -a "/etc/chrony.conf" "/etc/chrony.conf.bak.$(date +"%Y%m%d-%H%M%S")"
  
  if [ -n "${1}" ]; then
    # Update NTP Server
    #replace first matched line with placeholder
    sed -i -r "0,/^server \S+ iburst$/s//--placeholder--/" "/etc/chrony.conf"
    #remove remaining matches
    sed -i -r "s/^server \S+ iburst$//" "/etc/chrony.conf"
    #replace placeholder with ntp address
    sed -i -r "s/^--placeholder--$/server ${1} iburst/" "/etc/chrony.conf"
  fi
  
  # restart chrony service
  systemctl restart chronyd
  chronyc tracking
  chronyc sources
  chronyc sourcestats
}
###############################################################################
function setupc7:addLexPublicSSHKey() {
  printf "\n***Add Lex's Public SSH Key***\n\n"
  mkdir -p ~/.ssh
  chmod 700 ~/.ssh
  touch ~/.ssh/authorized_keys
  chmod 600 ~/.ssh/authorized_keys
  
  if ! grep -q "AAAAB3NzaC1y" ~/.ssh/authorized_keys; then
    echo 'ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAzhgKCvZTruEOCnkDHxWW9738LdwuCUpMGPHpkxDP9bD4EoQXIBgcvAYJMqBwFYdcbMX7KhS7FTNfszNAD6jWiR17mwTBz/ccI/JYP1G7zLwIUYl6or9tYBiDD6q8sqgl1v2kF1GDd2Pbr/ShAX/s4twnqnMbHzJ8ftY0Ss0EsfSOrXr3BYm4hAduWYEZEY9ro4D8y4xGmFj/bBVIhU4FbS9vBf3g+51OL2/2GqHaorgOKGdb1u7QlSsrx4bTdZSwlNOBB1utZ3H4ImaymjP2sHTSgsbCF4DX9cAoFnkTEibohfY9fN2g7G9uTuneK5DtFYRxSKGxgJyJqNRX+M8+qQ==
    ' >> ~/.ssh/authorized_keys
  fi
}
###############################################################################
function setupc7::askContinue() {
  local choice
  read -p "Continue (y/n)?" choice
  case "$choice" in 
    y|Y ) printf "yes";;
    n|N ) exit 0;;
    * ) printf "invalid";;
  esac
}
###############################################################################
function setupc7::sysprep() {
  
  printf "\n***Sysprep***\n\n"
  
  printf "stop logging services"
  systemctl stop rsyslog.service
  service auditd stop
  
  printf "remove old kernels"
  yum install -y yum-utils
  yum install -y yum-plugin-remove-with-leaves
  /bin/package-cleanup -y --oldkernels –-count=1
  
  printf "yum remove dependencies which are no longer used because of a removal"
  yum autoremove
  printf "clean yum cache"
  yum clean all
  printf "free space taken by orphaned data from disabled or removed yum repos"
  rm -rf /var/cache/yum
  
  printf "Force the logs to rotate & remove old logs we don’t need"
  /usr/sbin/logrotate /etc/logrotate.conf --force
  rm -f /var/log/*-???????? /var/log/*.gz
  rm -f /var/log/dmesg.old
  rm -rf /var/log/anaconda
  
  printf "Truncate audit logs (and other logs we want to keep placeholders for)"
  cat /dev/null > /var/log/audit/audit.log
  cat /dev/null > /var/log/wtmp
  cat /dev/null > /var/log/lastlog
  cat /dev/null > /var/log/grubby
  
  printf "remove udev hardware rules"
  rm -f /etc/udev/rules.d/70*
  
  printf "Remove the traces of the template MAC address and UUIDs"
  sed -i '/^\(HWADDR\|UUID\)=/d' /etc/sysconfig/network-scripts/ifcfg-e*

  printf "Clean /tmp out"
  rm -rf /tmp/*
  rm -rf /var/tmp/*
  
  printf "remove SSH host keys"
  rm -f /etc/ssh/*key*
  
  printf "Remove the root user’s SSH history"
  rm -rf ~root/.ssh/
  rm -f ~root/anaconda-ks.cfg
  
  printf "remove the root password"
  passwd -d root

  printf "support guest customization of CentOS 7 in vSphere 5.5 and vCloud Air"
  mv /etc/redhat-release /etc/redhat-release.old
  touch /etc/redhat-release
  echo 'Red Hat Enterprise Linux Server release 7.0 (Maipo)' > /etc/redhat-release
  
  printf "Remove the root user’s shell history"
  history -cw

  printf "remove root users shell history"
  rm -f ~root/.bash_history
  unset HISTFILE

  # The  sys-unconfig  command  is used to restore a system's configuration to
  # an "as-manufactured" state, ready to be reconfigured again. The system's 
  # configuration consists of host-name, Network Information Service (NIS) 
  # domain name, timezone, IP address, IP subnet mask,and root password
  sys-unconfig
}
###############################################################################
###############################################################################
function setupc7::main() {

  # This script sets hostname, updates OS, installs Apps, disables SELinux, 
  # disables FirewallD, sets the timezone, enables Chrony, adds public SSH Keys,
  # and syspreps.
  
  setupc7::setHostname "localhost.localdomain"
  setupc7::upgradeOS
  setupc7::installApps
  setupc7::disableSELinux
  setupc7::disableFirewallD

  timedatectl set-timezone "America/Los_Angeles"
  setupc7::enableChrony "time.google.com"
  setupc7:addLexPublicSSHKey
  # setupc7::sysprep
  
  printf "\nDONE\n"
}
###############################################################################
###############################################################################
# The best scripts always start out at the bottom
setupc7::main "$@"
exit 0
