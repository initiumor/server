#!/usr/bin/env bash
#
# vim: set et ts=2 sw=2

# set -x
set -euo pipefail

port=22
password=
user='user'
runner='runner'
apparmor_bin='https://testingcf.jsdelivr.net/gh/initiumor/server@main/assets/apparmor.d_0.001-1_amd64.deb'

red() {
  red='\e[91m'
  none='\e[0m'
  echo -e "${red}$*${none}"
}

log() {
  echo "$@" 1>&2
}

usage() {
  cat <<EOF
Usage: bash setup.sh [subcommand]

Subcommands:
    basic    Install dependencies and setup basic server
    full     Install dependencies and setup full server
EOF
  exit 1
}

setup() {
  log 'Start'

  install_deps
  disable_cloudinit

  port="$(get_high_port_number)"
  password="$(random_pass)"

  create_user
  setup_ssh
  setup_ufw
  setup_fail2ban
  setup_network
  setup_system
  # setup_module
  setup_identifier
  setup_permission
  setup_coredump
  setup_pam
  setup_apparmor
  setup_applications
  setup_unattended_upgrades

  log "SSH port is $(red "${port}")"
  log "User password is $(red "${password}")"

  log "Completed, please reboot and enjoy!"
}

setup_ssh() {
  log 'Setting up SSH server'

  log 'Replacing SSH port'
  local override
  override='/etc/ssh/sshd_config.d/override.conf'

  sed -i 's/# Include/Include/' /etc/ssh/sshd_config
  cat <<EOF >"${override}"
# See https://linux-audit.com/audit-and-harden-your-ssh-configuration/
LogLevel VERBOSE

Port $port
Protocol 2
MaxSessions 2
MaxAuthTries 3
ClientAliveCountMax 2
PermitRootLogin no
PermitEmptyPasswords no
PubkeyAuthentication yes
PasswordAuthentication no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
TCPKeepAlive no
IgnoreRhosts yes
AllowUsers $user
EOF

  # Refs to https://www.ssh-audit.com/hardening_guides.html
  # Re-generate the RSA and ED25519 keys
  rm -f /etc/ssh/ssh_host_*
  ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
  ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

  # Remove small Diffie-Hellman moduli
  awk '$5 >= 3071' /etc/ssh/moduli >/etc/ssh/moduli.safe
  mv -f /etc/ssh/moduli.safe /etc/ssh/moduli

  if [ "$(debian_version)" = "10" ]; then
    # Enable the RSA and ED25519 keys
    sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

    # Restrict supported key exchange, cipher, and MAC algorithms
    echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" >>/etc/ssh/sshd_config
  fi

  if [ "$(debian_version)" = "11" ]; then
    # Enable the RSA and ED25519 keys
    sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

    # Restrict supported key exchange, cipher, and MAC algorithms
    echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" >/etc/ssh/sshd_config.d/ssh-audit_hardening.conf
  fi

  if [ "$(debian_version)" = "12" ]; then
    # Restrict supported key exchange, cipher, and MAC algorithms
    echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\n KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nRequiredRSASize 3072\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n" >/etc/ssh/sshd_config.d/ssh-audit_hardening.conf
  fi

  log 'Configurations for SSH server'
  sshd -T

  systemctl reload ssh.service
}

setup_ufw() {
  # TODO: add more port here
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "${port}/tcp" comment 'Allow SSH'

  yes | ufw --force enable || true
}

setup_fail2ban() {
  log 'Setting up fail2ban'

  mkdir -p /etc/systemd/system/fail2ban.service.d
  cat <<EOF >/etc/systemd/system/fail2ban.service.d/override.conf
[Service]
PrivateDevices=yes
PrivateTmp=yes
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=-/var/run/fail2ban
ReadWritePaths=-/var/lib/fail2ban
ReadWritePaths=-/var/log/fail2ban
ReadWritePaths=-/var/spool/postfix/maildrop
ReadWritePaths=-/run/xtables.lock
CapabilityBoundingSet=CAP_AUDIT_READ CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_NET_RAW
EOF

  cat <<EOF >/etc/fail2ban/jail.local
[DEFAULT]
# Debian 12 has no log files, just journalctl
backend  = systemd

# "bantime" is the number of seconds that a host is banned.
bantime  = 1d
# "maxretry" is the number of failures before a host get banned.
maxretry = 5
# A host is banned if it has generated "maxretry" during the last "findtime"
findtime = 1h

[sshd]
enabled  = true
port     = $port
filter   = sshd
logpath  = /var/log/auth.log
findtime = 10m
EOF

  systemctl daemon-reload
  systemctl restart fail2ban
}

setup_network() {
  log 'Setting up network'

  cat <<EOF >/etc/sysctl.d/50-network.conf
###################################################################
# Improving performance
# See https://wiki.archlinux.org/title/sysctl
# Increasing the size of the receive queue
net.core.netdev_max_backlog = 16384
# Increase the maximum connections
net.core.somaxconn = 8192
# Increase the memory dedicated to the network interfaces
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.optmem_max = 65536
net.ipv4.tcp_rmem = 4096 1048576 2097152
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# Enable BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Enable TCP Fast Open
net.ipv4.tcp_fastopen = 3

# Tweak the pending connection handling
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0

# Change TCP keepalive parameters
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6

# Enable MTU probing
net.ipv4.tcp_mtu_probing = 1

# Increase the Ephemeral port range
net.ipv4.ip_local_port_range = 30000 65535

# TCP/IP stack hardening
# TCP SYN cookie protection
net.ipv4.tcp_syncookies = 1

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_echo_ignore_all = 1
net.ipv6.icmp.echo_ignore_all = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0 
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Validation of packets received from all interfaces
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable malicious IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Enable TCP SACK
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_fack = 1

# Log packets with impossible addresses for security
net.ipv4.conf.all.log_martians = 1
EOF
}

setup_system() {
  log 'Setting up and harden system'

  cat <<EOF >/etc/sysctl.d/30-hardening.conf
###################################################################
# System hardening
# See https://madaidans-insecurities.github.io/guides/linux-hardening.html
# See https://tldp.org/HOWTO/Adv-Routing-HOWTO/lartc.kernel.obscure.html
# See https://www.debian.org/doc/manuals/securing-debian-manual/index.en.html
# See https://github.com/GrapheneOS/hardened_malloc#traditional-linux-based-operating-systems
# See https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/index
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.printk = 3 3 3 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
dev.tty.ldisc_autoload = 0
vm.unprivileged_userfaultfd = 0
kernel.kexec_load_disabled = 1
kernel.sysrq = 4
kernel.unprivileged_userns_clone = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 2
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
vm.max_map_count = 1048576
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0

# IPv6 privacy extensions
# See https://madaidans-insecurities.github.io/guides/linux-hardening.html#ipv6-privacy
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
# kernel.deny_new_usb = 1
# net.ipv4.ip_unprivileged_port_start = 80
net.ipv4.ping_group_range = 0 2000000

# Increase system file descriptor limit
fs.file-max = 100000

# vm.vfs_cache_pressure = 45
# vm.dirty_background_ratio = 10
# vm.dirty_ratio = 10
# vm.dirty_writeback_centisecs = 1500
# kernel.nmi_watchdog = 0
EOF

  # Refs to https://madaidans-insecurities.github.io/guides/linux-hardening.html#hidepid
  # Qubes OS has its own mount policy, the strategy may break it.
  log 'Hide pid bewteen users'
  if ! is_qubes; then
    groupadd --system proc                                                                # --system primarily influences the range for choosing a GID, this might be however important, idk
    echo 'proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0' | tee -a /etc/fstab # assuming proc mount line is missing from fstab
    for d in /etc/systemd/system/{systemd-logind,user@}.service.d; do
      mkdir -p "$d"
      cat >"$d"/hidepid.conf <<EOF
[Service]
SupplementaryGroups=proc
EOF
    done
  fi

  # https://madaidans-insecurities.github.io/guides/linux-hardening.html#restricting-sysfs
  if [ "$(getent group sysfs)" ]; then
    log 'Restricting access to sysfs'
    mkdir -p /etc/systemd/system/user@.service.d
    cat <<EOF >/etc/systemd/system/user@.service.d/sysfs.conf
[Service]
SupplementaryGroups=sysfs
EOF
  fi

  log 'Enable privacy extensions for systemd-networkd'
  cat <<EOF >/etc/systemd/network/ipv6-privacy.conf
[Network]
IPv6PrivacyExtensions=kernel
EOF

  # Refs to https://madaidans-insecurities.github.io/guides/linux-hardening.html#kasr-kernel-modules
  log 'Blacklisting kernel modules'
  cat <<EOF >/etc/modprobe.d/blacklist.conf
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8023 /bin/false
install p8022 /bin/false
install can /bin/false
install atm /bin/false
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false
install cifs /bin/true
install nfs /bin/true
install nfsv3 /bin/true
install nfsv4 /bin/true
install gfs2 /bin/true
install vivid /bin/false
install bluetooth /bin/false
install btusb /bin/false
install uvcvideo /bin/false
install firewire-core /bin/false
install thunderbolt /bin/false
EOF

  # Refs to https://github.com/Kicksecure/security-misc/blob/7a4212dd/usr/libexec/security-misc/remove-system.map
  log 'Remove system.map'
  request https://testingcf.jsdelivr.net/gh/Kicksecure/security-misc@7a4212dd/usr/libexec/security-misc/remove-system.map | bash

  # Refs to https://madaidans-insecurities.github.io/guides/linux-hardening.html#restricting-su
  log 'Restricting su'
  echo 'auth		required	pam_wheel.so use_uid' | tee -a /etc/pam.d/su /etc/pam.d/su-l

  # Refs to https://madaidans-insecurities.github.io/guides/linux-hardening.html#locking-root
  log 'Locking the root account'
  passwd -l root

  # Refs to https://madaidans-insecurities.github.io/guides/linux-hardening.html#increase-hashing-rounds
  log 'Increasing the number of hashing rounds'
  echo 'password required pam_unix.so sha512 shadow nullok rounds=65536' | tee -a /etc/pam.d/passwd

  # Refs to https://madaidans-insecurities.github.io/guides/linux-hardening.html#apt-seccomp-bpf
  log 'Enable APT seccomp-bpf'
  echo 'APT::Sandbox::Seccomp "true";' | tee /etc/apt/apt.conf.d/40sandbox
}

setup_module() {
  log 'Enable TCP Brutal kernel module'
  bash <(request https://tcp.hy2.sh/)
}

setup_identifier() {
  log 'Setting up timezone to UTC'
  timedatectl set-timezone UTC

  log 'Setting up machine id'
  echo 'b08dfa6083e7567a1921a715000001fb' | tee /var/lib/dbus/machine-id /etc/machine-id

  # Refs to https://madaidans-insecurities.github.io/guides/linux-hardening.html#time-synchronisation
  # Refs to https://github.com/szorfein/secure-time-sync/tree/89bb833b1ba82e2603508db66d49ba20d0fd2fd0
  # Refs to https://github.com/Obscurix/Obscurix/tree/d9895045f/airootfs/etc/systemd/system
  log 'Setting up time sync'
  uninstall ntp
  systemctl disable systemd-timesyncd 2>/dev/null || true
  local syncbin='/usr/bin/secure-time-sync'
  request https://testingcf.jsdelivr.net/gh/girlbossceo/secure-time-sync@05ba04f3/secure-time-sync.timer | tee /etc/systemd/system/secure-time-sync.timer
  request https://testingcf.jsdelivr.net/gh/szorfein/secure-time-sync@89bb833/secure-time-sync.service | tee /etc/systemd/system/secure-time-sync.service
  request https://testingcf.jsdelivr.net/gh/szorfein/secure-time-sync@89bb833/secure-time-sync.sh | tee $syncbin

  chmod o+rx $syncbin
  systemctl enable --now secure-time-sync.timer
}

setup_permission() {
  # Refs to https://madaidans-insecurities.github.io/guides/linux-hardening.html#file-permissions
  log 'Setting up file permissions'
  # chmod 700 /home/$user
  # chmod 700 /home/$runner

  chmod 700 /boot /usr/src /lib/modules /usr/lib/modules

  echo 'umask 0077' | tee /etc/profile.d/umask.sh

  find / -type f \( -perm -4000 -o -perm -2000 \) || true

  # Set default permissions for directories
  chmod g+s /usr/share/keyrings
  setfacl -d -m group::r-- /usr/share/keyrings
  setfacl -d -m other::r-- /usr/share/keyrings

  # Refs to https://madaidans-insecurities.github.io/guides/linux-hardening.html#partitioning
  # Qubes OS has its own mount policy, the strategy may break it.
  if ! is_qubes; then
    cat <<EOF >/etc/fstab
/        /          ext4    defaults                              1 1
/home    /home      ext4    defaults,nosuid,noexec,nodev          1 2
/tmp     /tmp       ext4    defaults,bind,nosuid,noexec,nodev     1 2
/var     /var       ext4    defaults,bind,nosuid                  1 2
/boot    /boot      ext4    defaults,nosuid,noexec,nodev
EOF
  fi
}

setup_coredump() {
  # Refs to https://madaidans-insecurities.github.io/guides/linux-hardening.html#core-dumps
  mkdir -p /etc/systemd/coredump.conf.d

  cat <<EOF >/etc/systemd/coredump.conf.d/disable.conf
[Coredump]
Storage=none
EOF

  cat <<EOF >/etc/sysctl.d/40-disable-coredump.conf
# https://madaidans-insecurities.github.io/guides/linux-hardening.html#core-dumps
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0
vm.swappiness = 1
EOF

  echo '* hard core 0' | tee -a /etc/security/limits.d/99-ulimit.conf
}

setup_pam() {
  cat <<EOF >>/etc/pam.d/passwd
# https://madaidans-insecurities.github.io/guides/linux-hardening.html#pam
password required pam_pwquality.so retry=2 minlen=16 difok=6 dcredit=-3 ucredit=-2 lcredit=-2 ocredit=-3 enforce_for_root
password required pam_unix.so use_authtok sha512 shadow
EOF

  cat <<EOF >/etc/pam.d/system-login
# https://madaidans-insecurities.github.io/guides/linux-hardening.html#pam
auth optional pam_faildelay.so delay=4000000
EOF
}

setup_apparmor() {
  log 'Setting up AppArmor'

  echo 'write-cache' | sudo tee -a /etc/apparmor/parser.conf
  echo 'cache-loc /etc/apparmor/earlypolicy/' | sudo tee -a /etc/apparmor/parser.conf
  echo 'Optimize=compress-fast' | sudo tee -a /etc/apparmor/parser.conf

  mkdir -p /etc/systemd/system/haveged.service.d

  if is_qubes; then
    rm -f /etc/apparmor.d/usr.bin.thunderbird
  fi

  request $apparmor_bin | tee -a /tmp/apparmor.d_amd64.deb >/dev/null
  dpkg -i /tmp/apparmor.d_amd64.deb

  aa-enforce agetty \
    apt \
    auditd \
    cron \
    dbus-daemon \
    fail2ban-client \
    fail2ban-server \
    haveged \
    hostname \
    id \
    ip \
    lsblk \
    ps \
    rsyslogd \
    ssh \
    sshd \
    sudo \
    sysctl \
    systemd-journald \
    systemd-modules-load \
    systemd-sysctl \
    systemd-shutdown \
    w \
    who \
    whoami
}

setup_applications() {
  # TODO
  log 'Setting up applications'
  log 'Setting up i2pd'
  local i2pd='/etc/i2pd/i2pd.conf'
  # outproxies: purokishi.i2p,exit.stormycloud.i2p
  outproxy='exit.stormycloud.i2p'
  sed -Ei "s/^#\W+outproxy\W+=.*/ outproxy = ${outproxy}/g" ${i2pd}
  sed -i 's/# subscriptions/ subscriptions/' ${i2pd}
  sed -i '/ subscriptions/ s/$/,http:\/\/skank.i2p\/hosts.txt/' ${i2pd}
}

setup_unattended_upgrades() {
  systemctl enable --now unattended-upgrades
  cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Verbose "1";
APT::Periodic::AutocleanInterval "7";

Unattended-Upgrade::Mail "root";

Unattended-Upgrade::Origins-Pattern {
  "origin=Debian,codename=\${distro_codename},label=Debian";
  "origin=Debian,codename=\${distro_codename},label=Debian-Security";
  "origin=Debian,codename=\${distro_codename}-security,label=Debian-Security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::Automatic-Reboot "false";
EOF
  systemctl restart unattended-upgrades
}

user_exists() {
  id "$1" &>/dev/null
}

command_exists() {
  command -v "$1" &>/dev/null
}

get_distro() {
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    distro="${NAME}"
  elif type lsb_release >/dev/null 2>&1; then
    distro=$(lsb_release -si)
  elif [ -f /etc/lsb-release ]; then
    # For some versions of Debian/Ubuntu without lsb_release command
    # shellcheck disable=SC1091
    . /etc/lsb-release
    distro="${DISTRIB_ID}"
  elif [ -f /etc/debian_version ]; then
    # Older Debian/Ubuntu/etc.
    distro=Debian
  else
    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
    distro="$(uname -s)"
  fi

  echo "${distro}"
}

is_qubes() {
  os="$(uname -a)"
  case $os in
  'qubes')
    return 0
    ;;
  '*')
    return 1
    ;;
  esac
}

is_debian() {
  if [[ "$(get_distro)" =~ Debian* ]]; then
    return 0
  fi

  return 1
}

debian_version() {
  local version
  version="$(cat /etc/debian_version)"
  case "${version}" in
  10*)
    echo 10
    ;;
  11*)
    echo 11
    ;;
  12*)
    echo 12
    ;;
  esac
}

get_high_port_number() {
  port="$(comm -23 <(seq 10000 65535 | sort) <(ss -Htan | awk '{print $4}' | cut -d':' -f2 | sort -u) | shuf | head -n 1)"
  echo "${port}"
}

random_pass() {
  # words="$(sort -R <(printf "a-z\nA-Z\n0-9"))"
  # while IFS= read -r regex; do
  #   head -c 100 /dev/urandom | tr -dc "${regex}" | head -c 30
  # done <<<"${words}"

  head -c 100 /dev/urandom | tr -dc 'a-zA-Z0-9-_!@#%^&*()_+{}|<>?=' | fold -w 30 | grep -i '[!@#%^&*()_+{}|<>?=]' | head -n 1
}

create_user() {
  # Refs to https://madaidans-insecurities.github.io/guides/linux-hardening.html#accessing-root-securely
  log 'Accessing root securely'

  if ! user_exists "${user}"; then
    useradd --create-home --user-group --shell /bin/bash --password "$(openssl passwd -6 "${password}")" $user

    echo "${user} ALL=(ALL) ALL" | tee /etc/sudoers.d/user
    chmod 440 /etc/sudoers.d/user

    mkdir -p "/home/${user}/.ssh"
    chmod -R 700 "/home/${user}/.ssh"
    touch "/home/${user}/.ssh/authorized_keys"
    chmod 600 "/home/${user}/.ssh/authorized_keys"
    chown -R "${user}:${user}" "/home/${user}/.ssh"
  fi

  if [ -f ~/.ssh/authorized_keys ]; then
    cat ~/.ssh/authorized_keys >/home/user/.ssh/authorized_keys
  fi

  if ! user_exists "${runner}"; then
    useradd --create-home --user-group --shell /sbin/nologin $runner
  fi
}

disable_cloudinit() {
  if [ -d /etc/cloud ]; then
    # Refs to https://cloudinit.readthedocs.io/en/latest/howto/disable_cloud_init.html#method-1-text-file
    log 'Disable cloud-init'
    touch /etc/cloud/cloud-init.disabled
  fi
}

install_deps() {
  log 'Installing dependencies'
  apt-get update -yqq
  DEBIAN_FRONTEND="noninteractive" apt-get upgrade -yqq
  install apt-transport-https \
    unattended-upgrades \
    apt-listchanges \
    apparmor-profiles \
    apparmor-utils \
    openssh-server \
    libpwquality-common \
    python3-systemd \
    iproute2 \
    rkhunter \
    fail2ban \
    sudo \
    acl \
    ufw \
    tor \
    i2pd
}

install() {
  apt-get install --no-install-recommends -yqq "$@"
}

uninstall() {
  apt-get -yqq remove --purge "$@"
}

request() {
  curl -sSfL --tlsv1.2 --proto =https "$@"
}

main() {
  if ! is_debian; then
    red 'Avaliable for Debian distro only'
    exit 1
  fi

  target="${1:-}"
  case "${target}" in
  "basic")
    setup
    ;;
  *)
    usage
    ;;
  esac
}

main "$@"
