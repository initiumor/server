#!/usr/bin/env bash
#
# vim: set et ts=2 sw=2

# set -x
set -euo pipefail

log() {
  echo "$@" 1>&2
}

request() {
  curl -sSfL --tlsv1.2 --proto =https "$@"
}

audit() {
  log 'Downloading lynis'
  lynis="lynis"
  mkdir ${lynis}
  request https://api.github.com/repos/CISOfy/${lynis}/tarball | tar -zx -C ${lynis} --strip-components=1
  cd ${lynis}
  log 'Perform lynis'
  ./lynis audit system
  cd ..
  rm -rf ${lynis}

  ssh_audit="ssh-audit"
  log 'Downloading ssh-audit'
  mkdir ${ssh_audit}
  request https://api.github.com/repos/jtesta/${ssh_audit}/tarball | tar -zx -C ${ssh_audit} --strip-components=1
  cd ${ssh_audit}
  log 'Perform ssh-audit'
  local port
  port="$(ss -anlp | grep 'sshd' | awk 'NR==1{print $5}' | cut -d ':' -f 2)"
  ./ssh-audit.py --ssh1 --ssh2 --ipv4 --ipv6 --port "${port}" localhost
  cd ..
  rm -rf ${ssh_audit}

  kernel_hardening_checker="kernel-hardening-checker"
  log 'Downloading kernel-hardening-checker'
  mkdir ${kernel_hardening_checker}
  request https://api.github.com/repos/a13xp0p0v/${kernel_hardening_checker}/tarball | tar -zx -C ${kernel_hardening_checker} --strip-components=1
  cd ${kernel_hardening_checker}
  log 'Perform kernel-hardening-checker'
  ./bin/kernel-hardening-checker -g X86_64
  cd ..
  rm -rf ${kernel_hardening_checker}
}

main() {
  target="${1:-}"
  case "${target}" in
  *)
    audit
    ;;
  esac
}

main "$@"