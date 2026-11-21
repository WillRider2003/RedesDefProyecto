#!/bin/bash
set -euo pipefail
dev=$1
ip4=$2
case "$dev:$ip4" in ens4:192.168.0.1) ;; ens3:192.168.0.1[0-9]|ens3:192.168.0.2[0-3]) ;; *) exit 2;; esac
ip -o -4 addr show dev "$dev" | awk -v want="$ip4/24" '$4==want{ok=1}END{exit !ok}' || { echo 'OMITIDA: IP distinta de la prevista'; exit 1; }
sudo -v </dev/tty
key=ethernets.$dev
config() { sudo -n netplan get "$key"; }
check() { python3 -c 'import sys,yaml; x=yaml.safe_load(sys.stdin) or {}; keys=["dhcp6","accept-ra","link-local"]; print(" ".join(k+"="+str(x.get(k,"sin declarar")) for k in keys)); sys.exit(0 if x.get("dhcp6") is False and x.get("accept-ra") is False and x.get("link-local")==[] else 1)'; }
echo "ANTES $dev $ip4"
if config | check; then echo 'VERIFICADA: ya estaba declarado'; exit 0; fi
networkctl status "$dev" --no-pager 2>/dev/null | grep -Eq 'Network File: .*/[^ ]*netplan[^ ]*\.network' || { echo 'OMITIDA: confirmar renderer antes de aplicar'; exit 1; }
sudo -n netplan set "$key.dhcp6=false"
sudo -n netplan set "$key.accept-ra=false"
sudo -n netplan set "$key.link-local=[]"
sudo -n netplan generate
config | check || { echo 'ERROR: verificar las definiciones Netplan combinadas'; exit 1; }
sudo -n networkctl reload
sudo -n networkctl reconfigure "$dev"
echo "APLICADA $dev $ip4"
