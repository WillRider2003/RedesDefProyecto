#!/bin/bash
set -euo pipefail
shopt -s nullglob
interfaces=(/sys/class/net/ens[0-9]*)
(( ${#interfaces[@]} )) || { echo 'Sin interfaces ens detectadas'; exit 1; }
conf=/etc/sysctl.d/99-vnrt-interfaces-ipv6.conf
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
for path in "${interfaces[@]}"; do
    dev=${path##*/}
    [[ $dev =~ ^ens[0-9]+$ ]] || continue
    key="net.ipv6.conf.$dev.disable_ipv6"
    echo "$dev antes=$(sysctl -n "$key")"
    echo "$key = 1" >> "$tmp"
done
test -s "$tmp"
sudo -v </dev/tty
sudo -n install -m 0644 "$tmp" "$conf"
sudo -n sysctl -p "$conf"
for path in "${interfaces[@]}"; do
    dev=${path##*/}
    [[ $dev =~ ^ens[0-9]+$ ]] || continue
    [[ $(sysctl -n "net.ipv6.conf.$dev.disable_ipv6") == 1 ]]
    [[ -z $(ip -6 -o addr show dev "$dev") ]]
    echo "VERIFICADA $dev"
done
