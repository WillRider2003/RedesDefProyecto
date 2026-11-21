#!/bin/bash
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
wan_ip=10.20.12.7
wan=$(ip -o -4 addr show | awk '$4 ~ /^10\.20\.12\.7\// {print $2}')
[[ -n $wan && $wan != *$'\n'* ]]
echo "Gateway $wan=$wan_ip; destino gestion 192.168.0.0/24"
ensure() {
    local table=$1 chain=$2
    shift 2
    if ! iptables -w 5 -t "$table" -C "$chain" "$@" 2>/dev/null; then
        iptables -w 5 -t "$table" -I "$chain" 1 "$@"
    fi
}
for (( i=0; i<14; i++ )); do
    target=192.168.0.$((10+i))
    port=$((5800+i))
    orig=(-m conntrack --ctstate DNAT --ctorigdst "$wan_ip" --ctorigdstport "$port")
    ensure nat PREROUTING -i "$wan" -d "$wan_ip" -p tcp --dport "$port" -j DNAT --to-destination "$target:22"
    ensure filter FORWARD -i "$wan" -o "$wan" -p tcp -d "$target" --dport 22 "${orig[@]}" -j DROP
    ensure filter FORWARD -i "$wan" ! -o "$wan" -p tcp -d "$target" --dport 22 "${orig[@]}" -j ACCEPT
    ensure filter FORWARD ! -i "$wan" -o "$wan" -p tcp -s "$target" --sport 22 "${orig[@]}" -j ACCEPT
    ensure nat POSTROUTING ! -o "$wan" -d "$target" -p tcp --dport 22 "${orig[@]}" -j MASQUERADE
done
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -S PREROUTING | grep -F -- '--to-destination 192.168.0.'
