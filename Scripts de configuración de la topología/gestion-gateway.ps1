$ErrorActionPreference='Stop'
$src=@'
set -eu
test "$(cat /sys/class/net/ens4/address)" = fa:16:3e:b0:af:5e
ip -o -4 addr show dev ens3 | grep -Fq '10.20.12.7/24'
if ip -o -4 addr show dev ens4 | grep -vF '192.168.0.1/24' | grep -q .; then exit 1; fi
sudo -v </dev/tty
sudo netplan set ethernets.ens4.dhcp4=false
sudo netplan set 'ethernets.ens4.addresses=[192.168.0.1/24]'
sudo netplan generate
sudo ip link set dev ens4 up
if ! ip -o -4 addr show dev ens4 | grep -Fq '192.168.0.1/24'; then sudo ip address add 192.168.0.1/24 dev ens4; fi
ip -br -4 addr show dev ens4
ip route get 192.168.0.10
ip route get 192.168.0.23
sudo netplan get ethernets.ens4
'@
$blob=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($src.Replace("`r",'')))
& ssh.exe -t -p 22 ubuntu@10.20.12.7 "echo Introduce-la-clave-sudo-si-se-solicita; printf %s $blob | base64 -d | bash" | Tee-Object -FilePath (Join-Path $PSScriptRoot 'estado-gestion.txt')
if($LASTEXITCODE){throw 'No se confirmo la configuracion de ens4.'}
