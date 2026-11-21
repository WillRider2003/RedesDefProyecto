$ErrorActionPreference='Stop'
$id=[guid]::NewGuid().ToString('N')
$remote=".nat-ssh-$id"
$unit=@'
[Unit]
Description=SSH del slice VNRT a las VMs de gestion
Wants=network-online.target
After=network-online.target nftables.service netfilter-persistent.service ufw.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vnrt-g5-nat-ssh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
'@
$payload=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'nat-ssh.sh')))
$unit64=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($unit.Replace("`r",'') + "`n"))
$commands=@(
    "set -eu",
    "umask 077",
    "mkdir ~/$remote",
    "cd ~/$remote",
    "printf %s $payload | base64 -d > nat-ssh.sh",
    "printf %s $unit64 | base64 -d > vnrt-g5-nat-ssh.service",
    'sudo -v',
    'sudo bash ./nat-ssh.sh > estado.txt 2>&1 || { cat estado.txt; exit 1; }',
    'sudo install -m 0755 ./nat-ssh.sh /usr/local/sbin/vnrt-g5-nat-ssh',
    'sudo install -m 0644 ./vnrt-g5-nat-ssh.service /etc/systemd/system/vnrt-g5-nat-ssh.service',
    'sudo systemctl daemon-reload',
    'sudo systemctl enable --now vnrt-g5-nat-ssh.service',
    'sudo systemctl is-active vnrt-g5-nat-ssh.service >> estado.txt',
    'sudo systemctl is-enabled vnrt-g5-nat-ssh.service >> estado.txt',
    'cat estado.txt'
) -join '; '
& ssh.exe -t -o ForwardAgent=no -o ConnectTimeout=8 -p 22 ubuntu@10.20.12.7 $commands
$rc=$LASTEXITCODE
& scp.exe -P 22 "ubuntu@10.20.12.7:${remote}/estado.txt" (Join-Path $PSScriptRoot 'estado-nat.txt')
if($rc -or $LASTEXITCODE){throw 'No se pudieron confirmar todas las reglas o su persistencia.'}
