$ErrorActionPreference='Continue'
$dir=$PSScriptRoot
$file=Join-Path $dir ('ipv6-verificacion-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'.txt')
$blob=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $dir 'ipv6-interfaces.sh')))
foreach ($port in @(22)+(5800..5806)+(5808..5813)) {
    $dev='ens3'; $ip="192.168.0.$($port-5790)"
    if($port -eq 22){$dev='ens4';$ip='192.168.0.1'}
    $section="Puerto $port | $dev | $ip"
    $section | Tee-Object -FilePath $file -Append
    Write-Host 'Si sudo solicita la clave, introducela aqui.'
    $remote="printf %s $blob | base64 -d | bash -s -- $dev $ip"
    & ssh.exe -tt -o ForwardAgent=no -o ConnectTimeout=5 -p $port ubuntu@10.20.12.7 $remote | Tee-Object -FilePath $file -Append
    "RC $port $LASTEXITCODE" | Tee-Object -FilePath $file -Append
}
'FIN' | Tee-Object -FilePath $file -Append

