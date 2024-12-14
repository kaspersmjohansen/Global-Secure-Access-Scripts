$DNSSuffix = "johansen.local"
$PrivateConnectorFQDN = "srvapc01.johansen.local"
$PrivateConnectorIP = "192.168.30.245"
$HostCheck = "FQDN" #IP or #FQDN

# Get active and connected Network Interface Card - Exclude Hyper-V virtual ethernet switches and Hyper-V network adapters
$ActivePhysicalNIC = Get-NetAdapter | Where-Object {$_.Status -ne "Disconnected" -and $_.InterfaceDescription -notlike "Hyper-V Virtual Ethernet*"}

# Get active network interface card IP configuration
$IPconfiguration = Get-NetIPConfiguration -InterfaceIndex $ActivePhysicalNIC.ifIndex

# Detect if device is connected to local corporate network and disable GSA Private Access
If ($($IPconfiguration.NetProfile.Name) -eq "$DNSSuffix")
{
    Write-Host "On corp network - DNS Suffix: $($IPconfiguration.NetProfile.Name)"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Global Secure Access Client"  -Name "IsPrivateAccessDisabledByUser" -Value 1 -Type DWord -Force
}
elseif (Resolve-DnsName -Name $PrivateConnectorFQDN -Type A -ErrorAction SilentlyContinue)
{
    Write-Host "On corp network - DNS Suffix: $($IPconfiguration.NetProfile.Name)"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Global Secure Access Client"  -Name "IsPrivateAccessDisabledByUser" -Value 1 -Type DWord -Force
}

else {
    <# Action when all if and elseif conditions are false #>
}