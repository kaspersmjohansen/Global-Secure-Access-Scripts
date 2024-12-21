$DNSSuffix = "johansen.local"
$PrivateConnectorFQDN = "srvapc01.johansen.local"
$PrivateConnectorIP = "192.168.30.245"
$HostCheck = "DNS" #IP or #FQDN or #DNS

# Detect if device is connected to local corporate network, if not disable GSA Private Access
If ($HostCheck -eq "DNS")
{
    Write-Host "Determine corp network access based on DNS suffix" -ForegroundColor Cyan
    # Get active and connected Network Interface Card - Exclude Hyper-V virtual ethernet switches and Hyper-V network adapters
    $ActivePhysicalNIC = Get-NetAdapter | Where-Object {$_.Status -ne "Disconnected" -and $_.InterfaceDescription -notlike "Hyper-V Virtual Ethernet*"}

    # Get active network interface card IP configuration
    $IPconfiguration = Get-NetIPConfiguration -InterfaceIndex $ActivePhysicalNIC.ifIndex

    If ($($IPconfiguration.NetProfile.Name) -eq "$DNSSuffix")
    {
        Write-Host "Current DNS Suffix: $($IPconfiguration.NetProfile.Name)" -ForegroundColor Cyan
        Write-Host "Connected to corp network" -ForegroundColor Cyan
        Write-Host "Global Secure Access client is: DISABLED" -ForegroundColor Cyan
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Global Secure Access Client"  -Name "IsPrivateAccessDisabledByUser" -Value 1 -Type DWord -Force
    }
        else 
        {
            Write-Host "On unknown network" -ForegroundColor Cyan
            Write-Host "Global Secure Access client is: ENABLED" -ForegroundColor Cyan
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Global Secure Access Client"  -Name "IsPrivateAccessDisabledByUser" -Value 0 -Type DWord -Force
        }
}
        If ($HostCheck -eq "FQDN")
        {
            Write-Host "Determine corp network access based on resolving FQDN" -ForegroundColor Cyan
            If (Resolve-DnsName -Name $PrivateConnectorFQDN -Type A -ErrorAction SilentlyContinue)
            {
                Write-Host "Resolved FQDN: $PrivateConnectorFQDN" -ForegroundColor Cyan
                Write-Host "COnnected to corp network" -ForegroundColor Cyan
                Write-Host "Global Secure Access client is: DISABLED" -ForegroundColor Cyan
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Global Secure Access Client"  -Name "IsPrivateAccessDisabledByUser" -Value 1 -Type DWord -Force
            }
                else 
                {
                    Write-Host "On unknown network" -ForegroundColor Cyan
                    Write-Host "Global Secure Access client is: ENABLED" -ForegroundColor Cyan
                    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Global Secure Access Client"  -Name "IsPrivateAccessDisabledByUser" -Value 0 -Type DWord -Force
                }
        }               
                If ($HostCheck -eq "IP")
                {
                    Write-Host "Determine corp network access based on IP ping" -ForegroundColor Cyan
                    If (Test-Connection $PrivateConnectorIP -Count 3 -Quiet -ErrorAction SilentlyContinue)
                    {
                        Write-Host "Pinged IP: $PrivateConnectorIP"-ForegroundColor Cyan
                        Write-Host "On corp network" -ForegroundColor Cyan
                        Write-Host "Global Secure Access client is: DISABLED" -ForegroundColor Cyan
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Global Secure Access Client"  -Name "IsPrivateAccessDisabledByUser" -Value 1 -Type DWord -Force    
                    }
                        else
                        {
                            Write-Host "On unknown network" -ForegroundColor Cyan
                            Write-Host "Global Secure Access client is: ENABLED" -ForegroundColor Cyan
                            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Global Secure Access Client"  -Name "IsPrivateAccessDisabledByUser" -Value 0 -Type DWord -Force
                        }
                }
                    