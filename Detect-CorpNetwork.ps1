$DNSSuffix = "johansen.local"
$PrivateConnectorFQDN = "srvapc01.johansen.local"
$PrivateConnectorIP = "192.168.30.245"
$HostCheck = "DNS" #IP or #FQDN or #DNS

# Registry kay and value
$GSAregkey = "HKCU:\Software\Microsoft\Global Secure Access Client"
$GSAregvalue = "IsPrivateAccessDisabledByUser"

function Set-RegistryValue
    {
    param(
        [string]$RegPath,
        [string]$RegName,
        $RegValue,
        [ValidateSet("String","ExpandString","Binary","Dword","MultiString","Qword")]
        [string]$RegType = "String"
        )
            If (!(Test-Path -Path $RegPath))
            {
                Write-Output "Creating the registry key $RegPath"
                New-Item -Path $RegPath -Force | Out-Null
            }
                else
                {
                    $RegPath.Property
                    Write-Output "$RegPath already exist"
                }
                    If ($RegName)
                    {
                    $CheckReg = Get-Item -Path $RegPath

                        If ($CheckReg.GetValue($RegName) -eq $null)
                        {
                            Write-Output "Creating the registry value $RegName in $RegPath"
                            New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType $RegType | Out-Null
                        }
                            else
                            {
                                Write-Output "Modifying the registry value $RegName in $RegPath"
                                Set-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue | Out-Null
                            }
                    }
    }

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
        Set-RegistryValue -RegPath $GSAregkey -RegName $GSAregvalue -RegValue "1" -RegType "Dword"
    }
        else 
        {
            Write-Host "On unknown network" -ForegroundColor Cyan
            Write-Host "Global Secure Access client is: ENABLED" -ForegroundColor Cyan
            Set-RegistryValue -RegPath $GSAregkey -RegName $GSAregvalue -RegValue "1" -RegType "Dword"
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
                Set-RegistryValue -RegPath $GSAregkey -RegName $GSAregvalue -RegValue "1" -RegType "Dword"
            }
                else 
                {
                    Write-Host "On unknown network" -ForegroundColor Cyan
                    Write-Host "Global Secure Access client is: ENABLED" -ForegroundColor Cyan
                    Set-RegistryValue -RegPath $GSAregkey -RegName $GSAregvalue -RegValue "1" -RegType "Dword"
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
                        Set-RegistryValue -RegPath $GSAregkey -RegName $GSAregvalue -RegValue "1" -RegType "Dword"    
                    }
                        else
                        {
                            Write-Host "On unknown network" -ForegroundColor Cyan
                            Write-Host "Global Secure Access client is: ENABLED" -ForegroundColor Cyan
                            Set-RegistryValue -RegPath $GSAregkey -RegName $GSAregvalue -RegValue "1" -RegType "Dword"
                        }
                }
                    