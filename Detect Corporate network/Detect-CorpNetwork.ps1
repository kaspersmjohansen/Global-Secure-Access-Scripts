<#PSScriptInfo
.SYNOPSIS
    Script detect network changes and based on change either disable or enable Global Secure Global Access Private Access
 
.DESCRIPTION
    This script will detect when a NIC network change occurs. The script should be executed in user context as it creates a 
    registry value based on whether the device is on a corporate network or remote network. The registry value either enable 
    Global Secure Access Private Access when the Windows device is not on a corporate network or disables  
    Global Secure Access Private Access when on a corporate network.

.PARAMETER NetworkCheck
    Configure the network check to perform. DNS, FQDN and IP are accepted values.

    DNS = Check for a DNS suffix, configured in the DNSSuffix variable
    FQDN = Check if a FQDN can be resolved, configured in the HosFQDN variable
    IP = Check if a specific IP address answers ping requests, configured in the HostIP variable

.PARAMETER DNSSuffix
    If "DNS" is configured in the NetworkCheck parameter, specify a DNS suffix.

.PARAMETER HostFQDN
    If "FQDN" is configured in the NetworkCheck parameter, specify the FQDN name to resolve using the internal DNS.    

.PARAMETER HostIP
    If "IP" is configured in the NetworkCheck parameter, specify the IP address to ping.

.NOTES

.TODO

Configure a fallback feature. If a check fails do another check before disabling or enabling Global Secure Access Private Access.
       
.AUTHOR
    Kasper Johansen 
    https://kasperjohansen.net

.COPYRIGHT
    Feel free to use this as much as you want :)

.RELEASENOTES
    28-02-2025 - 1.0.0 - Release to public

.CHANGELOG
    28-02-2025 - 1.0.0 - Release to public
#>

# Script variables
$NetworkCheck = ""
$DNSSuffix = ""
$HostFQDN = ""
$HostIP = ""

# GSA client disable private access user registry key and value
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
If ($NetworkCheck -eq "DNS")
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
        If ($NetworkCheck -eq "FQDN")
        {
            Write-Host "Determine corp network access based on resolving FQDN" -ForegroundColor Cyan
            If (Resolve-DnsName -Name $HostFQDN -Type A -ErrorAction SilentlyContinue)
            {
                Write-Host "Resolved FQDN: $HostFQDN" -ForegroundColor Cyan
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
                If ($NetworkCheck -eq "IP")
                {
                    Write-Host "Determine corp network access based on IP ping" -ForegroundColor Cyan
                    If (Test-Connection $HostIP -Count 3 -Quiet -ErrorAction SilentlyContinue)
                    {
                        Write-Host "Pinged IP: $HostIP"-ForegroundColor Cyan
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