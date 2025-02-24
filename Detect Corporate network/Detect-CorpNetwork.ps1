<#PSScriptInfo
.SYNOPSIS
    Script to create a scheduled task to detect network changes and based on change either disable or enable Global Secure Global Access Private Access
 
.DESCRIPTION
    This script will create a scheduled task which executes when a network change occurs. The scheduled task is configured to run in user context and
    executes a powershell script that creates a registry value based on whether the device is on a corporate network or remote network. This disables 
    Global Secure Access Private Access when on a corporate network.

.PARAMETER NetworkCheck
    Configure the network check to perform. DNS, FQDN and IP are accepted values.

.PARAMETER DNSSuffix
    If "DNS" is configured in the NetworkCheck parameter, specify a DNS suffix.

.PARAMETER HostFQDN
    If "FQDN" is configured in the NetworkCheck parameter, specify the FQDN name to resolve using the internal DNS.    

.PARAMETER HostIP
    If "IP" is configured in the NetworkCheck parameter, specify the IP address to ping.
        
.EXAMPLE
    .\Detect-CorpNetwork.ps1 -NetworkCheck DNS -DNSSuffix "domain.local" 
        Network check is performed using the DNS suffix configured on the primary NIC

    .\Detect-CorpNetwork.ps1 -NetworkCheck FQDN -HostFQDN "domaincontroller.domain.local" 
        Network check is performed using the FQDN name resolution of a host on the network.
    
    .\Detect-CorpNetwork.ps1 -NetworkCheck DNS -HostIP "192.168.1.1" 
        Network check is performed using the IP address of a host/device on the network.

.NOTES
       
.AUTHOR
    Kasper Johansen 
    https://kasperjohansen.net

.COPYRIGHT
    Feel free to use this as much as you want :)

.RELEASENOTES
    24-02-2025 - 1.0.0 - Release to public

.CHANGELOG
    24-02-2025 - 1.0.0 - Release to public
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet("DNS","FQDN","IP")]
    [string]$NetworkCheck,
    [Parameter(Mandatory = $false)]
    [string]$DNSSuffix,
    [Parameter(Mandatory = $false)]
    [string]$HostFQDN,
    [Parameter(Mandatory = $false)]
    [string]$HostIP
)

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
                    