<#PSScriptInfo
.SYNOPSIS
    Script to do an unattended install of the Microsoft Entra Private Network Connector.
 
.DESCRIPTION
    This script will install the Microsoft Entra Private Network Connector and implement
    the recommended TLS 1.2 security hardening. The Private Network Connector will NOT be registered in
    Entra.

    Additional information about the TLS 1.2 security hardening and Private Network Connector configuration
    can be found here - https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-connectors

    A log file of the Private Network Connector setup process is created in the C:\Windows\Logs folder.

.AUTHOR
    Kasper Johansen 
    kmj@apento.com

.COMPANYNAME 
    APENTO
#>

# Enable TLS 1.2 -Requires restart!
If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'))
{
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null

If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'))
{
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null

If (-Not (Test-Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'))
{
    New-Item 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force | Out-Null

Write-Host 'TLS 1.2 has been enabled. You must restart the Windows Server for the changes to take effect.' -ForegroundColor Cyan

# Install Private Network Connector
Write-Host 'Installing the Entra Private Network Connector - Please wait...' -ForegroundColor Cyan
$LogFileName = "Microsoft Entra private network connector"+"-"+"install"+"-"+"$(Get-Date -Format hhmmss-ddMMyyyy)"+".log"
Start-Process -Filepath "$PSScriptRoot\MicrosoftEntraPrivateNetworkConnectorInstaller.exe" -Argumentlist "REGISTERCONNECTOR=`"false`" /install /quiet /log `"$env:windir\Logs\$LogFileName`"" -Wait