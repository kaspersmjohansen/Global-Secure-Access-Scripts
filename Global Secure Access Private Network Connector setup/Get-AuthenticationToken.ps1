<#PSScriptInfo
.SYNOPSIS
    Script to get an offline authentication token.
 
.DESCRIPTION
    This script will create an offline authentication token and store it in c:\temp\token.txt.
    If the authentication token is used to register a Microsoft Entra Private Network Connector
    make sure you have the Entra ID Application Administrator role assigned before creating 
    the authentication token, otherwise the registration will fail.

    The URLs https://login.microsoft.com and https://aadcdn.msauth.net are added to the list
    of Trusted Sites in Internet Options. 
    This is necessary for the authentication process to work properly.

.AUTHOR
    Kasper Johansen 
    kmj@apento.com

.COMPANYNAME 
    APENTO
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$TokenFileOutPutDir = "C:\temp",
    [Parameter(Mandatory = $true)]
    [string]$TokenFileName = "token.txt"
)


# Add sites to Trusted Sites
If (!(Test-Path -Path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\microsoftonline.com\login'))
{
    New-Item -Path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\microsoftonline.com' -ErrorAction SilentlyContinue
    New-Item -Path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\microsoftonline.com\login'
    New-ItemProperty -Path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\microsoftonline.com\login' -Name 'https' -Value '1' -PropertyType 'Dword' -Verbose
}

If (!(Test-Path -Path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\aadcdn'))
{
    New-Item -Path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net' -ErrorAction SilentlyContinue
    New-Item -Path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\aadcdn'
    New-ItemProperty -Path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\aadcdn' -Name 'https' -Value '1' -PropertyType 'Dword'
}

# Create authentication token
# Loading DLLs

Find-PackageProvider -Name NuGet| Install-PackageProvider -Force
Register-PackageSource -Name nuget.org -Location https://www.nuget.org/api/v2 -ProviderName NuGet -Force
Install-Package Microsoft.IdentityModel.Abstractions  -ProviderName Nuget -RequiredVersion 6.22.0.0 -Force
Install-Module Microsoft.Identity.Client -Force

add-type -path "C:\Program Files\PackageManagement\NuGet\Packages\Microsoft.IdentityModel.Abstractions.6.22.0\lib\net461\Microsoft.IdentityModel.Abstractions.dll"
add-type -path "C:\Program Files\WindowsPowerShell\Modules\Microsoft.Identity.Client\4.53.0\Microsoft.Identity.Client.dll"

# The AAD authentication endpoint uri
$authority = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"

#The application ID of the connector in AAD
$connectorAppId = "55747057-9b5d-4bd4-b387-abf52a8bd489";

#The AppIdUri of the registration service in AAD
$registrationServiceAppIdUri = "https://proxy.cloudwebappproxy.net/registerapp/user_impersonation"

# Define the resources and scopes you want to call
$scopes = New-Object System.Collections.ObjectModel.Collection["string"]
$scopes.Add($registrationServiceAppIdUri)
$app = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($connectorAppId).WithAuthority($authority).WithDefaultRedirectUri().Build()

[Microsoft.Identity.Client.IAccount] $account = $null

# Acquiring the token
$authResult = $null
$authResult = $app.AcquireTokenInteractive($scopes).WithAccount($account).ExecuteAsync().ConfigureAwait($false).GetAwaiter().GetResult()

# Check AuthN result
If (($authResult) -and ($authResult.AccessToken) -and ($authResult.TenantId)) {

$token = $authResult.AccessToken
   $tenantId = $authResult.TenantId

Write-Output "Success: Authentication result returned."
}
Else
{
    Write-Output "Error: Authentication result, token or tenant id returned with null."
}

$Token | Out-File $($TokenFileOutPutDir+"\"+$TokenFileName) -Force