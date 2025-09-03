<#PSScriptInfo
.SYNOPSIS
    Script to register a Microsoft Entra Private Network Connector in Entra
 
.DESCRIPTION
    This script will register a Microsoft Entra Private Network Connector in Entra. 
    For the registration to be successfull, you must have a valid offline authentication token 
    and provide an Entra tenant ID.

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
    [string]$TokenFileName = "token.txt",
    [Parameter(Mandatory = $true)]
    $TenantID

)
# Variables
$Token = Get-Content -Path "$($TokenFileOutPutDir+"\"+$TokenFileName)"

# Register connecter in Entra ID
$SecureToken = $Token | ConvertTo-SecureString -AsPlainText -Force
& "C:\Program Files\Microsoft Entra private network connector\RegisterConnector.ps1" -modulePath "C:\Program Files\Microsoft Entra private network connector\Modules\" -moduleName "MicrosoftEntraPrivateNetworkConnectorPSModule" -Authenticationmode Token -Token $SecureToken -TenantId $TenantID -Feature ApplicationProxy