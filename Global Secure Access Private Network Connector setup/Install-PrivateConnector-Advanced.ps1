
param (
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$RegisterConnector
)

# Global Secure Access app registration information
$TenantID = ""
$ConnecterInstallPath = "$PSScriptRoot\MicrosoftEntraPrivateNetworkConnectorInstaller.exe"
$User = ""
$UserPwd = ""

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [String]$Message,
        [Parameter(Mandatory = $true)]
        [String]$LogFilePath,
        [Parameter(Mandatory = $true)]
        [String]$LogType,
        [Parameter(Mandatory = $false)]
        [switch]$DebugEnabled = $false
    )
    $Date = Get-Date
    $Message = "$Date - [$LogType] $Message"
    Add-Content -Path $LogFilePath -Value $Message
    if ($DebugEnabled) {
        If ($LogType -eq "Error") {
            write-host $Message -ForegroundColor Red
        }
        elseif ($LogType -eq "Warning") {
            write-host $Message -ForegroundColor Yellow
        }
        else {
            write-host $Message
        }
    }
}
function Configure-PreReqs
{
    $ScriptLogFileName = "Configure-PrivateConnectorPrereqs"+"-"+"$(Get-Date -Format hhmmss-ddMMyyyy)"+".log"
    try 
    {
        # Disable Winhttp HTTP2
        $Regkey1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\"
        $Regname1 = "EnableDefaultHTTP2"
        $Regvalue1 = "0"

            # Configure TLS 1.2 client
            $Regkey2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
            $Regname2 = "Enabled"
            $Regvalue2 = "1"
            $Regtype2 = "Dword"
            $Regname3 = "DisabledByDefault"
            $Regvalue3 = "0"
            $Regtype3 = "Dword"

                # Configure TLS 1.2 server
                $Regkey3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
                $Regname4 = "Enabled"
                $Regvalue4 = "1"
                $Regtype4 = "Dword"
                $Regname5 = "DisabledByDefault"
                $Regvalue5 = "0"
                $Regtype5 = "Dword"

                    # Configure TLS 1.2 .NET Framework 4.x
                    $Regkey4 = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
                    $Regname6 = "SystemDefaultTlsVersions"
                    $Regvalue6 = "1"
                    $Regtype6 = "Dword"
                    $Regname7 = "SchUseStrongCrypto"
                    $Regvalue7 = "1"
                    $Regtype7 = "Dword"

        Write-Log -Message "Configuring Microsoft Entra private network connector prerequisites" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
        Write-Log -Message "Disable Winhttp HTTP2" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
        Write-Log -Message "Registry key: $Regkey1" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
        Write-Log -Message "Registry name: $Regname1" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
        Write-Log -Message "Registry value: $Regvalue1" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
        Set-ItemProperty $Regkey1 -Name $Regname1 -Value $Regvalue1

            Write-Log -Message "Configure TLS 1.2 client" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            Write-Log -Message "Registry key: $Regkey2" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            Write-Log -Message "Registry name: $Regname2" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            Write-Log -Message "Registry value: $Regvalue2" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            Write-Log -Message "Registry value type: $Regtype2" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            Write-Log -Message "Registry name: $Regname3" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            Write-Log -Message "Registry value: $Regvalue3" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            Write-Log -Message "Registry value type: $Regtype3" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            If (!(Test-Path "$Regkey2"))
            {
                New-Item "$Regkey2" -Force | Out-Null
            }
            New-ItemProperty -Path "$Regkey2" -Name $Regname2 -Value "$Regvalue2" -PropertyType $Regtype2 -Force | Out-Null
            New-ItemProperty -Path "$Regkey2" -Name $Regname3 -Value "$Regvalue3" -PropertyType $Regtype3 -Force | Out-Null


                Write-Log -Message "Configure TLS 1.2 server" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                Write-Log -Message "Registry key: $Regkey3" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                Write-Log -Message "Registry name: $Regname4" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                Write-Log -Message "Registry value: $Regvalue4" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                Write-Log -Message "Registry value type: $Regtype4" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                Write-Log -Message "Registry name: $Regname5" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                Write-Log -Message "Registry value: $Regvalue5" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                Write-Log -Message "Registry value type: $Regtype5" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                If (!(Test-Path "$Regkey3"))
                {
                    New-Item "$Regkey3" -Force | Out-Null
                }
                New-ItemProperty -Path "$Regkey3" -Name $Regname4 -Value $Regvalue4 -PropertyType $Regtype4 -Force | Out-Null
                New-ItemProperty -Path "$Regkey3" -Name $Regname5 -Value $Regvalue5 -PropertyType $Regtype5 -Force | Out-Null


                    Write-Log -Message "Configure TLS 1.2 .NET Framework 4.x" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                    Write-Log -Message "Registry key: $Regkey4" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                    Write-Log -Message "Registry name: $Regname6" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                    Write-Log -Message "Registry value: $Regvalue6" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                    Write-Log -Message "Registry value type: $Regtype6" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                    Write-Log -Message "Registry name: $Regname7" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                    Write-Log -Message "Registry value: $Regvalue7" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                    Write-Log -Message "Registry value type: $Regtype7" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                    If (!(Test-Path "$Regkey4"))
                    {
                        New-Item "$Regkey4" -Force | Out-Null
                    }
                    New-ItemProperty -Path "$Regkey4" -Name $Regname6 -Value $Regvalue6 -PropertyType $Regtype6 -Force | Out-Null
                    New-ItemProperty -Path "$Regkey4" -Name $Regname7 -Value $Regvalue7 -PropertyType $Regtype7 -Force | Out-Null
    
    Write-Log -Message "TLS 1.2 has been enabled. You must restart the Windows Server for the changes to take effect" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
    Write-Host 'TLS 1.2 has been enabled. You must restart the Windows Server for the changes to take effect.' -ForegroundColor Cyan        
    }
        catch 
        {
            Write-Log -Message "Error: $_" -LogType "Error" -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            Exit 1    
        }
}
function Install-GSAPNC
{
    $ScriptLogFileName = "Install-PrivateConnector"+"-"+"$(Get-Date -Format hhmmss-ddMMyyyy)"+".log"
    try
    {
        $LogFileName = "Microsoft Entra private network connector"+"-"+"install"+"-"+"$(Get-Date -Format hhmmss-ddMMyyyy)"+".log"
        If (Test-Path -Path "$PSScriptRoot\MicrosoftEntraPrivateNetworkConnectorInstaller.exe")
        {
            Write-Log -Message "Microsoft Entra private network connector setup file found in folder $PSScriptRoot" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
        }

            Write-Log -Message "Installing Microsoft Entra private network connector" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            Write-Host 'Installing Microsoft Entra private network connector' -ForegroundColor Cyan
            $Result = Start-Process -FilePath "$PSScriptRoot\MicrosoftEntraPrivateNetworkConnectorInstaller.exe" -ArgumentList "REGISTERCONNECTOR=`"false`" /install /quiet /log `"$env:windir\Logs\$LogFileName`"" -Wait -ErrorAction SilentlyContinue -PassThru
            If ($result.ExitCode -eq 0)
            {
                Write-Log -Message "Installation was successful" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            }
                else
                {
                    Write-Log -Message "Installation failed with exit code: $($result.ExitCode)" -LogType Error -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                    Write-Log -Message "Standard Out: $($result.StdOut)" -LogType Error -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                    Write-Log -Message "Standard Error: $($result.StdErr)" -LogType Error -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                }
    }
    catch
    {
        Write-Log -Message "Error: $_" -LogType "Error" -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
        Exit 1
    }
}
function Uninstall-GSAPNC
{
    $ScriptLogFileName = "Uninstall-PrivateConnector"+"-"+"$(Get-Date -Format hhmmss-ddMMyyyy)"+".log"
    try 
    {        
        $AppName = "Microsoft Entra private network connector"
        $Uninstall = Get-ChildItem "HKLM:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" | foreach {Get-ItemProperty $_.PSPath } | ? { $_ -match "$AppName" }        
        If ([string]::IsNullOrEmpty($Uninstall))
        {
            Write-Log -Message "$AppName not installed" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
        }
        else
        {
            $UninstallExe = $Uninstall.BundleCachePath
            $LogFileName = $AppName+"-"+"uninstall"+"-"+"$(Get-Date -Format hhmmss-ddMMyyyy)"+".log"
            Write-Log -Message "Uninstalling $AppName" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            Write-Host "Uninstalling $AppName" -ForegroundColor Cyan
            $Result = Start-Process -FilePath "$PSScriptRoot\MicrosoftEntraPrivateNetworkConnectorInstaller.exe" -ArgumentList "/uninstall /quiet /log `"$env:windir\Logs\$LogFileName`"" -Wait -ErrorAction SilentlyContinue -PassThru
            If ($result.ExitCode -eq 0)
            {
                Write-Log -Message "Uninstallation was successful" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            }
                else
                {
                    Write-Log -Message "Uninstallation failed with exit code: $($result.ExitCode)" -LogType Error -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                    Write-Log -Message "Standard Out: $($result.StdOut)" -LogType Error -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                    Write-Log -Message "Standard Error: $($result.StdErr)" -LogType Error -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
                }
        }
    }
    catch 
    {
        Write-Log -Message "Error: $_" -LogType "Error" -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
        Exit 1
    }
}
function Register-GSAPNC
{
    param(
        [Parameter(Mandatory = $true)]
        $Username,
        [Parameter(Mandatory = $true)]
        $Password

    )
    $ScriptLogFileName = "Register-PrivateConnector"+"-"+"$(Get-Date -Format hhmmss-ddMMyyyy)"+".log"
    try
    {
        Write-Log -Message "Installing NuGet package provider" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
        Write-Host "Installing NuGet package provider" -ForegroundColor Cyan
        Find-PackageProvider -Name NuGet -Force

            If (Get-PackageProvider -Name "NuGet")
            {
                Write-Log -Message "NuGet package provider succesfully installed" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"    
            }
            Write-Log -Message "Installing Microsoft Identity Model package and Powershell module" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            Install-Package Microsoft.IdentityModel.Abstractions -ProviderName Nuget -RequiredVersion 6.22.0.0 -Force
            If (Get-Package -Name Microsoft.IdentityModel.Abstractions)
            {
                Write-Log -Message "Microsoft.IdentityModel.Abstractions package succesfully installed" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"    
            }
            #Install-Module Microsoft.Identity.Client
            Install-Package -Name Microsoft.Identity.Client -ProviderName NuGet
            If (Get-Package -Name Microsoft.Identity.Client)
            {
                Write-Log -Message "Microsoft.Identity.Client package succesfully installed" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"    
            }

            # The AAD authentication endpoint uri
            $authority =  "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
            Write-Log -Message "Authority Uri: $authority" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"

            #The application ID of the connector in AAD
            $connectorAppId = "55747057-9b5d-4bd4-b387-abf52a8bd489";
            Write-Log -Message "Connector application ID: $connectorAppId" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"

            #The AppIdUri of the registration service in AAD
            $registrationServiceAppIdUri = "https://proxy.cloudwebappproxy.net/registerapp/user_impersonation"
            Write-Log -Message "Entra ID registration service AppIdUri : $registrationServiceAppIdUri" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"

            # Define the resources and scopes you want to call
            $scopes = New-Object System.Collections.ObjectModel.Collection["string"]
            $scopes.Add($registrationServiceAppIdUri)
            $app = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($connectorAppId).WithAuthority($authority).WithDefaultRedirectUri().Build()
            [Microsoft.Identity.Client.IAccount] $account = $null
            Write-Log -Message "Scopes: $scopes " -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"

            # Acquiring the token
            Write-Log -Message "Acquiring authentication token" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            $authResult = $null
            # $authResult = $app.AcquireTokenInteractive($scopes).WithAccount($account).ExecuteAsync().ConfigureAwait($false).GetAwaiter().GetResult()
            $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
            $authResult = $app.AcquireTokenByUsernamePassword($scopes, $Username, $SecurePassword).ExecuteAsync().ConfigureAwait($false).GetAwaiter().GetResult()

            # Check AuthN result
            If (($authResult) -and ($authResult.AccessToken) -and ($authResult.TenantId)) 
            {
            $token = $authResult.AccessToken
            $tenantId = $authResult.TenantId
            Write-Log -Message "Authentication token acquired!" -LogType Info -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            }
            else {
                Write-Log -Message "Authentication result, token or tenant id returned with null" -LogType Error -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
            }

                # Create secure token string
                $token = ConvertTo-SecureString $authResult.AccessToken -AsPlainText -Force
                #$SecureToken = $Token.Access_Token | ConvertTo-SecureString -AsPlainText -Force
                & "C:\Program Files\Microsoft Entra private network connector\RegisterConnector.ps1" -modulePath "C:\Program Files\Microsoft Entra private network connector\Modules\" -moduleName "MicrosoftEntraPrivateNetworkConnectorPSModule" -Authenticationmode Token -Token $Token -TenantId $TenantID -Feature ApplicationProxy
    }
    catch
    {
        Write-Log -Message "Error: $_" -LogType "Error" -LogFilePath "$env:windir\Logs\$ScriptLogFileName"
        Exit 1
    }
}

If ($Install)
{
    Configure-PreReqs
    Install-GSAPNC
}

If ($Uninstall)
{
    Uninstall-GSAPNC
}

If ($RegisterConnector)
{
    Register-GSAPNC -UserName $User -Password $UserPwd
    <#
    # Silently register Private Network Connector in Entra ID
    # Loading DLLs
    Find-PackageProvider -Name NuGet -Force
    #Register-PackageSource -Name nuget.org -Location https://www.nuget.org/api/v2 -ProviderName NuGet
    #Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

    #Get-PackageProvider | where name -eq 'nuget' | Install-PackageProvider -Force
    Install-Package Microsoft.IdentityModel.Abstractions -ProviderName Nuget -RequiredVersion 6.22.0.0 -Force 
    Install-Module Microsoft.Identity.Client

    add-type -path "C:\Program Files\PackageManagement\NuGet\Packages\Microsoft.IdentityModel.Abstractions.6.22.0\lib\net461\Microsoft.IdentityModel.Abstractions.dll"
    add-type -path "C:\Program Files\WindowsPowerShell\Modules\Microsoft.Identity.Client\4.53.0\Microsoft.Identity.Client.dll"

    # The AAD authentication endpoint uri
    # $authority = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"

    $authority =  "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"

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
    # $authResult = $app.AcquireTokenInteractive($scopes).WithAccount($account).ExecuteAsync().ConfigureAwait($false).GetAwaiter().GetResult()
    $password = ConvertTo-SecureString $UserPwd -AsPlainText -Force
    $authResult = $app.AcquireTokenByUsernamePassword($scopes, $User, $password).ExecuteAsync().ConfigureAwait($false).GetAwaiter().GetResult()

    # Check AuthN result
    If (($authResult) -and ($authResult.AccessToken) -and ($authResult.TenantId)) 
    {
    $token = $authResult.AccessToken
    $tenantId = $authResult.TenantId

    Write-Output "Success: Authentication result returned."
    }
    else {
        Write-Output "Error: Authentication result, token or tenant id returned with null."
    }

    $token = ConvertTo-SecureString $authResult.AccessToken -AsPlainText -Force

    # Create secure token string
    #$SecureToken = $Token.Access_Token | ConvertTo-SecureString -AsPlainText -Force
    & "C:\Program Files\Microsoft Entra private network connector\RegisterConnector.ps1" -modulePath "C:\Program Files\Microsoft Entra private network connector\Modules\" -moduleName "MicrosoftEntraPrivateNetworkConnectorPSModule" -Authenticationmode Token -Token $Token -TenantId $TenantID -Feature ApplicationProxy
    #>
}

<#
# Silently register Private Network Connector in Entra ID
# Loading DLLs
Find-PackageProvider -Name NuGet -Force
#Register-PackageSource -Name nuget.org -Location https://www.nuget.org/api/v2 -ProviderName NuGet
#Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

#Get-PackageProvider | where name -eq 'nuget' | Install-PackageProvider -Force
Install-Package Microsoft.IdentityModel.Abstractions -ProviderName Nuget -RequiredVersion 6.22.0.0 -Force 
Install-Module Microsoft.Identity.Client

add-type -path "C:\Program Files\PackageManagement\NuGet\Packages\Microsoft.IdentityModel.Abstractions.6.22.0\lib\net461\Microsoft.IdentityModel.Abstractions.dll"
add-type -path "C:\Program Files\WindowsPowerShell\Modules\Microsoft.Identity.Client\4.53.0\Microsoft.Identity.Client.dll"

# The AAD authentication endpoint uri
# $authority = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"

$authority =  "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"

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
# $authResult = $app.AcquireTokenInteractive($scopes).WithAccount($account).ExecuteAsync().ConfigureAwait($false).GetAwaiter().GetResult()
$password = ConvertTo-SecureString $UserPwd -AsPlainText -Force
$authResult = $app.AcquireTokenByUsernamePassword($scopes, $User, $password).ExecuteAsync().ConfigureAwait($false).GetAwaiter().GetResult()

# Check AuthN result
If (($authResult) -and ($authResult.AccessToken) -and ($authResult.TenantId)) 
{
$token = $authResult.AccessToken
   $tenantId = $authResult.TenantId

Write-Output "Success: Authentication result returned."
}
else {
    Write-Output "Error: Authentication result, token or tenant id returned with null."
}

$token = ConvertTo-SecureString $authResult.AccessToken -AsPlainText -Force

# Create secure token string
#$SecureToken = $Token.Access_Token | ConvertTo-SecureString -AsPlainText -Force
& "C:\Program Files\Microsoft Entra private network connector\RegisterConnector.ps1" -modulePath "C:\Program Files\Microsoft Entra private network connector\Modules\" -moduleName "MicrosoftEntraPrivateNetworkConnectorPSModule" -Authenticationmode Token -Token $Token -TenantId $TenantID -Feature ApplicationProxy

#>