<#PSScriptInfo
.SYNOPSIS
    Script to create a scheduled task to execute a Powershell script
 
.DESCRIPTION
    This script will create a scheduled task which executes a Powershell script. The scheduled task is configured to run in user context using the built-in Users group.
    The group name is derived using the well known SID - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#well-known-sids
    This is to prevent issues with localized Users group names

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

# Script variables
$ScriptFileName = "Detect-CorpNetwork.ps1"
$ScriptFileLocation = "C:\ProgramData\GSAscripts"

$ScheduledTaskName = "Global Secure Access - Detect network state"
$ScheduledTaskDescription = "Powershell script executed on event id 4004, to detect if the device is on the corporate network. GSA Private Access is disabled if the device is on the corporate network"
$ScheduledTaskPath = "\"

# Define CIM object variables
# This is needed for accessing the non-default trigger settings when creating a schedule task using Powershell
$Class = cimclass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler
$Trigger = $class | New-CimInstance -ClientOnly
$Trigger.Enabled = $true
$Trigger.Subscription = "<QueryList><Query Id=`"0`" Path=`"Microsoft-Windows-NetworkProfile/Operational`"><Select Path=`"Microsoft-Windows-NetworkProfile/Operational`">*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and EventID=4004]]</Select></Query></QueryList>"

# Find Builtin\Users name on localized Windows

$GroupName = Get-LocalGroup -SID "S-1-5-32-545"

# Define additional variables containing scheduled task action and scheduled task principal
$A = New-ScheduledTaskAction -Execute powershell.exe -Argument "-executionpolicy bypass -WindowStyle Hidden -file `"$($ScriptFileLocation + "\" + $ScriptFileName)`""
$P = New-ScheduledTaskPrincipal -GroupId $GroupName -RunLevel Limited
$S = New-ScheduledTaskSettingsSet -Compatibility Win8 -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries -DontStopOnIdleEnd

# Cook it all up and create the scheduled task
$RegSchTaskParameters = @{
    TaskName    = $ScheduledTaskName
    Description = $ScheduledTaskDescription
    TaskPath    = $ScheduledTaskPath
    Action      = $A
    Principal   = $P
    Settings    = $S
    Trigger     = $Trigger
}

Register-ScheduledTask @RegSchTaskParameters