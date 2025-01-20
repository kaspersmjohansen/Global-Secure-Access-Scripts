
# Define CIM object variables
# This is needed for accessing the non-default trigger settings when creating a schedule task using Powershell
$Class = cimclass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler
$Trigger = $class | New-CimInstance -ClientOnly
$Trigger.Enabled = $true
$Trigger.Subscription = "<QueryList><Query Id=`"0`" Path=`"Microsoft-Windows-NetworkProfile/Operational`"><Select Path=`"Microsoft-Windows-NetworkProfile/Operational`">*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and EventID=4004]]</Select></Query></QueryList>"

# Find Builtin\Users name on localized Windows
# Well known SIDs are found here - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#well-known-sids
$GroupName = Get-LocalGroup -SID "S-1-5-32-545"

# Define additional variables containing scheduled task action and scheduled task principal
$A = New-ScheduledTaskAction -Execute powershell.exe -Argument "-executionpolicy bypass -WindowStyle Hidden -file C:\ProgramData\GSAscripts\Detect-CorpNetwork.ps1"
$P = New-ScheduledTaskPrincipal -GroupId $GroupName -RunLevel Limited
$S = New-ScheduledTaskSettingsSet -Compatibility Win8 -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries -DontStopOnIdleEnd

# Cook it all up and create the scheduled task
$RegSchTaskParameters = @{
    TaskName    = "Global Secure Access - Detect network state"
    Description = "Powershell script executed on event id 4004, to detect if the device is on the corporate network. GSA Private Access is disabled if the device is on the corporate network"
    TaskPath    = "\"
    Action      = $A
    Principal   = $P
    Settings    = $S
    Trigger     = $Trigger
}

Register-ScheduledTask @RegSchTaskParameters