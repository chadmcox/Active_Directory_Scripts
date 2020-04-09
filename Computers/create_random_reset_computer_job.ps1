#this creates a scheduled job that runs and resets one computer account a day to increment the pwdlastset
#it will also set one random computer pwdlastset to 0
#provide a credential that has the rights to run this task

#this is ideal to test stale computer account clean up processes
#make sure to update the two filters in the get-adcomputer cmdlets

$trigger = New-JobTrigger -Weekly -DaysOfWeek Monday,Tuesday,Wednesday,Thursday,Friday -At "23:00"
$option = New-ScheduledJobOption -RunElevated

$credential = Get-Credential 

Register-ScheduledJob –Name "Reset Random Computer" –Trigger $trigger –ScheduledJobOption $option -Credential $credential `
–ScriptBlock {
import-module activedirectory
$computer = get-adcomputer -Filter {name -like "stale-computer*"} | get-random
dsmod computer $computer.distinguishedname -reset
$computer = get-adcomputer -Filter {name -like "stale-computer*"} | get-random
$computer.pwdlastset = 0
set-adcomputer -instance $computer
}
