$trigger = New-JobTrigger -Weekly -DaysOfWeek Monday,Tuesday,Wednesday,Thursday,Friday -At "13:00"
$option = New-ScheduledJobOption -RunElevated

$credential = Get-Credential 

Register-ScheduledJob `
–Name "Random Group Membership" `
–Trigger $trigger `
–ScheduledJobOption $option `
-Credential $credential `
–ScriptBlock {
import-module activedirectory

$groups = get-adgroup -filter * -searchbase "OU=Groups,DC=contoso,DC=com"
1..100 | foreach{
    $group = ($groups | get-random)
    $user = Get-ADGroupMember $group | where objectclass -eq "user" | get-random
    $group | Remove-ADGroupMember -Members $user.distinguishedName -confirm:$false
}
$users = get-aduser -filter * -SearchBase "OU=User Accounts,DC=contoso,DC=com" -properties * | where {!($_.admincount -eq 1)}
1..100 | foreach{
    $group = ($groups | get-random)
    $group | Add-ADGroupMember -Members ($users | get-random).distinguishedName -confirm:$false
}
}
