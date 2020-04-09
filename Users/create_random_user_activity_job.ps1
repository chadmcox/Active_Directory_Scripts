
Register-ScheduledJob `
–Name "Randon User Activity" `
–Trigger $trigger `
–ScheduledJobOption $option `
-Credential $credential `
–ScriptBlock {
import-module activedirectory
$users = get-aduser -filter * -SearchBase "OU=User Accounts,DC=contoso,DC=com" -properties * | where {!($_.admincount -eq 1)}
#reset password
1..100 | foreach{
    Set-ADAccountPassword -Identity $($users | get-random) -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "Th1SistheGre@testpWd#v3r" -Force)
}
#try to change password
1..50 | foreach{
    Set-ADAccountPassword -Identity elisada -OldPassword (ConvertTo-SecureString -AsPlainText "Th1SistheGre@testpWd#v3r" -Force) -NewPassword (ConvertTo-SecureString -AsPlainText "N0tTh3Gr3atestPwd$v$r!" -Force)
}
#emulate Logon to set new lastlogondate s4su
1..1000 | foreach{
   New-Object System.Security.Principal.WindowsIdentity(($users | get-random).userprincipalname)
}
#simulate bad password attempts
$computers = get-adcomputer -filter * -properties IPv4Address | where {!($_.IPv4Address -eq $null)}
1..300 | foreach{
    $username = "contoso\$(($users | get-random).samaccountname)"
    $password = (ConvertTo-SecureString -AsPlainText "wfwefwer444" -Force)
    $Credentials = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $password
    invoke-command -computername ($computers | get-random).DNSHostName -Credential $Credentials -ScriptBlock {ipconfig}
}
}
