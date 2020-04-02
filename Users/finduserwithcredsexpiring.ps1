#this commandlet will display users who's password's will start expiring over the next 60 days, good when the max password age is 90, and wanting to see how many users will be changing passwords.
$date = (Get-Date).Adddays(-30).ToFileTimeUTC() 
get-aduser -Filter {(pwdlastset -lt $date) -and (pwdlastset -ne 0)} -Properties pwdlastset,Enabled,PasswordNeverExpires | select samaccountname, @{N="pwdLastSet";
    E={if($_.PwdLastSet -ne 0){([datetime]::FromFileTime($_.pwdLastSet).ToString('MM/dd/yyyy'))}}},Enabled,PasswordNeverExpires | where {($_.enabled -eq $true) -and ($_.PasswordNeverExpires -eq $false)} | out-gridview 
