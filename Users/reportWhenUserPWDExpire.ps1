get-adforest | select -ExpandProperty domains -pv domain | foreach{
    Get-ADUser -filter * –Properties DisplayName,PasswordLastSet,PasswordExpired, "msDS-UserPasswordExpiryTimeComputed" -Server $domain | `
    Select-Object -Property @{Name="Domain";Expression={$domain}},samaccountname,PasswordExpired,PasswordLastSet,`
        @{Name="pwdLastSet";Expression={if($_.PwdLastSet -ne 0){([datetime]::FromFileTime($_.pwdLastSet).ToString('MM/dd/yyyy'))}}},
        @{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}
} | export-csv .\ad_user_when_password_change.csv -NoTypeInformation
