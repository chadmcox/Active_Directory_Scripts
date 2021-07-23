function collectADContainers{
    get-adforest | select -ExpandProperty domains -PipelineVariable domain | foreach{
        Get-ADOrganizationalUnit -filter * -properties "msds-approx-immed-subordinates" -server $domain -PipelineVariable ou | `
            where {$_."msds-approx-immed-subordinates" -ne 0} | select distinguishedname, `
                @{Name="domain";Expression={$domain}}
            get-adobject -ldapfilter "(objectclass=Container)" -SearchScope OneLevel -server $domain | select distinguishedname, `
                @{Name="domain";Expression={$domain}}}
}

function collectADUsers{
   
    $properties = "msDS-AssignedAuthNPolicySilo","msDS-AssignedAuthNPolicy","Trustedfordelegation","TrustedToAuthForDelegation", `
    "samaccountname","mailNickname","thumbnailPhoto","DisplayName","mail",'msRTCSIP-PrimaryUserAddress',"servicePrincipalName", `
    "UserPrincipalName","description","extensionAttribute7","manager","lastLogonTimestamp","whenchanged","extensionAttribute2", `
    "extensionAttribute1","enabled","AccountExpirationDate","UserAccountControl","PwdLastSet","msExchHomeServerName", `
    "msExchRecipientDisplayType","msExchUMEnabledFlags2","msExchRecipientTypeDetails",'msRTCSIP-UserEnabled','msRTCSIP-OptionFlags','msRTCSIP-Line', `
    "telephoneNumber","extensionAttribute3","extensionAttribute4","c","co","countryCode","extensionAttribute5","extensionAttribute6","physicalDeliveryOfficeName", `
    "extensionAttribute12","title","extensionAttribute11","extensionAttribute13","extensionAttribute8","WhenCreated","CanonicalName", `
    "DistinguishedName","PrimaryGroupID","admincount","sidhistory","PasswordExpired","iscriticalsystemobject","msds-keycredentiallink"
    
    foreach($sb in $searchbases){
        write-host "Scanning $($sb.distinguishedname)"
        try{get-aduser -filter * -Properties $properties -searchbase $sb.DistinguishedName -SearchScope OneLevel -server $sb.domain  | select $selectproperties}
            catch{}
    }
    

}
function reportADUsers{
    $WH4BProvisioned = @{N="WH4BProvisioned";e={if($_."msds-keycredentiallink"){$true}else{$false}}}
    $sidhistory = @{N="sidHistory";e={if($_.sidhistory){$True}else{$False}}}
    $PasswordNotRequired = @{n='UACPasswordNotRequired';e={$(if($_.UserAccountControl -band 32){$True}else{$false})}}
    $AccountNotDelegated = @{n='UACAccountNotDelegated';e={$(if($_.UserAccountControl -band 1048576){$True}else{$false})}}
    $DoesNotRequirePreAuth = @{n='UACDoesNotRequirePreAuth';e={$(if($_.UserAccountControl -band 4194304){$True}else{$false})}}
    $SmartCardRequired = @{n='UACSmartCardRequired';e={$(if($_.UserAccountControl -band 262144){$True}else{$false})}}
    $CannotChangePassword = @{n='UACCannotChangePassword';e={$(if($_.UserAccountControl -band 64){$True}else{$false})}}
    $UseDesKeyOnly = @{n='UACUseDesKeyOnly';e={$(if($_.UserAccountControl -band 2097152){$True}else{$false})}}
    $ReversibleEncryption = @{n='UACReversibleEncryption';e={if($_.UserAccountControl -band 128){$True}else{$False}}}
    $OU = @{n='OU';e={($_.CanonicalName -split '/')[0..(($_.CanonicalName -split '/').Count – 2)] -join '/'}}
    $PwdLastSet = @{N="PwdLastSet";e={if($_.PwdLastSet -ne 0){(Get-Date([datetime]::FromFileTime($_.PwdLastSet))).ToString('MM/dd/yyyy')}else{"Never"}}}
    $PwdAge = @{N="PwdAge";e={if($_.PwdLastSet -ne 0){(new-TimeSpan([datetime]::FromFileTimeUTC($_.PwdLastSet)) $(Get-Date)).days}else{"NA"}}}
    $PasswordChangeonNextLogon = @{N="PasswordChangeonNextLogon";e={if($_.pwdLastSet -eq 0){$True}else{$false}}}
    $LastLogonTimeStamp = @{N="LastLogonTimeStamp";e={if($_.LastLogonTimeStamp){(Get-Date([datetime]::FromFileTime($_.LastLogonTimeStamp))).ToString('MM/dd/yyyy')}Else{"Never"}}}
    $DoesPasswordExpire = @{n='UACDoesPasswordExpire';e={$(if($_.UserAccountControl -band 65536){$false}else{$true})}}
    $Description = @{n='Description';e={($_).description -replace '[^a-zA-Z0-9\s]', ''}}
    $thumbnailPhotoSize = @{N="thumbnailPhotoSize";e={[math]::round((($_.thumbnailPhoto.count)/1.33)/1kb,2)}}
    $WhenCreated = @{n='WhenCreated';e={(Get-Date($_.WhenCreated)).ToString('MM/dd/yyyy')}}
    $WhenChanged = @{n='WhenChanged';e={(Get-Date($_.WhenChanged)).ToString('MM/dd/yyyy')}}
    $spn = @{N="SPN";e={if($_.servicePrincipalName){$True}else{$False}}}
    
    collectADUsers | select domain, "msDS-AssignedAuthNPolicySilo","msDS-AssignedAuthNPolicy","Trustedfordelegation","TrustedToAuthForDelegation", `
    "samaccountname",$thumbnailPhotoSize,"DisplayName","mail",$spn, "UserPrincipalName",$Description,"manager", `
    "$LastLogonTimeStamp",$WhenChanged, "enabled","AccountExpirationDate",$PwdLastSet,$PwdAge, "telephoneNumber","c","co","countryCode","physicalDeliveryOfficeName", `
    "title",$WhenCreated,$OU, "DistinguishedName","PrimaryGroupID","admincount",$sidhistory,"PasswordExpired","iscriticalsystemobject", `
    $WH4BProvisioned, $DoesPasswordExpire,$PasswordChangeonNextLogon,$ReversibleEncryption,$UseDesKeyOnly,$CannotChangePassword, `
    $SmartCardRequired,$DoesNotRequirePreAuth,$AccountNotDelegated,$PasswordNotRequired, extensionAttribute*,  msExch*, msRTCSIP*

}

$searchbases = collectADContainers
reportADUsers | export-csv ".\$((get-adforest).name)_adusers.csv" -NoTypeInformation
