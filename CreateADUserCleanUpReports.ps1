
<#PSScriptInfo

.VERSION 0.8

.GUID c7ffb7da-8352-4a04-9920-4eca7929fba9

.AUTHOR Chad.Cox@microsoft.com
    https://blogs.technet.microsoft.com/chadcox/
    https://github.com/chadmcox

.COMPANYNAME 

.COPYRIGHT This Sample Code is provided for the purpose of illustration only and is not
intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
nonexclusive, royalty-free right to use and modify the Sample Code and to
reproduce and distribute the object code form of the Sample Code, provided
that You agree: (i) to not use Our name, logo, or trademarks to market Your
software product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneys` fees, that arise or result
from the use or distribution of the Sample Code..

.TAGS AD Users

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
0.8 Search for objects in root level of domain
0.7
formatting and added iscritical system object exclusion to blankpwd function
0.6
ran into timeout issues in large domains, breaking up queries to be smaller more effiecent.
0.5
created null upn user report
error handling sends failed query to text file

0.1 First go around of the script

.PRIVATEDATA 

#>

#Requires -Module ActiveDirectory
#Requires -Version 4
<# 

.DESCRIPTION 
 Creates Useful Cleanup Reports for Active Directory Users.

#> 
Param($reportpath = "$env:userprofile\Documents",[switch]$dontrun,[switch]$skipfunctionlist)

$reportpath = "$reportpath\ADCleanUpReports"
If (!($(Try { Test-Path $reportpath } Catch { $true }))){
    new-Item $reportpath -ItemType "directory"  -force
}
$reportpath = "$reportpath\Users"
If (!($(Try { Test-Path $reportpath } Catch { $true }))){
    new-Item $reportpath -ItemType "directory"  -force
}

$default_err_log = $reportpath + '\err_log.txt'

#change current path to the report path
cd $reportpath

$domains = (get-adforest).domains

if($includetrust){
    $domains = ((get-adforest).domains | foreach {get-adtrust -filter * -server $_}).name | select -Unique
}
Function ADOUList{
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADOUList"
        $script:ou_list = "$reportpath\ADOUList.csv"
        Get-ChildItem $script:ou_list | Where-Object { $_.LastWriteTime -lt $((Get-Date).AddDays(-10))} | Remove-Item -force

        If (!(Test-Path $script:ou_list)){
            foreach($domain in (get-adforest).domains){
                try{Get-ADObject -ldapFilter "(|(objectclass=organizationalunit)(objectclass=domainDNS))" -server $domain | select `
                     $hash_domain, DistinguishedName  | export-csv $script:ou_list -append -NoTypeInformation}
                catch{"function ADOUList - $domain - $($_.Exception)" | out-file $default_err_log -append}
                try{(get-addomain $domain).UsersContainer | Get-ADObject -server $domain | select `
                     $hash_domain, DistinguishedName | export-csv $script:ou_list -append -NoTypeInformation}
                catch{"function ADOUList - $domain - $($_.Exception)" | out-file $default_err_log -append}
            }
        }

        $script:ous = import-csv $script:ou_list
    }
}
Function ADUsersWithSIDHistoryFromSameDomain{
    [cmdletbinding()]
    param()
    process{
        #https://adsecurity.org/?p=1772
        write-host "Starting Function ADUsersWithSIDHistoryFromSameDomain"
        $default_log = "$reportpath\report_ADUsersWithSIDHistoryFromSameDomain.csv"
        $results = @()
        #Find Users with sid history from same domain
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            [string]$Domain_SID = ((Get-ADDomain $domain).DomainSID.Value)
            try{$results += Get-ADUser -Filter {SIDHistory -Like '*'} `
                -Properties SIDHistory,admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged `
                -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                Where { $_.SIDHistory -Like "$domain_sid-*"} | `
                    select $hash_domain, samaccountname,admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUsersWithSIDHistoryFromSameDomain - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with sidhistory from the same domain."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview "
        }
    }
}
Function ADUsersWithDoNotRequireKerbPreauth{
    #users_do_not_require_kerb_preauth
    [cmdletbinding()]
    param()
    process{
        #DONT_REQ_PREAUTH  0x400000 4194304
        #This account does not require Kerberos pre-authentication for logging on.

        write-host "Starting Function ADUsersWithDoNotRequireKerbPreauth"
        $default_log = "$reportpath\report_ADUsersWithDoNotRequireKerbPreauth.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            try{$results += get-aduser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(IsCriticalSystemObject=TRUE)))"`
                -Properties admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged `
                -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUsersWithDoNotRequireKerbPreauth - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with account does not require Kerberos pre-authentication for logging on enabled."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview "
        }
    }
}
Function ADUsersWithStorePwdUsingReversibleEncryption{
    #users_store_pwd_using_reversible_encryption
    [cmdletbinding()]
    param()
    process{
        #ENCRYPTED_TEXT_PWD_ALLOWED 0x0080 128
        #The user can send an encrypted password.

        write-host "Starting Function ADUsersWithStorePwdUsingReversibleEncryption"
        $default_log = "$reportpath\report_ADUsersWithStorePwdUsingReversibleEncryption.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-aduser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=128)(!(IsCriticalSystemObject=TRUE)))"`
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,AllowReversiblePasswordEncryption,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,AllowReversiblePasswordEncryption,admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUsersWithStorePwdUsingReversibleEncryption - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with account Store Password Using Reversible Encryption enabled."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview "
        }
    }
}
Function ADUserswithUseDESKeyOnly{
    #users_use_kerberos_des_enabled
    [cmdletbinding()]
    param()
    process{
        #USE_DES_KEY_ONLY 2097152
        
        write-host "Starting Function ADUserswithUseDESKeyOnly"
        $default_log = "$reportpath\report_ADUserswithUseDESKeyOnly.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            try{$results += get-aduser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=2097152)(!(IsCriticalSystemObject=TRUE)))"`
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,UseDESKeyOnly,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,UseDESKeyOnly,admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUserswithUseDESKeyOnly - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with account Use DES Key Only enabled."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview "
        }
    }
}
Function ADUserswithUnConstrainedDelegationEnabled{
    #unconstrained_delegation_enabled
    [cmdletbinding()]
    param()
    process{
        #TRUSTED_FOR_DELEGATION
        
        write-host "Starting Function ADUserswithUnConstrainedDelegationEnabled"
        $default_log = "$reportpath\report_ADUserswithUnConstrainedDelegationEnabled.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            #Get-ADUser -Filter {UserAccountControl -band 524288}
            #Get-ADUser -Filter {Trustedfordelegation -eq $True}
            try{$results += get-aduser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(IsCriticalSystemObject=TRUE)))"`
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,Trustedfordelegation,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,Trustedfordelegation,admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUserswithUnConstrainedDelegationEnabled - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with trusted for delegation (unconstrained kerb delegation) enabled."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserswithPwdNotSet{
    #users_pwd_never_set
    [cmdletbinding()]
    param()
    process{
        
        write-host "Starting Function ADUserswithPwdNotSet"
        $default_log = "$reportpath\report_ADUserswithPwdNotSet.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            try{$results += Get-ADUser -Filter {(pwdlastset -eq 0) -and (iscriticalsystemobject -notlike "*")} `
                -Properties admincount,enabled,PasswordExpired,PasswordLastSet,Trustedfordelegation,whencreated,whenchanged `
                -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUserswithPwdNotSet - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with password not set."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserswithPwdNotRequired{
    #users_pwd_not_required
    #PASSWD_NOTREQD 0x0020 32
    [cmdletbinding()]
    param()
    process{
    write-host "Starting Function ADUserswithPwdNotRequired"
        $default_log = "$reportpath\report_ADUserswithPwdNotRequired.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            #Get-ADUser -Filter {UserAccountControl -band 32}
            #Get-ADUser -Filter {PasswordNotRequired -eq $True}
            try{$results += get-aduser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=32)(!(IsCriticalSystemObject=TRUE)))"`
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,PasswordNotRequired,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,PasswordNotRequired,admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged$hash_parentou}
            catch{"function ADUserswithPwdNotRequired - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with password not required."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserswithPwdNeverExpired{
    #users_pwd_never_expires
    #DONT_EXPIRE_PASSWORD 0x10000 65536
    [cmdletbinding()]
    param()
    process{

        write-host "Starting Function ADUserswithPwdNeverExpired"
        $default_log = "$reportpath\report_ADUserswithPwdNeverExpired.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            #Get-ADUser -Filter {UserAccountControl -band 65536}
            #get-aduser -filter {PasswordNeverExpires -eq $true}
            try{$results += get-aduser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(IsCriticalSystemObject=TRUE)))" `
                 -Properties admincount,enabled,PasswordNeverExpires,PasswordExpired,PasswordLastSet,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,PasswordNeverExpires,admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUserswithPwdNeverExpired - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with password never expired set."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserswithAdminCount{
    #users_with_admincount
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserswithAdminCount"
        $default_log = "$reportpath\report_ADUserswithAdminCount.csv"
        $results = @()
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-aduser -Filter {admincount -eq 1 -and iscriticalsystemobject -notlike "*"}`
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUserswithAdminCount - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with admincount set."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserswithAdminCountandEmailorSkypeEnabled{
    #users_with_admincount
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserswithAdminCountandEmailorSkypeEnabled"
        $default_log = "$reportpath\report_ADUserswithAdminCountandEmailorSkypeEnabled.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-aduser -filter {(proxyaddresses -like "*" -or msRTCSIP-PrimaryUserAddress -like "*") -and (admincount -eq 1 -and iscriticalsystemobject -notlike "*")} `
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUserswithAdminCountandEmailorSkypeEnabled - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with admincount set."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserswithStaleAdminCount{
    #users_with_admincount
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserswithStaleAdminCount"
        $orphan_log = "$reportpath\report_ADUserswithStaleAdminCount.csv"
        $default_log = "$reportpath\report_ADUsersMembersofPrivilegedGroups.csv"
        #users with stale admin count
        $results = @();$orphan_results = @();$non_orphan_results  = @()
        $flagged_users = foreach($domain in (get-adforest).domains)
            {get-aduser -filter 'admincount -eq 1 -and iscriticalsystemobject -notlike "*"' `
                    -server $domain `
                    -properties whenchanged,whencreated,admincount,isCriticalSystemObject,"msDS-ReplAttributeMetaData",samaccountname |`
                select @{name='Domain';expression={$domain}},distinguishedname,whenchanged,whencreated,admincount,`
                    SamAccountName,objectclass,isCriticalSystemObject,@{name='adminCountDate';expression={($_ | `
                        Select-Object -ExpandProperty "msDS-ReplAttributeMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_ATTR_META_DATA |`
                        where { $_.pszAttributeName -eq "admincount"}}).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}}}
        $default_admin_groups = foreach($domain in (get-adforest).domains){get-adgroup -filter 'admincount -eq 1 -and iscriticalsystemobject -like "*"'`
                    -server $domain | select @{name='Domain';expression={$domain}},distinguishedname}
        foreach($user in $flagged_users){
            $udn = ($user).distinguishedname
            $results = foreach($group in $default_admin_groups){
                $user | select `
                    @{Name="Group_Domain";Expression={$group.domain}},`
                    @{Name="Group_Distinguishedname";Expression={$group.distinguishedname}},`
                    @{Name="Member";Expression={if(Get-ADgroup -Filter {member -RecursiveMatch $udn} -searchbase $group.distinguishedname -server $group.domain){$True}else{$False}}},`
                    domain,distinguishedname,admincount,adminCountDate,whencreated,objectclass
            }
            if($results | where {$_.member -eq $True}){
                $non_orphan_results += $results | where {$_.member -eq $True}
            }else{
                #$results | select Domain,objectclass,admincount,adminCountDate,distinguishedname | get-unique
                $orphan_results += $results  | select Domain,objectclass,admincount,adminCountDate,distinguishedname | get-unique
            }
        }
        $non_orphan_results  | export-csv $default_log -NoTypeInformation
        $orphan_results | export-csv $orphan_log -NoTypeInformation
        if($orphan_results){
            write-host "Found $(($orphan_results | measure).count) user object that are no longer a member of a priviledged group but still has admincount attribute set to 1"
            write-host "and inheritance disabled."
            write-host -foregroundcolor yellow "To view results run: import-csv $orphan_log | out-gridview"
        }
    }
}
Function ADUserswithAdminCountnotMemberofProtectedUsersGroup{
    #users_with_admincount
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserswithAdminCountnotMemberofProtectedUsersGroup"
        $default_log = "$reportpath\report_ADUserswithAdminCountnotMemberofProtectedUsersGroup.csv"
        #users with stale admin count
        $results = @();$not_protected_results = @();
        $flagged_users = foreach($domain in (get-adforest).domains)
            {get-aduser -filter 'admincount -eq 1 -and iscriticalsystemobject -notlike "*"' `
                    -server $domain `
                    -properties whenchanged,whencreated,admincount,isCriticalSystemObject,"msDS-ReplAttributeMetaData",samaccountname |`
                select @{name='Domain';expression={$domain}},distinguishedname,whenchanged,whencreated,admincount,`
                    SamAccountName,objectclass,isCriticalSystemObject,@{name='adminCountDate';expression={($_ | `
                        Select-Object -ExpandProperty "msDS-ReplAttributeMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_ATTR_META_DATA |`
                        where { $_.pszAttributeName -eq "admincount"}}).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}}}
        $protected_users_groups = foreach($domain in (get-adforest).domains){get-adgroup "Protected Users"`
                    -server $domain | select @{name='Domain';expression={$domain}},distinguishedname}
        foreach($user in $flagged_users){
            $udn = ($user).distinguishedname
            $results = foreach($group in $default_admin_groups){
                $user | select `
                    @{Name="Group_Domain";Expression={$group.domain}},`
                    @{Name="Group_Distinguishedname";Expression={$group.distinguishedname}},`
                    @{Name="Member";Expression={if(Get-ADgroup -Filter {member -RecursiveMatch $udn} -searchbase $group.distinguishedname -server $group.domain){$True}else{$False}}},`
                    domain,SamAccountName,distinguishedname,admincount,adminCountDate,whencreated,objectclass
            }
            if($results | where {$_.member -eq $True}){
                
            }else{
                $results | select Domain,objectclass,admincount,adminCountDate,distinguishedname | get-unique
                $not_protected_results += $results  | select Domain,SamAccountName,objectclass,admincount,adminCountDate,distinguishedname | get-unique
            }
        }
        
        $not_protected_results | export-csv $default_log -NoTypeInformation
        if($not_protected_results){
            write-host "Found $(($not_protected_results | measure).count) privileged user objects not in the protected users group."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserswithStalePWDAgeAndLastLogon{
    #stale Users
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserswithStalePWDAgeAndLastLogon"
        $default_log = "$reportpath\report_ADUserswithStalePWDAgeAndLastLogon.csv"
        $results = @()
        $DaysInactive = 90 
        $threshold_time = (Get-Date).Adddays(-($DaysInactive)).ToFileTimeUTC() 
        $create_time = (Get-Date).Adddays(-($DaysInactive))

        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            try{$results += get-aduser -Filter {(LastLogonTimeStamp -lt $threshold_time -or LastLogonTimeStamp -notlike "*") -and (pwdlastset -lt $threshold_time -or pwdlastset -eq 0) -and (enabled -eq $true) -and (iscriticalsystemobject -notlike "*") -and (whencreated -lt $create_time)}`
                    -Properties admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged,LastLogonDate,PasswordNeverExpires,CannotChangePassword,SmartcardLogonRequired `
                    -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled,PasswordExpired,PasswordNeverExpires,CannotChangePassword,`
                        SmartcardLogonRequired,PasswordLastSet,LastLogonDate,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUserswithStalePWDAgeAndLastLogon - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with passwords or lastlogon time stamps `
                greater than $DaysInactive days. Most of these objects can be considered stale."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserswithNonStandardPrimaryGroup{
#users_default_primary_group_membership_not_standard
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserswithNonStandardPrimaryGroup"
        $default_log = "$reportpath\report_ADUserswithNonStandardPrimaryGroup.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-aduser -Filter {primaryGroupID -ne 513 -and iscriticalsystemobject -notlike "*"}`
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,primaryGroupID,primaryGroup,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled,PasswordExpired,PasswordLastSet,primaryGroupID,primaryGroup,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUserswithNonStandardPrimaryGroup - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with Primary Group other than Domain Users (513)."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserswithAdminCountAndSPN{
#users_with_admincount_and_spn
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserswithAdminCountandSPN"
        $default_log = "$reportpath\report_ADUserswithAdminCountandSPN.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-aduser -Filter {admincount -eq 1 -and iscriticalsystemobject -notlike "*" -and servicePrincipalName -like '*'}`
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUserswithAdminCountandSPN - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with admincount set and serviceprincipalnames defined."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserswithAdminCountandUnConstrainedDelegation{
    #users_with_admincount_and_unconstrained_delegation_enabled
    [cmdletbinding()]
    param()
    process{
        #TRUSTED_FOR_DELEGATION
        
        write-host "Starting Function ADUserswithAdminCountandUnConstrainedDelegation"
        $default_log = "$reportpath\report_ADUserswithAdminCountandUnConstrainedDelegation.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            #Get-ADUser -Filter {UserAccountControl -band 524288}
            #Get-ADUser -Filter {Trustedfordelegation -eq $True}
            try{$results += get-aduser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(IsCriticalSystemObject=TRUE))(AdminCount=1))"`
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,Trustedfordelegation,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,Trustedfordelegation,admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUserswithAdminCountandUnConstrainedDelegation - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with trusted for delegation (unconstrained kerb delegation) enabled and could have privilaged access (admincount set)."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserwithAdminCountandNotProtected{
#admincount_and_account_is_sensitive_cannot_be_delegate_not_set
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserwithAdminCountandNotProtected"
        $default_log = "$reportpath\report_ADUserwithAdminCountandNotProtected.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-aduser -Filter {admincount -eq 1 -and iscriticalsystemobject -notlike "*" -and AccountNotDelegated -eq $false}`
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,AccountNotDelegated,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled,PasswordExpired,PasswordLastSet,AccountNotDelegated,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUserwithAdminCountandNotProtected - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with admincount set and Account is sensitive and cannot be delegated is Disabled."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserwithAdminCountandSmartcardLogonNotRequired{
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserwithAdminCountandSmartcardLogonNotRequired"
        $default_log = "$reportpath\report_ADUserwithAdminCountandSmartcardLogonNotRequired.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-aduser -Filter {admincount -eq 1 -and iscriticalsystemobject -notlike "*" -and SmartcardLogonRequired -eq $false}`
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,SmartcardLogonRequired,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled,PasswordExpired,PasswordLastSet,SmartcardLogonRequired,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUserwithAdminCountandSmartcardLogonNotRequired - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user object with admincount set and Smartcard required for logon disabled."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserPWDAge{
#user password age report
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserPWDAge"
        $default_log = "$reportpath\report_ADUserPWDAge.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-aduser -LDAPFilter "(!(IsCriticalSystemObject=TRUE))" `
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged,LastLogonDate,`
                    PasswordNeverExpires,CannotChangePassword,SmartcardLogonRequired,PwdLastSet `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled,PasswordExpired,PasswordNeverExpires,CannotChangePassword,`
                        SmartcardLogonRequired,PasswordLastSet,$hash_pwdage,LastLogonDate,whencreated,whenchanged,$hash_parentou}
            catch{"function ADUserPWDAge - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            $results | where {$_.PwdAgeinDays -gt 365} | export-csv "$reportpath\report_ADUserPWDAgeover1Year.csv" -NoTypeInformation
            $results | where {$_.PwdAgeinDays -gt 1825} | export-csv "$reportpath\report_ADUserPWDAgeover5Years.csv" -NoTypeInformation
            $results | where {$_.PwdAgeinDays -gt 3650} | export-csv "$reportpath\report_ADUserPWDAgeover10Years.csv" -NoTypeInformation
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserDisabled{
#disabled User
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserDisabled"
        $default_log = "$reportpath\report_ADUserDisabled.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-aduser -Filter {(Enabled -eq $false) -and (iscriticalsystemobject -notlike "*")} `
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,LastLogonDate,`
                    PasswordNeverExpires,CannotChangePassword,whencreated,whenchanged,PwdLastSet,"msDS-ReplAttributeMetaData" `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled,PasswordExpired,PasswordNeverExpires,CannotChangePassword,`
                        PasswordLastSet,LastLogonDate,$hash_uacchanged,whenchanged,whencreated,$hash_parentou}
            catch{"function ADUserDisabled - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user objects that are disabled."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserThumbnailPhotoSize{
#thumbnail photosize
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserThumbnailPhotoSize"
        $default_log = "$reportpath\report_ADUserThumbnailPhotoSize.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-aduser -ldapFilter "(thumbnailPhoto=*)" `
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,LastLogonDate,`
                    PasswordNeverExpires,CannotChangePassword,whenchanged,PwdLastSet,thumbnailPhoto,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,@{Name="thumbnailPhotoSize";Expression={[math]::round((($_.thumbnailPhoto.count)/1.33)/1kb,2)}}, `
                        admincount,enabled,PasswordExpired,PasswordNeverExpires,CannotChangePassword,`
                        PasswordLastSet,LastLogonDate,whenchanged,whencreated,$hash_parentou}
            catch{"function ADUserThumbnailPhotoSize - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user objects with thumbnailphoto."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserwithEmptyUPN{
#is UPN Empty
[cmdletbinding()]
    param()
    process{
        write-host "Starting FunctionADUserwithEmptyUPN"
        $default_log = "$reportpath\report_ADUserwithEmptyUPN.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-aduser -ldapFilter "(&(!(userprincipalname=*))(!(IsCriticalSystemObject=TRUE)))" `
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,LastLogonDate,`
                    PasswordNeverExpires,CannotChangePassword,whenchanged,PwdLastSet,thumbnailPhoto,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname, userprincipalname, `
                        admincount,enabled,PasswordExpired,PasswordNeverExpires,CannotChangePassword,`
                        PasswordLastSet,LastLogonDate,whenchanged,whencreated,$hash_parentou}
            catch{"function ADUserwithEmptyUPN - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user objects with no UPN set."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserwithPSOApplied{
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserwithPSOApplied"
        $default_log = "$reportpath\report_ADUserwithPSOApplied.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-aduser -ldapFilter "(msDS-PSOApplied=*)" `
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,LastLogonDate,`
                    PasswordNeverExpires,CannotChangePassword,whenchanged,PwdLastSet,"msDS-PSOApplied" `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,"msDS-PSOApplied",admincount,enabled,PasswordExpired,PasswordNeverExpires,CannotChangePassword,`
                        PasswordLastSet,LastLogonDate,whenchanged,whencreated,$hash_parentou}
            catch{"function ADUserwithPSOApplied - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user objects with fine grain password policy defined."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserwithAuthNPolicyOrSiloDefined{
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserwithAuthNPolicyOrSiloDefined"
        $default_log = "$reportpath\report_ADUserwithAuthNPolicyOrSiloDefined.csv"
        $results = @()
        
        foreach($domain in (get-adforest).domains){
            
            try{$results += get-aduser -ldapFilter "(|(msDS-AssignedAuthNPolicy=*)(msDS-AssignedAuthNPolicySilo=*))" `
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,LastLogonDate,`
                    PasswordNeverExpires,CannotChangePassword,whenchanged,PwdLastSet,"msDS-AssignedAuthNPolicy"."msDS-AssignedAuthNPolicySilo" `
                 -server $domain | `
                    select $hash_domain, samaccountname,$hash_AuthNPolicy,$hash_AuthNPolicySilo,admincount,enabled,PasswordExpired,PasswordNeverExpires,CannotChangePassword,`
                        PasswordLastSet,LastLogonDate,whenchanged,whencreated,$hash_parentou}
            catch{"function ADUserwithAuthNPolicyOrSiloDefined - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user objects with AuthNPolicySilo or AuthNPolicy set."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUsersFoundinRootofDomain{
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUsersFoundinRootofDomain"
        $default_log = "$reportpath\report_ADUsersFoundinRootofDomain.csv"
        $results = @()
        foreach($domain in (get-adforest).domains){
            try{$results += Get-ADUser -Filter * `
                -searchbase $((get-adobject -LDAPFilter '(objectclass=domainDNS)' -server $domain).distinguishedname) `
                    -SearchScope OneLevel -server $domain -Properties whencreated,samaccountname,enabled,PasswordExpired | `
                    Select $hash_domain,samaccountname, whencreated, distinguishedname}
            catch{"function ADUsersFoundinRootofDomain - $domain - $($_.Exception)" | out-file $default_err_log -append}     
        }
        
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) user objects that exist in root of domain."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
Function ADUserDuplicateSamAccountNameOrUPN{
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserDuplicateSamAccountNameOrUPN"
        
        
        $temp_log = "$reportpath\tmp_forADUserDuplicateSamAccountNameOrUPN.csv"
        If ($(Try { Test-Path $temp_log} Catch { $false })){Remove-Item $temp_log -force}
        $users = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            try{get-aduser -filter {enabled -eq $true -and iscriticalsystemobject -notlike "*"} `
                -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | select `
                $hash_domain,samaccountname,UserPrincipalName | export-csv $temp_log -append -NoTypeInformation}
            catch{"function ADUserDuplicateSamAccountNameOrUPN - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        write-host "Searching for Duplicate SAM"
        $sam_log = "$reportpath\report_ADUserDuplicateSamAccountNameFound.csv"
        If ($(Try { Test-Path $sam_log} Catch { $false })){Remove-Item $sam_log -force}
        $users = import-csv $temp_log | select * | sort-object -Property samaccountname 
        foreach($user in $Users){
            if($user.samaccountname -eq $lastuser){
                    $user | select domain, samaccountname,`
                     @{name='FoundIn';expression={$lastdomain}}| export-csv $sam_log -Append -notypeinformation
                }else{
                    $lastuser = $user.samaccountname
                    $lastdomain = $user.domain
                }
        }
        write-host "Searching for Duplicate UPN"
        $upn_log = "$reportpath\report_ADUserDuplicateUPNFound.csv"
        If ($(Try { Test-Path $upn_log} Catch { $false })){Remove-Item $upn_log -force}
        $users = import-csv $temp_log | where {$_.UserPrincipalName -like "*"} | select * | sort-object -Property UserPrincipalName
        foreach($user in $Users){
            if($user.UserPrincipalName -eq $lastuser -and $user.UserPrincipalName -like "*"){
                    $user | select domain, userprincipalname,`
                     @{name='FoundIn';expression={$lastdomain}}| export-csv $upn_log -Append -notypeinformation
                }else{
                    $lastuser = $user.UserPrincipalName
                    $lastdomain = $user.domain
                }
        }

        if($results){
            write-host "Found $(($results | measure).count) user objects with AuthNPolicySilo or AuthNPolicy set."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
        }
    }
}
#region hash calculated properties

#creating hash tables for each calculated property

$hash_domain = @{name='Domain';expression={$domain}}
$hash_parentou = @{name='ParentOU';expression={`
    $($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}}
$hash_pwdage = @{Name="PwdAgeinDays";Expression={`
    if($_.PwdLastSet -ne 0){(new-TimeSpan([datetime]::FromFileTimeUTC($_.PwdLastSet)) $(Get-Date)).days}else{0}}}
$hash_uacchanged = @{name='UACChanged';expression={`
    ($_ | Select-Object -ExpandProperty "msDS-ReplAttributeMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_ATTR_META_DATA | where `
        { $_.pszAttributeName -eq "userAccountControl"}}).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}}
$hash_thumbnailphotosize = @{Name="thumbnailPhotoSize";Expression={[math]::round((($_.thumbnailPhoto.count)/1.33)/1kb,2)}}
$hash_AuthNPolicy = @{Name="AuthNPolicy";Expression={if($_."msDS-AssignedAuthNPolicy"){$True}else{$False}}}
$hash_AuthNPolicySilo = @{Name="AuthNPolicySilo";Expression={if($_."msDS-AssignedAuthNPolicySilo"){$True}else{$False}}}
#endregion


ADUsersFoundinRootofDomain
ADUsersWithSIDHistoryFromSameDomain
ADUsersWithDoNotRequireKerbPreauth
ADUsersWithStorePwdUsingReversibleEncryption
ADUserswithUseDESKeyOnly
ADUserswithUnConstrainedDelegationEnabled
ADUserswithPwdNotSet
ADUserswithPwdNeverExpired
ADUserswithPwdNotRequired
ADUserswithAdminCount
ADUserswithStaleAdminCount
ADUserswithAdminCountnotMemberofProtectedUsersGroup
ADUserswithStalePWDAgeAndLastLogon
ADUserswithNonStandardPrimaryGroup
ADUserswithAdminCountandEmailorSkypeEnabled
ADUserswithAdminCountAndSPN
ADUserswithAdminCountandUnConstrainedDelegation
ADUserwithAdminCountandNotProtected
ADUserwithAdminCountandSmartcardLogonNotRequired
ADUserwithEmptyUPN
ADUserPWDAge
ADUserDisabled
ADUserThumbnailPhotoSize
ADUserwithPSOApplied
#ADUserwithAuthNPolicyOrSiloDefined
ADUserDuplicateSamAccountNameOrUPN

write-host "Report Can be found here $reportpath"
