
<#PSScriptInfo

.VERSION 0.1

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
0.1 First go around of the script

.PRIVATEDATA 

#>

#Requires -Module ActiveDirectory
#Requires -Version 4
<# 

.DESCRIPTION 
 Creates Useful Cleanup Reports for Active Directory Users.

#> 
Param($reportpath = "$env:userprofile\Documents")

#change current path to the report path
cd $reportpath

Function ADUsersWithSIDHistoryFromSameDomain{
    [cmdletbinding()]
    param()
    process{
        #https://adsecurity.org/?p=1772
        write-host "Starting Function ADUsersWithSIDHistoryFromSameDomain"
        $default_log = "$reportpath\report_ADUsersWithSIDHistoryFromSameDomain.csv"
        $results = @()
        #Find Users with sid history from same domain
        foreach($domain in (get-adforest).domains){
            [string]$Domain_SID = ((Get-ADDomain $domain).DomainSID.Value)
            $results += Get-ADUser -Filter {SIDHistory -Like '*'} -Properties SIDHistory,admincount,enabled,PasswordExpired,PasswordLastSet -server $domain | `
                Where { $_.SIDHistory -Like "$domain_sid-*"} | `
                    select $hash_domain, samaccountname,admincount,enabled,PasswordExpired,PasswordLastSet,$hash_parentou
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
        #DONT_REQ_PREAUTH
        #This account does not require Kerberos pre-authentication for logging on.

        write-host "Starting Function ADUsersWithDoNotRequireKerbPreauth"
        $default_log = "$reportpath\report_ADUsersWithDoNotRequireKerbPreauth.csv"
        $results = @()
        
        foreach($domain in (get-adforest).domains){
            $results += Get-ADUser -Filter {UserAccountControl -band 4194304} -Properties admincount,enabled,PasswordExpired,PasswordLastSet -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled,PasswordExpired,PasswordLastSet,$hash_parentou
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
        #ENCRYPTED_TEXT_PWD_ALLOWED
        #The user can send an encrypted password.

        write-host "Starting Function ADUsersWithStorePwdUsingReversibleEncryption"
        $default_log = "$reportpath\report_ADUsersWithStorePwdUsingReversibleEncryption.csv"
        $results = @()
        
        foreach($domain in (get-adforest).domains){
            $results += Get-ADUser -Filter {UserAccountControl -band 128} -Properties admincount,enabled,PasswordExpired,PasswordLastSet,AllowReversiblePasswordEncryption -server $domain | `
                    select $hash_domain, samaccountname,AllowReversiblePasswordEncryption,admincount,enabled,PasswordExpired,PasswordLastSet,$hash_parentou
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
        #USE_DES_KEY_ONLY
        
        write-host "Starting Function ADUserswithUseDESKeyOnly"
        $default_log = "$reportpath\report_ADUserswithUseDESKeyOnly.csv"
        $results = @()
        
        foreach($domain in (get-adforest).domains){
            $results += Get-ADUser -Filter {UserAccountControl -band 2097152} -Properties admincount,enabled,PasswordExpired,PasswordLastSet,UseDESKeyOnly -server $domain | `
                    select $hash_domain, samaccountname,UseDESKeyOnly,admincount,enabled,PasswordExpired,PasswordLastSet,$hash_parentou
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
        
        foreach($domain in (get-adforest).domains){
            #Get-ADUser -Filter {UserAccountControl -band 524288}
            $results += Get-ADUser -Filter {Trustedfordelegation -eq $True} -Properties admincount,enabled,PasswordExpired,PasswordLastSet,Trustedfordelegation -server $domain | `
                    select $hash_domain, samaccountname,Trustedfordelegation,admincount,enabled,PasswordExpired,PasswordLastSet,$hash_parentou
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
        #TRUSTED_FOR_DELEGATION
        
        write-host "Starting Function ADUserswithPwdNotSet"
        $default_log = "$reportpath\report_ADUserswithPwdNotSet.csv"
        $results = @()
        
        foreach($domain in (get-adforest).domains){
            #Get-ADUser -Filter {UserAccountControl -band 524288}
            $results += Get-ADUser -Filter {pwdLastSet -eq 0} -Properties admincount,enabled,PasswordExpired,PasswordLastSet,Trustedfordelegation -server $domain | `
                    select $hash_domain, samaccountname,Trustedfordelegation,admincount,enabled,PasswordExpired,PasswordLastSet,$hash_parentou
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
}
Function ADUserswithPwdNeverExpired{
    #users_pwd_never_expires
}
Function ADUserswithAdminCount{
    #users_with_admincount
}
Function ADUserswithStaleAdminCount{
    #users with stale admin count
}
Function ADUserswithStalePWDAgeAndLastLogon{
    #stale Users
}
Function ADUserswithNonPrimaryGroupMembership{
#users_default_primary_group_membership_not_standard
}
Function ADUserswithAdminCountAndSPN{
#users_with_admincount_and_spn
}
Function ADUserswithAdminCountandUnConstrainedDelegation{
    #users_with_admincount_and_unconstrained_delegation_enabled
}
Function ADUserwithAdminCountandNotProtected{
#admincount_and_account_is_sensitive_cannot_be_delegate_not_set
}
#user password age report

#disabled User

#region hash calculated properties

#creating hash tables for each calculated property

$hash_domain = @{name='Domain';expression={$domain}}
$hash_parentou = @{name='ParentOU';expression={`
    $($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}}



#endregion


ADUsersWithSIDHistoryFromSameDomain
ADUsersWithDoNotRequireKerbPreauth
ADUsersWithStorePwdUsingReversibleEncryption
ADUserswithUseDESKeyOnly
ADUserswithUnConstrainedDelegationEnabled
ADUserswithPwdNotSet

write-host "Report Can be found here $reportpath"
