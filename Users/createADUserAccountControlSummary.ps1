#Requires -Module ActiveDirectory
#Requires -Version 4
#Requires -RunAsAdministrator

<#PSScriptInfo

.VERSION 0.1

.GUID 28a1bcd8-3870-4b22-82af-70383231a1a9

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

.description
    https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro
    SCRIPT - The logon script will be run.
    ACCOUNTDISABLE - The user account is disabled. 
    HOMEDIR_REQUIRED - The home folder is required.
    PASSWD_NOTREQD - No password is required.
    PASSWD_CANT_CHANGE - The user cannot change the password. This is a permission on the user's object. For information about how to programmatically set this permission, visit the following Web site: 
    http://msdn2.microsoft.com/en-us/library/aa746398.aspx
    ENCRYPTED_TEXT_PASSWORD_ALLOWED - The user can send an encrypted password. 
    TEMP_DUPLICATE_ACCOUNT - This is an account for users whose primary account is in another domain. This account provides user access to this domain, but not to any domain that trusts this domain. This is sometimes referred to as a local user account.
    NORMAL_ACCOUNT - This is a default account type that represents a typical user. 
    INTERDOMAIN_TRUST_ACCOUNT - This is a permit to trust an account for a system domain that trusts other domains. 
    WORKSTATION_TRUST_ACCOUNT - This is a computer account for a computer that is running Microsoft Windows NT 4.0 Workstation, Microsoft Windows NT 4.0 Server, Microsoft Windows 2000 Professional, or Windows 2000 Server and is a member of this domain.
    SERVER_TRUST_ACCOUNT - This is a computer account for a domain controller that is a member of this domain. 
    DONT_EXPIRE_PASSWD - Represents the password, which should never expire on the account. 
    MNS_LOGON_ACCOUNT - This is an MNS logon account.
    SMARTCARD_REQUIRED - When this flag is set, it forces the user to log on by using a smart card. 
    TRUSTED_FOR_DELEGATION - When this flag is set, the service account (the user or computer account) under which a service runs is trusted for Kerberos delegation. Any such service can impersonate a client requesting the service. To enable a service for Kerberos delegation, you must set this flag on the userAccountControl property of the service account. 
    NOT_DELEGATED - When this flag is set, the security context of the user is not delegated to a service even if the service account is set as trusted for Kerberos delegation.
    USE_DES_KEY_ONLY - (Windows 2000/Windows Server 2003) Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys. 
    DONT_REQUIRE_PREAUTH - (Windows 2000/Windows Server 2003) This account does not require Kerberos pre-authentication for logging on.
    PASSWORD_EXPIRED - (Windows 2000/Windows Server 2003) The user's password has expired. 
    TRUSTED_TO_AUTH_FOR_DELEGATION - (Windows 2000/Windows Server 2003) The account is enabled for delegation. This is a security-sensitive setting. Accounts that have this option enabled should be tightly controlled. This setting lets a service that runs under the account assume a client's identity and authenticate as that user to other remote servers on the network. 
    PARTIAL_SECRETS_ACCOUNT - (Windows Server 2008/Windows Server 2008 R2) The account is a read-only domain controller (RODC). This is a security-sensitive setting. Removing this setting from an RODC compromises security on that server.
#>
Param($reportpath = "$env:userprofile\Documents")

$time_log = "$reportpath\runtime.csv"
$final_report = "$reportpath\reportUserAccountControlFlags_$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).csv"

Function createADSearchBase{
    $searchbase_list = "$reportpath\tmpADSearchBaseList.csv"
    try{Get-ChildItem $searchbase_list | Where-Object { $_.LastWriteTime -lt $((Get-Date).AddDays(-5))} | Remove-Item -force}catch{}
    write-host "Generating Search Base List"
    If (!(Test-Path $searchbase_list)){
        foreach($domain in (get-adforest).domains){
            write-debug "Gathering OUs"
            try{Get-ADObject -ldapFilter "(objectclass=organizationalunit)" `
                -Properties "msds-approx-immed-subordinates" -server $domain -ResultPageSize 500 -ResultSetSize $null |`
                     where {$_."msds-approx-immed-subordinates" -ne 0} | select `
                $hash_domain, DistinguishedName  | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
            try{Get-ADObject -ldapFilter "(objectclass=domainDNS)" `
                -Properties "msds-approx-immed-subordinates" -server $domain -ResultPageSize 500 -ResultSetSize $null |`
                     where {$_."msds-approx-immed-subordinates" -ne 0} | select `
                $hash_domain, DistinguishedName  | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
            try{Get-ADObject -ldapFilter "(objectclass=builtinDomain)" `
                -Properties "msds-approx-immed-subordinates" -server $domain -ResultPageSize 500 -ResultSetSize $null |`
                     where {$_."msds-approx-immed-subordinates" -ne 0} | select `
                $hash_domain, DistinguishedName  | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
            try{(get-addomain $domain).UsersContainer | Get-ADObject -server $domain | select `
                $hash_domain, DistinguishedName | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
            try{(get-addomain $domain).ComputersContainer | Get-ADObject -server $domain | select `
                $hash_domain, DistinguishedName | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
    }
    else{
        Write-host "Reusing Existing Searchbase List"
    }
    $searchbase = import-csv $searchbase_list
    $searchbase
}

function collectADUserUAC{
    if(!($search_base)){
        #go to function to populate the variable
        $function_results = Measure-Command {$search_base = createADSearchBase} | `
            select @{name='RunDate';expression={get-date -format d}},`
            @{name='Function';expression={"createADSearchBase"}}, `
            @{name='Hours';expression={$_.hours}}, `
            @{name='Minutes';expression={$_.Minutes}}, `
            @{name='Seconds';expression={$_.Seconds}}
            $function_results | export-csv $time_log -append -notypeinformation
    }
    write-host "Collecting AD Users"
    $userProperties = @("whencreated","lastlogontimestamp","SamAccountName",`
            "UserAccountControl","Enabled","admincount","distinguishedname","PasswordExpired","LockedOut")
    $select_properties = $userProperties + $hash_domain
    $results = @()
    foreach($sb in $search_base){$domain = $sb.domain
            try{$results += get-aduser -filter * `
                 -Properties $userProperties -SearchBase $sb.distinguishedname -SearchScope OneLevel `
                 -Server $sb.domain -ResultPageSize 500 -ResultSetSize $null | select $select_properties}
            catch{"functionCollectADComputers - $domain - $($_.Exception)" | out-file $default_err_log -append}
    }
    $results
}

function createUACReport{
    
    $array_uacvalues = @{SCRIPT=1
    ACCOUNTDISABLE=2
    HOMEDIR_REQUIRED=8
    LOCKOUT=16
    PASSWD_NOTREQD=32
    PASSWD_CANT_CHANGE=64
    ENCRYPTED_TEXT_PWD_ALLOWED=128
    TEMP_DUPLICATE_ACCOUNT=256
    NORMAL_ACCOUNT=512
    INTERDOMAIN_TRUST_ACCOUNT=2048
    WORKSTATION_TRUST_ACCOUNT=4096
    SERVER_TRUST_ACCOUNT=8192
    DONT_EXPIRE_PASSWORD=65536
    MNS_LOGON_ACCOUNT=131072
    SMARTCARD_REQUIRED=262144
    TRUSTED_FOR_DELEGATION=524288
    NOT_DELEGATED=1048576
    USE_DES_KEY_ONLY=2097152
    DONT_REQ_PREAUTH=4194304
    PASSWORD_EXPIRED=8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION=16777216
    PARTIAL_SECRETS_ACCOUNT=67108864}
    $function_time_to_run = Measure-Command {$users = collectADUserUAC} | `
            select @{name='RunDate';expression={get-date -format d}},`
            @{name='Function';expression={"collectADUserUAC"}}, `
            @{name='Hours';expression={$_.hours}}, `
            @{name='Minutes';expression={$_.Minutes}}, `
            @{name='Seconds';expression={$_.Seconds}} | export-csv $time_log -append -notypeinformation
    $function_time_to_run | export-csv $time_log -append -notypeinformation
    Write-host "Generating Report"
    $array_uacvalues.GetEnumerator() | foreach{$uac = $_
        $user_results = $users | where {$_.useraccountcontrol -band $uac.value}
        Write-host "$(($UAC).key) = $(($user_results | measure-object).count) Users"
        $user_results | select Domain, SamAccountName, useraccountcontrol, $hash_uacflag
    }
}

$hash_uacflag = @{name='UserAccountControlFlag';expression={$uac.key}} 
$hash_domain = @{name='Domain';expression={$domain}}
cls

$time_to_Run = Measure-Command {createUACReport  | export-csv $final_report -NoTypeInformation} | `
    select @{name='RunDate';expression={get-date -format d}},`
    @{name='Function';expression={"createUACReport"}}, `
    @{name='Hours';expression={$_.hours}}, `
    @{name='Minutes';expression={$_.Minutes}}, `
    @{name='Seconds';expression={$_.Seconds}}
    
$time_to_Run | sort samaccountname | export-csv $time_log -append -notypeinformation
write-host "Report Can be found here $reportpath"
