
<#PSScriptInfo

.VERSION 0.3

.GUID aed4e88b-ed60-47de-a722-9c28f1258a98

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

.TAGS AD Computers

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
0.3 date cleanup
0.2 Added duplicate sid lookup
0.1 First go around of the script

.PRIVATEDATA 

#>

#Requires -Module ActiveDirectory
#Requires -version 3.0
#Requires -RunAsAdministrator

<# 

.DESCRIPTION 
 Creates reports about Active Directory Computers 

 Use the importfunctiononly switch to run particular function / reports

#> 
Param($reportpath = "$env:userprofile\Documents",[switch]$importfunctionsonly)

$reportpath = "$reportpath\ADCleanUpReports"
If (!($(Try { Test-Path $reportpath } Catch { $true }))){
    new-Item $reportpath -ItemType "directory"  -force
}

If (!($(Try { Test-Path "$reportpath\Computers" } Catch { $true }))){
    new-Item "$reportpath\Computers" -ItemType "directory"  -force
}

$global:default_err_log = $reportpath + '\err_log.txt'
$global:ous = @()
$Global:finished = @()
$global:singleuse_comp = $False
#change current path to the report path
cd $reportpath
cls

function global:DisplayFunctionResults{
    if($global:singleuse_comp){$script:finished
                write-host "Report Can be found here $reportpath"
                $script:finished = @()
    }
}
Function global:ADOUList{
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADOUList"
        $ou_list = "$reportpath\Computers\ADOUList.csv"
        Get-ChildItem $ou_list | Where-Object { $_.LastWriteTime -lt $((Get-Date).AddDays(-10))} | Remove-Item -force

        If (!(Test-Path $ou_list)){
            Write-host "This will take a few minutes to gather a list of OU's to search through."
            foreach($domain in (get-adforest).domains){
                try{Get-ADObject -ldapFilter "(|(objectclass=organizationalunit)(objectclass=domainDNS)(objectclass=builtinDomain))" `
                    -Properties "msds-approx-immed-subordinates" -server $domain | where {$_."msds-approx-immed-subordinates" -ne 0} | select `
                     $hash_domain, DistinguishedName  | export-csv $ou_list -append -NoTypeInformation}
                catch{"function ADOUList - $domain - $($_.Exception)" | out-file $default_err_log -append}
                try{(get-addomain $domain).ComputersContainer | Get-ADObject -server $domain | select `
                     $hash_domain, DistinguishedName | export-csv $ou_list -append -NoTypeInformation}
                catch{"function ADOUList - $domain - $($_.Exception)" | out-file $default_err_log -append}
            }
        }

        $script:ous = import-csv $ou_list
    }
}
Function global:ADComputerswithNonStandardPrimaryGroup{
#report_computers_with_default_primary_group_not_standard
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADComputerswithNonStandardPrimaryGroup"
        $default_log = "$reportpath\Computers\report_ADComputerswithNonStandardPrimaryGroup.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-adcomputer -Filter {primaryGroupID -ne 515 -and enabled -eq "True" 
                                -and iscriticalsystemobject -eq $false}`
                 -Properties admincount,enabled,primaryGroupID, `
                    primaryGroup,whencreated,whenchanged,operatingSystem `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, name,operatingsystem,admincount,enabled,primaryGroupID, `
                        primaryGroup,$hash_whencreated,$hash_whenchanged,$hash_parentou}
            catch{"function ADComputerswithNonStandardPrimaryGroup - $domain - $($_.Exception)" | `
                out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            $script:finished += "Computer object with Primary Group other than Domain Computers (515): $(($results | measure).count)"
            DisplayFunctionResults
        }
    }
}
Function global:ADComputerswithPwdNotRequired{
    #report_computers_with_pwd_not_required_set
    #PASSWD_NOTREQD 0x0020 32
    [cmdletbinding()]
    param()
    process{
    write-host "Starting Function ADComputerswithPwdNotRequired"
        $default_log = "$reportpath\Computers\report_ADComputerswithPwdNotRequired.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            #Get-ADComputer -Filter {UserAccountControl -band 32}
            #Get-ADComputer -Filter {PasswordNotRequired -eq $True}
            try{$results += get-adcomputer -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=32)(!(IsCriticalSystemObject=TRUE)))"`
                 -Properties admincount,enabled,pwdlastset,PasswordNotRequired,whencreated,whenchanged,operatingSystem `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, name,operatingsystem,PasswordNotRequired,admincount, `
                        enabled,$hash_pwdlastset,$hash_whencreated,$hash_whenchanged,$hash_parentou}
            catch{"function ADComputerswithPwdNotRequired - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation
        if($results){
            $script:finished += "Computer object with password not required: $(($results | measure).count)"
            DisplayFunctionResults
        }
    }
}
Function global:ADComputersDisabled{
#report_computers_disabled
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADComputersDisabled"
        $default_log = "$reportpath\Computers\report_ADComputersDisabled.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-adcomputer -Filter {(Enabled -eq $false) -and (iscriticalsystemobject -eq $false)} `
                 -Properties admincount,enabled,PasswordExpired,whencreated,LastLogontimestamp,operatingSystem, `
                    PasswordNeverExpires,CannotChangePassword,whencreated,whenchanged,PwdLastSet,"msDS-ReplAttributeMetaData" `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, name,operatingsystem,admincount,enabled,`
                        $hash_uacchanged,$hash_pwdlastset, `
                        $hash_lastLogonTimestamp,$hash_whencreated,$hash_whenchanged,$hash_parentou}
            catch{"function ADComputerDisabled - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            $script:finished += "Computer object that are disabled: $(($results | measure).count)"
            DisplayFunctionResults
        }
    }
}
Function global:ADComputerswithUnConstrainedDelegationEnabled{
    #report_computers_unconstrained_delegation_enabled
    [cmdletbinding()]
    param()
    process{
        #TRUSTED_FOR_DELEGATION
        
        write-host "Starting Function ADComputerswithUnConstrainedDelegationEnabled"
        $default_log = "$reportpath\Computers\report_ADComputerswithUnConstrainedDelegationEnabled.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            #Get-ADComputer -Filter {UserAccountControl -band 524288}
            #Get-ADcomputer -Filter {Trustedfordelegation -eq $True}
            try{$results += get-adcomputer -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(IsCriticalSystemObject=TRUE)))"`
                 -Properties admincount,enabled,Trustedfordelegation,whencreated,whenchanged,operatingSystem `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, name,operatingsystem,Trustedfordelegation,admincount,enabled, `
                    $hash_whenchanged,$hash_whencreated,$hash_parentou}
            catch{"function ADComputerswithUnConstrainedDelegationEnabled - $domain - $($_.Exception)" | `
                out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            
            $script:finished += "Computer object with trusted for delegation (unconstrained kerb delegation) enabled: $(($results | measure).count)"
            DisplayFunctionResults
        }
    }
}
Function global:ADComputersWithSIDHistoryFromSameDomain{
    #report_computers_sid_history_from_same_domain
    [cmdletbinding()]
    param()
    process{
        #https://adsecurity.org/?p=1772
        write-host "Starting Function ADComputersWithSIDHistoryFromSameDomain"
        $default_log = "$reportpath\Computers\report_ADComputersWithSIDHistoryFromSameDomain.csv"
        $results = @()
        #Find Computer with sid history from same domain
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            [string]$Domain_SID = ((Get-ADDomain $domain).DomainSID.Value)
            try{$results += Get-ADComputer -Filter {SIDHistory -Like '*'} `
                -Properties SIDHistory,admincount,enabled,PasswordExpired,pwdlastset,whencreated,whenchanged,operatingsystem `
                -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                Where { $_.SIDHistory -Like "$domain_sid-*"} | `
                    select $hash_domain, name,operatingsystem,admincount,enabled,$hash_whenchanged,$hash_whencreated,$hash_parentou}
            catch{"function ADComputersWithSIDHistoryFromSameDomain - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            $script:finished += "Computer object with sidhistory from the same domain: $(($results | measure).count)"
            DisplayFunctionResults
        }
    }
}
Function global:ADComputerswithAdminCount{
    #computers_with_admincount
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADComputerswithAdminCount"
        $default_log = "$reportpath\Computers\report_ADComputerswithAdminCount.csv"
        $results = @()
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            
            try{$results += get-adcomputer -Filter {admincount -eq 1 -and iscriticalsystemobject -eq $false}`
                 -Properties admincount,enabled,PasswordExpired,PasswordLastSet,whencreated,whenchanged,operatingsystem `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, name,operatingsystem,admincount,enabled,$hash_whenchanged,$hash_whencreated,$hash_parentou}
            catch{"function ADcomputerswithAdminCount - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            $script:finished += "Computer object with admincount set: $(($results | measure).count)"
            DisplayFunctionResults
        }
    }
}
Function global:ADComputersisDeleted{
#report_computers_isdeleted
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADComputersisDeleted"
        $default_log = "$reportpath\Computers\report_ADComputersisDeleted.csv"
        $results = @()
        foreach($domain in (get-adforest).domains){
            try{$results += Get-ADobject -filter {objectclass -eq "computer" -and deleted -eq $true} -IncludeDeletedObject `
                -server $domain -Properties whencreated,samaccountname,Deleted,operatingsystem | `
                    Select $hash_domain,name, operatingsystem,$hash_whencreated, Deleted,distinguishedname}
            catch{"function ADComputersisDeleted - $domain - $($_.Exception)" | out-file $default_err_log -append}     
        }
        
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            $script:finished += "Computer object that are in a deleted state: $(($results | measure).count)"
            DisplayFunctionResults
        }
    }
}
Function global:ADComputerswithCertificates{
#report_computers_with certificates
    [cmdletbinding()]
    param()
    process{
        #https://docs.microsoft.com/en-us/azure/active-directory/connect/active-directory-aadconnectsync-largeobjecterror-usercertificate
        
        write-host "Starting Function ADComputerswithCertificates"
        $default_log = "$reportpath\Computers\report_ADComputerswithmorethan1Certificate.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            try{$results += get-adComputer -LDAPFilter "(usercertificate=*)"`
                 -Properties admincount,enabled,usercertificate,whencreated,whenchanged `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, *}
            catch{"function ADComputerswithCertificates - $domain - $($_.Exception)" | `
                out-file $default_err_log -append}
        }
        
        $results | select domain, samaccountname,$hash_usercertificatecount,admincount,enabled, `
            $hash_whenchanged,$hash_whencreated,$hash_parentou | where {$_.usercertificateCount -gt 1} | `
                export-csv $default_log -NoTypeInformation
        

        if($results | where {$_.usercertificateCount -gt 1}){
            
            $script:finished += "Computer found with more than 1 certificates in usercertificate attribute"
            DisplayFunctionResults
        }
        $cert_results = @()
        $default_log = "$reportpath\Computers\report_ADComputerswithExpiredCertificates.csv"
        [int] $days = 0
        foreach($comp in $results){
            foreach($cert in $comp.usercertificate){
                $converted = [System.Security.Cryptography.X509Certificates.X509Certificate2] $cert
                if ($converted.NotAfter -lt [datetime]::Today.AddDays($days)) {
                    $cert_results += $comp | select $hash_domain, samaccountname, `
                    @{name='CertThumbprint';expression={$converted.Thumbprint}},`
                    @{name='CertExpired';expression={$converted.NotAfter}}, `
                    admincount,enabled,PasswordExpired,$hash_pwdLastSet,$hash_whenchanged,$hash_whencreated,$hash_parentou
                }
            }
        }
        $cert_results | export-csv $default_log -NoTypeInformation
        if($cert_results){
            $script:finished += "Computer objects with expired certificate in usercertificate attribute : $(($cert_results | measure).count)"
            DisplayFunctionResults
        }
    }
}
Function global:ADComputerswithStalePWDAgeAndLastLogon{
    #report_computers_stale
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADComputerswithStalePWDAgeAndLastLogon"
        
        $results = @()
        $DaysInactive = 90 
        $threshold_time = (Get-Date).Adddays(-($DaysInactive)).ToFileTimeUTC() 
        $create_time = (Get-Date).Adddays(-($DaysInactive))

        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            try{$results += get-adcomputer -Filter {(LastLogonTimeStamp -lt $threshold_time -or LastLogonTimeStamp -notlike "*") 
                                -and (pwdlastset -lt $threshold_time -or pwdlastset -eq 0) -and (enabled -eq $true) 
                                -and (iscriticalsystemobject -eq $false) -and (whencreated -lt $create_time)} `
                    -properties IPv4Address,OperatingSystem,serviceprincipalname,LastLogonTimeStamp,pwdlastset, `
                        enabled,whencreated `
                    -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, name,OperatingSystem,admincount,enabled,$hash_pwdage,$hash_pwdlastset, `
                        $hash_lastLogonTimestamp,$hash_whencreated,$hash_whenchanged,$hash_parentou}
            catch{"function ADComputerswithStalePWDAgeAndLastLogon - $domain - $($_.Exception)" | `
                out-file $default_err_log -append}
        }
        $default_log = "$reportpath\Computers\report_ADWindowsComputerswithStalePWDAgeAndLastLogon.csv"
        $results | where {($_.IPv4Address -eq $null) -and ($_.OperatingSystem -like "Windows*") -and ` 
            (!($_.serviceprincipalname -like "*MSClusterVirtualServer*"))} | export-csv $default_log -NoTypeInformation
        $default_log = "$reportpath\Computers\report_ADNonWindowsComputerswithStalePWDAgeAndLastLogon.csv"
        $results | where {($_.IPv4Address -eq $null) -and ($_.OperatingSystem -notlike "*Windows*") -and ` 
            (!($_.serviceprincipalname -like "*MSClusterVirtualServer*"))} | export-csv $default_log -NoTypeInformation

        if($results | where {($_.IPv4Address -eq $null) -and ($_.OperatingSystem -like "Windows*") -and `
             (!($_.serviceprincipalname -like "*MSClusterVirtualServer*"))}){
            $script:finished += "Windows Computer object with passwords or lastlogon timestamps greater than $DaysInactive days: $(($results | `
             where {($_.IPv4Address -eq $null) -and ($_.OperatingSystem -like "Windows*") -and `
             (!($_.serviceprincipalname -like "*MSClusterVirtualServer*"))} | measure).count)"
            DisplayFunctionResults
        }
    }
}
Function global:ADComputerswithDuplicateSid{
#report_computers_with certificates
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADComputerswithDuplicateSid"
        $temp_log = "$reportpath\Computers\tmp_ADComputers.csv"
        #https://support.microsoft.com/en-us/help/314828/the-microsoft-policy-for-disk-duplication-of-windows-installations
        #https://support.microsoft.com/en-us/help/816099/how-to-find-and-clean-up-duplicate-security-identifiers-with-ntdsutil
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            try{$results += get-adComputer -filter * `
                 -Properties samaccountname, name, sid, enabled, distinguishedname `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname, name, sid, enabled, distinguishedname}
            catch{"function ADComputerswithDuplicateSid - $domain - $($_.Exception)" | `
                out-file $default_err_log -append}
        }
        $results | export-csv $temp_log -NoTypeInformation
        $default_log = "$reportpath\Computers\ADComputerswithDuplicateSid.csv"
        If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}
        foreach($comp in ($results | sort-object -Property sid)){
                $comp.sid
                $lastcomp.sid
            if($comp.sid -eq $lastcomp.sid){
                $Comp | select domain, samaccountname, sid, enabled, `
                @{name='OtherComputer';expression={$lastcomp.samaccountname}} | `
                    export-csv $default_log -Append -notypeinformation
            }else{
                $lastcomp = $comp
            }
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
$hash_usercertificatecount = @{Name="usercertificateCount";Expression={$_.usercertificate.count}}
#this hashtable is used to create a calculated property that converts lastlogontimestamp
$hash_lastLogonTimestamp = @{Name="LastLogonTimeStamp";
    Expression={if($_.LastLogonTimeStamp -like "*"){([datetime]::FromFileTime($_.LastLogonTimeStamp).ToString('MM/dd/yyyy'))}}}
$hash_whenchanged = @{Name="whenchanged";
    Expression={($_.whenchanged).ToString('MM/dd/yyyy')}}
$hash_whencreated = @{Name="whencreated";
    Expression={($_.whencreated).ToString('MM/dd/yyyy')}}
$hash_pwdLastSet = @{Name="pwdLastSet";
    Expression={if($_.PwdLastSet -ne 0){([datetime]::FromFileTime($_.pwdLastSet).ToString('MM/dd/yyyy'))}}}
#endregion

if(!($importfunctionsonly)){
    $time_log = "$reportpath\computers\runtime.csv"
    (dir function: | where name -like adcomputer*).name | foreach{$script_function = $_
        Measure-Command {Invoke-Expression -Command $script_function} | `
            select @{name='RunDate';expression={get-date -format d}},`
            @{name='Function';expression={$script_function}}, `
            @{name='Hours';expression={$_.hours}}, `
            @{name='Minutes';expression={$_.Minutes}}, `
            @{name='Seconds';expression={$_.Seconds}} | export-csv $time_log -append -notypeinformation
    }
    $script:finished
    write-host "Report Can be found here $reportpath"
}else{
    $global:singleuse_comp = $True
    write-host -foreground yellow "Type out the function and press enter to run a particular report"
    (dir function: | where name -like adcomputer*).name
}
