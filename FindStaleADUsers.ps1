
<#PSScriptInfo

.VERSION 0.1

.GUID 6baf9533-56a2-41f4-a51b-9818241efb74

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

.TAGS msonline PowerShell get-aduser

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


.PRIVATEDATA 

#>

#Requires -Module ActiveDirectory

<# 

.DESCRIPTION 
 This script finds all stale userss in active directory. 

#> 
Param($reportpath = "$env:userprofile\Documents")
$default_err_log = "$reportpath\err_log.txt"

Function ADOUList{
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADOUList"
        $script:ou_list = "$reportpath\ADOUList.csv"
        Get-ChildItem $script:ou_list | Where-Object { $_.LastWriteTime -lt $((Get-Date).AddDays(-10))} | Remove-Item -force

        If (!(Test-Path $script:ou_list)){
            Write-host "This will take a few minutes to gather a list of OU's to search through."
            foreach($domain in (get-adforest).domains){
                try{Get-ADObject -ldapFilter "(|(objectclass=organizationalunit)(objectclass=domainDNS)(objectclass=builtinDomain))" `
                    -Properties "msds-approx-immed-subordinates" -server $domain | where {$_."msds-approx-immed-subordinates" -ne 0} | select `
                     $hash_domain, DistinguishedName | export-csv $script:ou_list -append -NoTypeInformation}
                catch{"function ADOUList - $domain - $($_.Exception)" | out-file $default_err_log -append}
                try{(get-addomain $domain).UsersContainer | Get-ADObject -server $domain | select `
                     $hash_domain, DistinguishedName | export-csv $script:ou_list -append -NoTypeInformation}
                catch{"function ADOUList - $domain - $($_.Exception)" | out-file $default_err_log -append}
            }
        }

        $script:ous = import-csv $script:ou_list
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
        foreach($ou in $script:ous){$domain = $((Get-ADDomainController -Discover -Domain ($ou).domain -Service "PrimaryDC").hostname)
            try{$results += get-aduser -Filter {(LastLogonTimeStamp -lt $threshold_time -or LastLogonTimeStamp -notlike "*")
                 -and (pwdlastset -lt $threshold_time -or pwdlastset -eq 0) -and (enabled -eq $true) 
                 -and (iscriticalsystemobject -notlike "*") -and (whencreated -lt $create_time)}`
                    -Properties admincount,enabled,PasswordExpired,pwdLastSet,whencreated,whenchanged,LastLogonDate, `
                        PasswordNeverExpires,CannotChangePassword,SmartcardLogonRequired, serviceprincipalname,lockedout, `
                        LastBadPasswordAttempt,SIDHistory `
                    -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled,lockedout,PasswordExpired,PasswordNeverExpires,`
                        CannotChangePassword,SmartcardLogonRequired,$hash_pwdage,$hash_pwdLastSet,$hash_lastLogonTimestamp, `
                        $hash_lastbadpassword,$hash_whenchanged,$hash_whencreated,$hash_spn,$hash_sidhist,$hash_parentou}
            catch{"function ADUserswithStalePWDAgeAndLastLogon - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "User object with passwords or lastlogon timestamps greater than $DaysInactive days: $(($results | measure).count)"
            write-host "Stale User object with no password set ever: $(($results | where {$_.pwdLastSet -eq $null} | measure).count)"
            write-host "Stale User with expired password: $(($results | where {$_.PasswordExpired -eq $True} | measure).count)"
            write-host "Stale User where spn is defined: $(($results | where {$_.SPNExist -eq $true} | measure).count)"
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

$hash_lastbadpassword = @{Name="LastBadPasswordAttemp";
    Expression={($_.LastBadPasswordAttemp).ToString('MM/dd/yyyy')}}
$hash_whenchanged = @{Name="whenchanged";
    Expression={($_.whenchanged).ToString('MM/dd/yyyy')}}
$hash_whencreated = @{Name="whencreated";
    Expression={($_.whencreated).ToString('MM/dd/yyyy')}}
$hash_pwdLastSet = @{Name="pwdLastSet";
    Expression={if($_.PwdLastSet -ne 0){([datetime]::FromFileTime($_.pwdLastSet).ToString('MM/dd/yyyy'))}}}
$hash_lastLogonTimestamp = @{Name="LastLogonTimeStamp";
    Expression={if($_.LastLogonTimeStamp -like "*"){([datetime]::FromFileTime($_.LastLogonTimeStamp).ToString('MM/dd/yyyy'))}}}
$hash_spn = @{Name="containsSPN";Expression={if($_.serviceprincipalname){$true}else{$false}}}
$hash_sidhist = @{name='SIDHistory';expression={if($_.SIDHistory -like "*"){$true}else{$false}}}
#endregion

ADUserswithStalePWDAgeAndLastLogon
