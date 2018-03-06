
<#PSScriptInfo

.SYNOPSIS


.DESCRIPTION 
 This script finds all stale windows computers in active directory and disables them. 
 use the disablestale switch to disable the windows computers.  Please look at the results
 first and then when you are ready to disable the objects comment out the -whatif in the DisableADComputers
 function

 !!!remove the -whatif after you test it.

.EXAMPLE
.\Findanddisablestaleadcomputers.ps1 

.\Findanddisablestaleadcomputers.ps1 -disablestale

.\Findanddisablestaleadcomputers.ps1 -$DaysInactive 120

.VERSION 0.4

.GUID 2b49ab62-9f8e-4542-b890-329b42c15d75

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

.TAGS msonline PowerShell

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
#Requires -version 4.0
#Requires -RunAsAdministrator


Param($DaysInactive=90,
$reportpath = "$env:userprofile\Documents",
[switch]$disablestale)

$default_err_log = $reportpath + '\err_log.txt'
$windows_log = "$reportpath\reportStaleWindowsADComputers.csv"
$non_windows_log = "$reportpath\reportStaleNonWindowsADComputers.csv"
$stale = @()

#region functions
Function createADSearchBase{
    write-host "Getting Searchbase list"
    $searchbase_list = "$reportpath\tmpADSearchBaseList.csv"
    try{Get-ChildItem $searchbase_list | Where-Object { $_.LastWriteTime -lt $((Get-Date).AddDays(-5))} | Remove-Item -force}catch{}
    If (!(Test-Path $searchbase_list)){
        foreach($domain in (get-adforest).domains){
            try{Get-ADObject -ldapFilter "(|(objectclass=organizationalunit)(objectclass=domainDNS)(objectclass=builtinDomain))" `
                -Properties "msds-approx-immed-subordinates" -server $domain | where {$_."msds-approx-immed-subordinates" -ne 0} | select `
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
    $searchbase = import-csv $searchbase_list
    $searchbase
}
Function collectADStaleComputers{
    $d = ([DateTime]::Today.AddDays(-$DaysInactive)).ToFileTimeUTC()
    $results = @()
    $Default_Group_ID = 515
    $ComputerProperties = @("whencreated","lastlogontimestamp","SamAccountName","operatingsystem",`
        "operatingsystemversion","UserAccountControl","admincount","pwdlastset","IPv4Address","DNSHostName", `
        "PasswordNotRequired")

    if(!($searchbase)){
            #go to function to populate the variable
            $searchbase = createADSearchBase
    }
    write-host "Collecting Stale Computers"
    foreach($sb in $searchbase){$domain = $sb.domain
        try{$results += get-adcomputer -Filter {(LastLogonTimeStamp -lt $d -or LastLogonTimeStamp -notlike "*")
                    -and (pwdlastset -lt $d -or pwdlastset -eq 0) -and (enabled -eq $true)
                    -and (iscriticalsystemobject -notlike $true)
                    -and ((ServicePrincipalName -notlike "*") -or (ServicePrincipalName -notlike "*MSClusterVirtualServer*"))} `
                -Properties $ComputerProperties -SearchBase $sb.distinguishedname -SearchScope OneLevel `
                -Server $sb.domain | where {$_.IPv4Address -eq $null} | select $hash_domain, *}
        catch{"functionCollectADComputers - $domain - $($_.Exception)" | out-file $default_err_log -append}
    }

    $results | select domain,SamAccountName,DNSHostName,operatingsystem,UserAccountControl,`
            $hash_pwdLastSet,$hash_lastLogonTimestamp,$hash_whencreated,PasswordNotRequired,$hash_parentou
}
Function DisableADComputers{
    [cmdletbinding()]
    param($computer,$domain)
    process{
        write-host "Disabling $computer"
            try{Disable-ADAccount $computer -server $domain -whatif}
            catch{"Failed"; "$(Get-Date) - ($computer).domain - Failed to disable $(($computer).samaccountname) - $($_.Exception)" | `
                out-file $default_err_log -append}
    }
}
#endregion
#region hashes
$hash_whencreated = @{Name="whencreated";
    Expression={($_.whencreated).ToString('MM/dd/yyyy')}}
$hash_pwdLastSet = @{Name="pwdLastSet";
    Expression={if($_.PwdLastSet -ne 0){([datetime]::FromFileTime($_.pwdLastSet).ToString('MM/dd/yyyy'))}}}
$hash_lastLogonTimestamp = @{Name="LastLogonTimeStamp";
    Expression={if($_.LastLogonTimeStamp -like "*"){([datetime]::FromFileTime($_.LastLogonTimeStamp).ToString('MM/dd/yyyy'))}}}
$hash_domain = @{Name="Domain";
    Expression={$domain}}
$hash_parentou = @{name='ParentOU';expression={`
    $($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}}
#endregion

$stale = collectADStaleComputers

if($disablestale){
    $stale | where {$_.operatingsystem -like "Windows*"} | foreach{DisableADComputers -computer $_.samaccountname -domain $_.domain}
}

$stale | where {$_.operatingsystem -like "Windows*"} | export-csv $windows_log -NoTypeInformation
$stale | where {$_.operatingsystem -notlike "Windows*"} | export-csv $non_windows_log -NoTypeInformation


cd $reportpath
write-host "Results can be found here: $reportpath"
