#Requires -Module activedirectory
#Requires -version 4.0

<#PSScriptInfo
.VERSION 0.3
.GUID 522d844c-93a4-4220-a198-7c3737e78b3c
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
.TAGS get-aduser get-adobject get-adgroups
.LICENSEURI 
.PROJECTURI 
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
.DESCRIPTION 
 This script will run and produce an output to determine if group membership growth is occuring. 
#> 
Param($reportpath = "$env:userprofile\Documents")
$default_err_log = "$reportpath\err.txt"
$time_log = "$reportpath\runtime.csv"


Function createADSearchBase{
    $searchbase_list = "$reportpath\tmpADSearchBaseList.csv"
    try{Get-ChildItem $searchbase_list | Where-Object { $_.LastWriteTime -lt $((Get-Date).AddDays(-1))} | Remove-Item -force}catch{}
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
Function getADSecurityGroups{
    $results = @()
    $GroupProperties = @("samaccountname","whencreated","distinguishedname","GroupScope")
    $Select_properties = $GroupProperties + $hash_domain
    if(!($searchbase)){
        #go to function to populate the variable
        Measure-Command {$searchbase = createADSearchBase} | `
            select @{name='RunDate';expression={get-date -format d}},`
            @{name='Function';expression={"createADSearchBase"}}, `
            @{name='Hours';expression={$_.hours}}, `
            @{name='Minutes';expression={$_.Minutes}}, `
            @{name='Seconds';expression={$_.Seconds}} | export-csv $time_log -append -notypeinformation
    }
    write-host "Collecting AD Groups"
    foreach($sb in $searchbase){$domain = $sb.domain
        try{$results += get-adgroup -filter 'GroupCategory -eq "Security"' `
                -Properties $GroupProperties -SearchBase $sb.distinguishedname -SearchScope OneLevel `
                -Server $sb.domain -ResultPageSize 500 -ResultSetSize $null| select $Select_properties}
        catch{"CollectADGroups - $domain - $($_.Exception)" | out-file $default_err_log -append}

            
    }
    $results | select domain,samaccountname,GroupScope,$hash_whencreated,$hash_parentou
}

#region hashes for calculated properties
$hash_domain = @{name='Domain';expression={$domain}}
$hash_whencreated = @{Name="whencreated";
    Expression={($_.whencreated).ToString('yyyy-MM')}}
$hash_parentou = @{name='ParentOU';expression={
        $($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}}
#endregion

$groups = @()
$groups = getADSecurityGroups
$groups  | group whencreated | select name,count | sort name -Descending | out-host

Write-host "OU Location for Groups created in $(get-date -Format yyyy)"
$groups | where whencreated -like "$(get-date -Format yyyy)*" | group parentou | select name,count | out-host

Write-host "Results can be found here $reportpath\reportADGroupGrowth.csv" 
$groups | export-csv "$reportpath\reportADGroupGrowth.csv" -NoTypeInformation
