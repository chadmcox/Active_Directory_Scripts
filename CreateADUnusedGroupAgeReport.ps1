
<#PSScriptInfo

.VERSION 0.2

.GUID 8cc222be-d143-4b38-a8c0-ba25df4e1db1

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

.TAGS AD AdminCount Groups

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
0.1 First go around of the script
0.2 rewrite

.PRIVATEDATA 

#>

#Requires -Module ActiveDirectory
#Requires -version 4
<# 

.DESCRIPTION 
 Collects Unused Groups in the forest, the last version of this script did a poor job
 @ excluding default groups.  This is filtering out any group with a rid lower than 1000.
 The search filter makes sure to only look for groups that are not a member or has members.
 Then it filters out groups with data in msDS-ReplValueMetaData.  this is a forsure way
 to know if a group has ever been used.  make sure to consider ignoring any groups
 in the users or builting containers just in case
#> 
Param($reportpath = "$env:userprofile\Documents")

$default_log = "$reportpath\report_StaleADGroups.csv"
If ($(Try { Test-Path $_default_log} Catch { $false })){Remove-Item $_default_log -force}
$groups = @()

#region hash calculated properties
#creating hash tables for each calculated property
$hash_domain = @{name='Domain';expression={$domain}}
$hash_ageindays = @{name='AgeinDays';expression={(new-TimeSpan($($_.whencreated)) $(Get-Date)).days}}
$hash_rid = @{name='Rid';expression={[int]($_.objectsid -split("-"))[7]}}
$hash_parentou = @{name='ParentOU';expression={`
    $($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}}
$hash_whencreated = @{Name="whencreated";
    Expression={($_.whencreated).ToString('MM/dd/yyyy')}}
#endregion

foreach($domain in (get-adforest).domains){
    $groups += get-adgroup -LDAPFilter "(&(!(member=*))(!(memberof=*)))" `
            -Properties "msDS-ReplValueMetaData",whencreated,groupscope,groupcategory, `
                objectSid,description,managedby -server $domain | `
        where {(!($_."msDS-ReplValueMetaData"))} | `
        select $hash_domain,samaccountname,groupcategory,groupscope,$hash_whencreated,`
            $hash_ageindays,isCriticalSystemObject,$hash_rid,$hash_parentou,description,managedby | `
            where {$_.Rid -gt 1000 -and $_.parentou -notlike "*CN=Users,DC=*" -and $_.parentou `
            -notlike "*OU=Microsoft Exchange Security Groups,DC=*"} 
}

$groups | export-csv $default_log -NoTypeInformation

cls
write-host "Report Can be found here $default_log"
write-host -foregroundcolor yellow "Found $($groups.count) not ever used"
write-host "--------------------------------------------------------------------------------------"
write-host "Group Count by Age:"
$groups | group AgeinDays | select name, count -First 10| sort count -Descending
