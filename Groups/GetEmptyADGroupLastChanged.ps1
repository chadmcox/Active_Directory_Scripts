<#PSScriptInfo
.VERSION 0.1
.GUID 7cd13fef-ab13-4d14-a703-07f05ccac7c3
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
#>

#Requires -Module activedirectory

<# 
.DESCRIPTION 
 This group will be used to find groups with no memberships but have been used in the past and display the date they were last used. 
#> 
Param()


function CollectADGroupnoMemLastChange{
    $GroupProperties = @("samaccountname","DisplayName","groupscope","groupcategory","admincount","iscriticalsystemobject", `
                        "whencreated","mail","msDS-ReplValueMetaData","objectSid","ProtectedFromAccidentalDeletion", `
                        "distinguishedname")
    $Select_properties = $GroupProperties + $hash_domain
    $results = @()
    foreach($domain in (get-adforest).domains){
        $results += get-adgroup `
            -LDAPFilter "(&(!(member=*))(!(IsCriticalSystemObject=TRUE))(groupType:1.2.840.113556.1.4.803:=2147483648))" `
            -Properties $GroupProperties  `
            -Server $domain -ResultPageSize 500 -ResultSetSize $null | Select $Select_properties | `
                where {($_."msDS-ReplValueMetaData")}
    }
    $results | select domain,samaccountname,displayname,groupscope,groupcategory,mail,admincount, `
        $hash_rid,$hash_whencreated,$hash_memlastchange,ProtectedFromAccidentalDeletion,$hash_parentou | `
            where {$_.Rid -gt 1000 -and $_.parentou -notlike "*CN=Users,DC=*" -and $_.parentou `
            -notlike "*OU=Microsoft Exchange Security Groups,DC=*"} 
}

cls

#region hashes
$hash_memlastchange = @{name='MembershipLastChanged';
        expression={if($_."msDS-ReplValueMetaData"){($_ | Select-Object -ExpandProperty "msDS-ReplValueMetaData" | 
            foreach {([XML]$_.Replace("`0","")).DS_REPL_VALUE_META_DATA | where { $_.pszAttributeName -eq "member" }} | 
            select -first 1).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}else{"Never Used"}}}
$hash_rid = @{name='Rid';expression={$([int]($_.objectsid -split("-"))[7])}}
$hash_domain = @{name='Domain';expression={$domain}}
$hash_whencreated = @{Name="whencreated";
        Expression={($_.whencreated).ToString('MM/dd/yyyy')}}
$hash_parentou = @{name='ParentOU';expression={
        $($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}} 
#endregion

#get last group Membership Change for Groups with no members
$groupnone = @()
$groupnone = CollectADGroupnoMemLastChange

Write-host "Number of Groups With No Members Last Modified by Year"
$groupnone | select @{Name="whencreated";Expression={(get-date($_.whencreated)).ToString('yyyy')}} | group whencreated | `
    sort name | select Name, Count | out-host
$groupnone | export-csv "$reportpath\reportEmptyADGroupMemLastChanged.csv" -NoTypeInformation
write-host "Results can be found here: $reportpath\reportEmptyADGroupMemLastChanged.csv"
