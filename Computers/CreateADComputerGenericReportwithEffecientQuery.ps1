
<#PSScriptInfo

.VERSION 0.1

.GUID 73469c83-3fa5-4f08-83d3-dbb62c81a5ed

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

.TAGS Active Directory PowerShell Get-adcomputer searchbase searchscope

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
 This script modifies and object in the configuration container and watches update on all domain controllers. Then creaes a final report. 

#> 
Param($reportpath = "$env:userprofile\Documents")
cd $reportpath
$default_log = "$reportpath\report_generic_ad_computer_info.csv"
$results = @()
$hash_domain = @{name='Domain';expression={$domain}}
$hash_parentou = @{name='ParentOU';expression={`
    $($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}}
foreach($domain in (get-adforest).domains){
    foreach($object_location in (Get-adobject -ldapFilter "(|(objectclass=organizationalunit)(objectclass=container))"`
         -server $domain | where {$_.DistinguishedName -NotLike "*CN=System,DC*"}).DistinguishedName){
       $results += get-adcomputer -Filter {(isCriticalSystemObject -eq $False)} `
            -Properties ipv4address,dnshostname,operatingsystem,enabled `
             -server $domain -searchbase $object_location -SearchScope OneLevel | `
        select $hash_domain,name,dnshostname,ipv4address,enabled,operatingsystem,$hash_parentou 
    }
}

$results | export-csv $default_log -notypeinformation

write-host "Found $($results.count) Computer Objects"
write-host "Report Can be found here $default_log"
