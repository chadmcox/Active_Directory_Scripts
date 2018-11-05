#Requires -Module activedirectory
<#PSScriptInfo

.VERSION 0.5

.GUID 8ef10281-c133-4516-b937-f4e425ad254e

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
 this will populate all of the directs for an individual. 

#> 
Param($reportpath = "$env:userprofile\Documents")

#doing this to keep the initial run of the data into memory, so script can be ran multiple times.
Set-Variable hash_direct_results -Scope global

function buildADUserDirectshashtable{
    $users = @{}
    $enabledusers = @()
    
    foreach($domain in (get-adforest).domains){
        $userProperties = @("SamAccountName","DirectReports","displayname","mail","distinguishedname")
        $select_properties = $userProperties + $hash_domain
        write-information "getting adusers $domain"
        $enabledusers += get-aduser -ldapFilter "(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(IsCriticalSystemObject=TRUE)))" `
            -server $domain -Properties $userProperties | select $select_properties
    }
    $count = $enabledusers.count
    $enabledusers | foreach{
        $i++
        write-host "hashing $($_.displayname) remaing $($count - $i) / $count"
        $users += @{$_.distinguishedname = @{
            Domain = $_.domain
            DirectReports = @($_.directreports | foreach{@{direct=$_}})
            samaccountname = $_.samaccountname
            displayname = $_.displayname
            mail = $_.mail
        }}
    }
    
    $users
}
function expandadusersdirects{
    param($DNtoexpand,$displayname,$place,$original)
 $searched += $DNtoexpand
 write-information "Expanding $DNtoexpand"
 $results[$DNtoexpand] | select `
        @{name='OrgFor';expression={$original}}, `
        @{name='Level';expression={$place}}, `
        @{name='ReportsDirectlyTo';expression={$displayname}}, `
        @{name='Displayname';expression={$_.displayname}}, `
        @{name='Samaccountname';expression={$_.samaccountname}}, `
        @{name='Mail';expression={$_.mail}}, `
        @{name='domain';expression={$_.domain}}
    
    if(($results[$DNtoexpand]).directreports.values){
        ($results[$DNtoexpand]).directreports.values | foreach{
            if(!($searched -contains $_)){
                $i++
                expandadusersdirects -dntoexpand $_ -displayname ($results[$DNtoexpand]).displayname -original $original -place $i
            }
        }
    }
}
cls
Write-host -ForegroundColor yellow "Select the AD Report to run:"
Write-host "   0 - Get All Directs for Single User"
Write-host "   1 - Get All Direct Reports for Forest"
$xMenuChoiceA = read-host "Please enter an option 0 to 1..."

cls
$hash_domain = @{name='Domain';expression={$domain}}
if(!($hash_direct_results)){$hash_direct_results = @{}}
$directs = @()

if($xMenuChoiceA -eq 0){
    $found = @()
    $samaccountname = read-host -Prompt "Enter samaccountname"
    $found = foreach($domain in (get-adforest).domains){
        try{get-aduser $samaccountname -Properties directreports,displayname -server $domain `
            -ErrorAction SilentlyContinue}catch{}}
    if($found){
        if($hash_direct_results.count -lt 1){
            write-host "Building HashTable"
            measure-command{$hash_direct_results = buildADUserDirectshashtable} | select minutes,secounds}
        write-host "Building Direct Report"
        measure-command{foreach($direct in $found.directreports){
            $directs += expandadusersdirects -dntoexpand $direct -displayname $found.displayname -original $found.displayname -place 1
        }} | select minutes,secounds
            $directs | export-csv "$reportpath\$samaccountname Directreports.csv" -NoTypeInformation
            $directs | out-host
    }
}elseif($xMenuChoiceA -eq 1){
    if($hash_direct_results.count -lt 1){
        write-host "Building HashTable"
        measure-command{$hash_direct_results = buildADUserDirectshashtable} | select minutes,secounds}
        write-host "Building Direct Report"
    measure-command{
        foreach($key in $results.keys){
            if(($results[$key]).directreports.values){
                $searched = @()
                foreach($direct in $results[$key].directreports.values){
                $directs += expandadusersdirects -dntoexpand $direct -displayname $results[$key].displayname -original $results[$key].displayname -place 1
                }
            }
        }
    } | select minutes,secounds
    $directs | export-csv "$reportpath\AllADUsersDirectReportsExpanded.csv" -NoTypeInformation
    $directs | group OrgFor | select name,count | sort count -Descending | select -First 10 | out-host
}


write-host "All Reports found here: $reportpath"
