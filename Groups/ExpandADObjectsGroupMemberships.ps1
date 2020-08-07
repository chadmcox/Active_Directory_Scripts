#Requires -Module ActiveDirectory
#Requires -version 4
<#PSScriptInfo
.VERSION 2020.7.20
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
.description
this enumerates all of the groups and 
#>

function expandgpmem{
    [cmdletbinding()]
    param($dn)
    write-information "Expanding $dn" 
    if(!($script:alreadyexplored.containskey($dn))){
        write-information "Not Searched Yet: $dn" 
        if($hash_group_membership.containskey($dn)){
            write-information "Is a member: $dn" 
            $script:alreadyexplored.add($dn,$null)
            foreach($mem in $hash_group_membership[$dn].parent){
                $mem | select @{name='object';expression={$object}}, `
                @{name='memberof';expression={$mem}}
                if(!($script:alreadyexplored.ContainsKey($mem))){
                    expandgpmem -dn $mem
                }
            }
        }
    }

}


cd "$env:userprofile\Documents"
get-adforest | select -ExpandProperty domains -pv domain | foreach{
    write-host "Dumping Groups Members from $domain"
    get-adgroup -LDAPFilter "(|(member=*)(memberof=*))" -property member -server $domain -pv group -ErrorAction SilentlyContinue | select -ExpandProperty member -pv member | select `
        @{name='child';expression={$member}}, `
        @{name='parent';expression={$group.distinguishedname}}
} | export-csv .\gpmem.tmp -NoTypeInformation

Write-Host "Creating Hash Table for lookup"
$hash_group_membership = import-csv .\gpmem.tmp | group child -AsHashTable -AsString

remove-item .\expandedmembership.csv -force -ErrorAction SilentlyContinue

foreach($object in ($hash_group_membership).keys){
    write-host "Enumerating: $object"
    $script:alreadyexplored = @{}
    expandgpmem -dn $object | export-csv .\expandedmembership.csv -Append -NoTypeInformation
}

import-csv .\expandedmembership.csv | group object | select name, count | export-csv ".\adObjectMemberofCount.csv" -NoTypeInformation
