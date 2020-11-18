#Requires -Modules activedirectory
<#PSScriptInfo

.VERSION 2020.11.18

.GUID 4b43aafd-97d0-44e4-95e6-d2b129c5b449

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

.DESCRIPTION 
 This script will gather last time a group's membership has changed.  This data is formulated from the msDS-ReplValueMetaData. 

#> 
Param($reportpath = "$env:userprofile\Documents")

function retrieveOUInventory{
    param($domain, $dn)
    get-adobject -Filter * -searchbase $dn -SearchScope OneLevel -server $domain | group objectclass | select @{name='Container';expression={$dn}}, name, count
}

$hash_domain = @{name='Domain';expression={$domain}}

$lists = get-adforest | select -ExpandProperty domains -pv domain | foreach{
    get-adobject -server $domain -ldapFilter "(|(objectclass=organizationalunit)(objectclass=domainDNS)(objectclass=builtinDomain))" -Properties "msds-approx-immed-subordinates" | select $hash_domain, DistinguishedName
    (get-addomain $domain).UsersContainer | Get-ADObject -server $domain | select $hash_domain, DistinguishedName
}

$lists | foreach{
    retrieveOUInventory -domain $_.domain -dn $_.distinguishedname
} | export-csv "$reportpath\ouobjectsummary.csv" -NoTypeInformation

write-host "Complete"
