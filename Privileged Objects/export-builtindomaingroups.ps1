#Requires -Module ActiveDirectory
<#PSScriptInfo
.VERSION 2020.6.18
.GUID 43c7362f-d300-4bf9-a481-622b67e43137
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

#>
param($export_file = "$env:userprofile\documents\domain_builtin_group_export.csv")
#retrieve all of the critical and builtin groups
$privileged_groups = get-adforest | select -ExpandProperty domains -PipelineVariable domain | foreach{
    get-adgroup -filter 'admincount -eq 1 -and iscriticalsystemobject -notlike "*"' `
        -server $domain -Properties distinguishedname,SamAccountName,member  | select @{n='Domain';e={$domain}},distinguishedname,SamAccountName,member
    get-adgroup -filter '(admincount -eq 1 -and iscriticalsystemobject -like "*") -or samaccountname -eq "Cert Publishers"' `
        -server $domain -Properties distinguishedname,SamAccountName,member  | select @{n='Domain';e={$domain}},distinguishedname,SamAccountName,member
    get-adgroup -filter 'samaccountname -eq "Schema Admins" -or samaccountname -eq "Group Policy Creator Owners" -or samaccountname -eq "Key Admins" -or samaccountname -eq "Enterprise Key Admins" -or samaccountname -eq "Remote Desktop Users" -or samaccountname -eq "Cryptographic Operators"' `
        -server $domain -Properties distinguishedname,SamAccountName,member  | select @{n='Domain';e={$domain}},distinguishedname,SamAccountName,member
    get-adgroup -filter '(iscriticalsystemobject -like "*") -and (samaccountname -ne "Domain Users") -and (samaccountname -ne "Users") -and (samaccountname -ne "Domain Controllers") -and (samaccountname -ne "Domain Computers")' `
        -server $domain -Properties distinguishedname,SamAccountName,member  | select @{n='Domain';e={$domain}},distinguishedname,SamAccountName,member
} | select domain,distinguishedname,SamAccountName,member -Unique

#Im only using the Get-ADGroupMember because these groups should have low numbers of members.  wont use this for larger enumeration
#places a huge strain on domain controller and only returns a subset of members.
$privileged_groups | foreach{$group = $_; Get-ADGroupMember -Identity $_.distinguishedname -Server $_.domain -Recursive | where objectclass -eq "user" | `
    get-adobject -server "$((get-addomain).PDCEmulator):3268" -property * | select @{n='Domain';e={$group.Domain}},@{n='Group';e={$group.samaccountname}}, `
        samaccountname, displayname, userprincipalname, company, objectclass} | export-csv $export_file -NoTypeInformation
