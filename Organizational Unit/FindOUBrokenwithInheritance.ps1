#Requires -Module ActiveDirectory
#Requires -Version 4
<#PSScriptInfo

.VERSION 0.1

.GUID 28a1bbb8-3871-4b22-82cf-70383231a1a9

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
param($reportpath = "$env:userprofile\Documents")
$results = @()
$hash_domain = @{name='Domain';expression={$domain}}
$hash_inheritance = @{name='InheritanceBroken';expression={$_.nTSecurityDescriptor.AreAccessRulesProtected}}
foreach($domain in (get-adforest).domains){
    Write-host "Gathering OU's from $domain"
    try{$results += Get-ADObject -ldapFilter "(objectclass=organizationalunit)" `
            -Properties "msds-approx-immed-subordinates",nTSecurityDescriptor -server $domain -ResultPageSize 500 -ResultSetSize $null |`
            where {$_."msds-approx-immed-subordinates" -ne 0} | select `
            $hash_domain, DistinguishedName,$hash_inheritance
    }catch{}
}

$results | export-csv "$reportpath\OUInheritanceStatus.csv" -NoTypeInformation
write-host "Found $(($results | where {$_.InheritanceBroken -eq $true} | Measure-object).count) OU's with Broken Inheritance"