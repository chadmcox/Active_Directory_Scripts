#Requires -Module ActiveDirectory
#Requires -version 3.0
#Requires -RunAsAdministrator

<#PSScriptInfo

.VERSION 0.1

.GUID 5e7bfd24-88b8-4e4d-99fd-c4ffbfcf5be6

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

.RELEASENOTES

.DESCRIPTION 
 this is to help descover Objects with this exploit
 https://support.microsoft.com/en-us/help/4490425/updates-to-tgt-delegation-across-incoming-trusts-in-windows-server

#> 
Param($reportpath = "$env:userprofile\Documents")
$trust = @()
$objects = @()

$SERVER_TRUST_ACCOUNT = 0x2000  
$TRUSTED_FOR_DELEGATION = 0x80000  
$TRUSTED_TO_AUTH_FOR_DELEGATION= 0x1000000  
$PARTIAL_SECRETS_ACCOUNT = 0x4000000
$bitmask = $TRUSTED_FOR_DELEGATION -bor $TRUSTED_TO_AUTH_FOR_DELEGATION -bor $PARTIAL_SECRETS_ACCOUNT 

$filter = @"  
(& 
  (servicePrincipalname=*) 
  (| 
    (msDS-AllowedToActOnBehalfOfOtherIdentity=*) 
    (msDS-AllowedToDelegateTo=*) 
    (UserAccountControl:1.2.840.113556.1.4.804:=$bitmask) 
  ) 
  (| 
    (objectcategory=computer) 
    (objectcategory=person) 
    (objectcategory=msDS-GroupManagedServiceAccount) 
    (objectcategory=msDS-ManagedServiceAccount) 
  ) 
) 
"@ -replace "[\s\n]", ''  

$propertylist = @(  
        "servicePrincipalname",   
        "useraccountcontrol",   
        "samaccountname",   
        "msDS-AllowedToDelegateTo",   
        "msDS-AllowedToActOnBehalfOfOtherIdentity"  
    ) 

$hash_isDC = @{name='isDC';expression={($account.useraccountcontrol -band $SERVER_TRUST_ACCOUNT) -ne 0}} 
$hash_fullDelegation = @{name='fullDelegation';expression={($account.useraccountcontrol -band $TRUSTED_FOR_DELEGATION) -ne 0}} 
$hash_constrainedDelegation = @{name='constrainedDelegation';expression={($account.'msDS-AllowedToDelegateTo').count -gt 0}}  
$hash_isRODC = @{name='isRODC';expression={($account.useraccountcontrol -band $PARTIAL_SECRETS_ACCOUNT) -ne 0}}
$hash_resourceDelegation = @{name='resourceDelegation';expression={$account.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null}}
$hash_domain = @{name='Domain';expression={$domain}}

foreach($domain in (get-adforest).domains){
    write-host "Scanning $domain"
    $trust += get-adtrust -filter {TGTDelegation -eq $false} `
        -server $domain | select 

    $objects += Get-ADObject -LDAPFilter $filter -SearchScope Subtree `
        -Properties $propertylist -Server $domain -PipelineVariable account | select `
        $hash_domain, samaccountname, objectclass, $hash_isDC,$hash_isRODC, $hash_fullDelegation, `
        $hash_constrainedDelegation,$hash_resourceDelegation 
}

$trust_count = ($trust | Measure-Object).count
$obj_count = ($objects | where {($_.isDC -eq $false) -and ($_.isRODC -eq $false) -and ($_.fullDelegation -eq $true)} | measure-object).count

Write-host "Trust Found: $trust_count" -ForegroundColor Yellow
Write-host "Objects with Full Delegation Found: $obj_count" -ForegroundColor Yellow

Write-host "Files can be found here $reportpath  * _at_risk.csv"

$trust | export-csv "$reportpath\trust_at_risk.csv" -NoTypeInformation
$objects | export-csv "$reportpath\objects_at_risk.csv" -NoTypeInformation
