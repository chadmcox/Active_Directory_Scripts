#Requires -Modules activedirectory
#requires -version 3.0
<#PSScriptInfo

.VERSION 0.2

.GUID 368e7248-347a-46d9-ba35-3ae42890daed

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
 Use this script to create a list of groups with foreign security principals.  if a FSP is not resolvable then the membership needs to be removed. 

#> 
Param($reportpath = "$env:userprofile\Documents")
cd $reportpath
$default_log = "$reportpath\reportDomainLocalGroupswithOrphanFSP.csv"
$results = @()
#region hashes
$hash_domain = @{name='Domain';expression={$domain}}
$hash_member = @{name='Member';expression={$member}}
$hash_resolved = @{name='MemberObjectClass';expression={$resolve.objectclass}}
$hash_translate = @{name='MemberTranslated';expression={$fsp_translate}}
$hash_trustexist = @{name='TrustExist';expression={if($trusted_domain_SIDs -like $domain_sid){$True}}}
#endregion
function CollectDLGroupOrphanFSP{
    $trusted_domain_SIDs = @()
    $groups = @()
    foreach($domain in (get-adforest).domains){
        write-host "Querying $domain for Domain Local Groups"
        $trusted_domain_SIDs += (get-adtrust -filter {intraforest -eq $false} `
            -Properties securityIdentifier -server $domain).securityIdentifier.value
        $groups += get-adgroup -LDAPFilter "(&(groupType:1.2.840.113556.1.4.803:=4)(member=*))" `
            -Properties member -Server $domain -ResultPageSize 500 -ResultSetSize $null | select `
            $hash_domain, samaccountname, distinguishedname,GroupCategory,GroupScope, member
    
    }
    Write-host "Building Report"
    foreach($group in $groups){
        foreach($member in ($group).member){
            $resolve = try{get-adobject $member -server $group.domain}catch{$null}
            if($resolve.objectclass -eq "foreignSecurityPrincipal"){
                if($resolve.Name -match "^S-\d-\d+-\d+-\d+-\d+-\d+"){$domain_sid = $matches[0]}else{$domain_sid = $null}
                $fsp_translate = try{([System.Security.Principal.SecurityIdentifier] $resolve.Name).Translate([System.Security.Principal.NTAccount])}catch{"Orphan"}
                $group | select domain,samaccountname,GroupCategory,GroupScope,$hash_member,$hash_resolved,$hash_translate, `
                $hash_trustexist | where {$_.MemberTranslated -eq "Orphan"}
    }}}
}

cls
$results = CollectDLGroupOrphanFSP
$results | export-csv $default_log -NoTypeInformation
write-host "Results are found here $default_log"
write-host "Review the results and remove any orphan foreign Security Principal from the group as they are not being used."
