
<#PSScriptInfo

.VERSION 0.2

.GUID bff8254c-d342-4d67-876e-378d5ba57447

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

.TAGS Active Directory PowerShell Foreign Security Principals

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
 0.2 fixed to make sure it enumerates each domain
    does a trust domain sid check to make sure trust is still valid
    removes builtin sids from report


.PRIVATEDATA 

#>

#Requires -Module ActiveDirectory

<# 

.DESCRIPTION 
 This script creates reports on foreign security principals. 

#> 

Param($reportpath = "$env:userprofile\Documents")

$hash_domain = @{name='Domain';expression={$domain}}
$results = @()
#translate Sid
Foreach($domain in (get-adforest).domains){
    $trusted_domain_SIDs = (get-adtrust -filter {intraforest -eq $false} -Properties securityIdentifier -server $domain).securityIdentifier.value
    Get-ADObject -Filter { objectClass -eq "foreignSecurityPrincipal" } -server $domain | ForEach {$fsp_translate = $null
        if($_.Name -match "^S-\d-\d+-\d+-\d+-\d+-\d+"){$domain_sid = $matches[0]}else{$domain_sid = $null}
        $fsp_translate = try{([System.Security.Principal.SecurityIdentifier] $_.Name).Translate([System.Security.Principal.NTAccount])}catch{"Orphan"}
	    $results += $_ | select $hash_domain,name, `
            @{name='Translate';expression={$fsp_translate}}, `
            @{name='TrustExist';expression={if($trusted_domain_SIDs -like $domain_sid){$True}}} | `
            where {$_.name -notmatch "^S-\d-\d+-(\d+)$"}
    }
}
$results | export-csv "$reportpath\report_ForeignSecurityPricipals.csv" -NoTypeInformation
$results = @()
#enumerate fsp members
Foreach($domain in (get-adforest).domains){
    Get-ADObject -Filter { objectClass -eq "foreignSecurityPrincipal" } -Properties memberof -server $domain -PipelineVariable fsp | select -ExpandProperty memberof | foreach{
        $group = $_
        $fsp_translate = try{([System.Security.Principal.SecurityIdentifier] $fsp.name).Translate([System.Security.Principal.NTAccount])}catch{"Orphan"}
        $results += $fsp | select $hash_domain,name, `
            @{name='Translate';expression={$fsp_translate}}, `
            @{name='Memberof';expression={$group}} | `
            where {$_.name -notmatch "^S-\d-\d+-(\d+)$"}
    }
}

$results | export-csv "$reportpath\report_ForeignSecurityPricipalsGroupMembership.csv" -NoTypeInformation
$results = @()
#translate Sid
Foreach($domain in (get-adforest).domains){
    $results += Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal" -and memberof -notlike "*"} -server $domain | ForEach-Object {$fsp_translate = $null
        $fsp_translate = try{([System.Security.Principal.SecurityIdentifier] $_.Name).Translate([System.Security.Principal.NTAccount])}catch{"Orphan"}
	    $_ | select $hash_domain,name, `
        @{name='Translate';expression={$fsp_translate}} | `
            where {$_.name -notmatch "^S-\d-\d+-(\d+)$"}
    }
}
$results | export-csv "$reportpath\report_ForeignSecurityPricipalsNoGroupMemberShips.csv" -NoTypeInformation
