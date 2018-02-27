
<#PSScriptInfo

.VERSION 0.1

.GUID 2b08616d-89b0-4cd7-8869-eab34eb97e47

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

.TAGS msonline PowerShell get-adobject get-acl

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
 this script will get the extended rights set on the root of each domain. 

#> 
Param($reportpath = "$env:userprofile\Documents",[switch]$importfunctionsonly)

$default_log = "$reportpath\report_Domain_acl.csv"
If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}

    $er = "cn=extended-rights,$((get-adrootdse).configurationnamingcontext)"
    $repextendedrights = get-adobject -filter * -SearchBase $er -Properties * 

Foreach($domain in (get-adforest).domains){
    try{get-PSDrive -Name ADROOT -ErrorAction SilentlyContinue | Remove-PSDrive -force}catch{}
    New-PSDrive -Name ADROOT -PSProvider ActiveDirectory -Server $domain -Scope Global -root "//RootDSE/"
    $rootdn = "ADROOT:\" + ($domain | get-addomain).DistinguishedName
    foreach($right in $repextendedrights){
        $rootacls = (Get-ACL $rootdn).access 
        foreach($rootacl in $rootacls){
            if ($rootacl.ObjectType -like $right.rightsGuid){
                
                $rootacl | select `
                    @{name='Domain';expression={$domain}},`
                    @{name='IdentityReference';expression={$rootacl.IdentityReference}},`
                    @{name='ExtendedRight';expression={$right.name}},`
                    @{name='Expected';expression={$expected}},AccessControlType | export-csv $default_log -append -NoTypeInformation
                
            }   
        }
    
    }
    try{Remove-PSDrive -Name ADROOT -Force}catch{}
}


