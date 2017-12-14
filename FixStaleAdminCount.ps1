
<#PSScriptInfo

.VERSION 0.1

.GUID f46faf8e-6b30-480e-891a-26aeb3937d73

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

.TAGS Active Directory PowerShell

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
 This script will take a csv file of a domain, gpo and group or user samaccountname and remove that permission from the gpo. 

#> 
Param($report = "$env:userprofile\Documents\ADCleanUpReports\Users\report_ADUserswithStaleAdminCount.csv")

$hash_domain = @{name='Domain';expression={$domain}}

If (!($(Try { Test-Path $report } Catch { $true }))){
    write-host "report not found in location: $report"
    Write-host "if hasnt been done already run the following to generate the report of users with stale admin count"
    Write-host "https://raw.githubusercontent.com/chadmcox/ADPoSh/master/CreateADUserCleanUpReports.ps1"
}else{
    $last_domain = $null
    import-csv $report | foreach{ $domain = $_.domain
        if($_.Domain -ne $last_domain){
            $last_domain = $_.Domain
            get-PSDrive -Name ADROOT -ErrorAction SilentlyContinue | Remove-PSDrive -force
            New-PSDrive -Name ADROOT -PSProvider ActiveDirectory -Server $_.domain -Scope Global -root "//RootDSE/"
        }

        get-aduser $_.distinguishedname -server $_.domain | set-aduser -Remove @{admincount=1} -server $_.domain
        $user = "ADROOT:\$(($_).distinguishedname)"
        $SourceACL = Get-ACL -Path $user
        $SourceACL.SetAccessRuleProtection($False,$True)
        Set-Acl -Path $user -AclObject $SourceACL
        get-aduser $_.distinguishedname -Properties admincount -server $_.domain | select $hash_domain, distinguishedname, admincount
    }
}
