<#PSScriptInfo
.VERSION 0.3
.GUID bafabea1-77fa-4507-aa57-1acc77fb9b9c
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
.TAGS Active Directory PowerShell Get-GPO Group Policy get-gppermissions
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
#Requires -Module GroupPolicy
#Requires -version 3.0
#Requires -RunAsAdministrator
<# 
.DESCRIPTION 
 This script gets all gpo's in a forest and reports on the permissions. 
https://technet.microsoft.com/en-us/library/ee461018.aspx
Two reports one shows all the gpo's and the acl being applied.
Other is report with gpo and any instance of a unresolved sid.
#> 
Param($reportpath = "$env:userprofile\Documents")

#Creating a Report Path
$reportpath = "$reportpath\ADCleanUpReports"
If (!($(Try { Test-Path $reportpath } Catch { $true }))){
    new-Item $reportpath -ItemType "directory"  -force
}
$reportpath = "$reportpath\GroupPolicies"
If (!($(Try { Test-Path $reportpath } Catch { $true }))){
    new-Item $reportpath -ItemType "directory"  -force
}

#report Name
$default_log = "$reportpath\report_GroupPolicyPermissions.csv"
$default_log2 = "$reportpath\report_GroupPolicywithUnresolvedSidAcl.csv"
$unresolvedsid_results = @()
$results = @()
foreach($domain in (get-adforest).domains){
    (Get-GPO -all -domain $domain).DisplayName | foreach{$gpo = $_
        Get-GPPermissions -Name $_ -All -DomainName $domain | foreach{
        if($_.trustee.sidtype -eq "Unknown"){
        $unresolvedsid_results += $_ | select `
            @{name='Domain';expression={$domain}},`
            @{name='GPO';expression={$gpo}},`
            @{name='TrusteeSid';expression={$_.trustee.Sid}}
        }
        $results += $_ | select `
        @{name='Domain';expression={$domain}},`
        @{name='GPO';expression={$gpo}},`
        @{name='Trustee';expression={$_.trustee.name}}, `
        @{name='TrusteeDomain';expression={$_.trustee.Domain}}, `
        @{name='TrusteeSid';expression={$_.trustee.Sid}}, `
        Denied,Inherited,Permission
        }
    }
}

$unresolvedsid_results | export-csv $default_log2 -NoTypeInformation
$results | export-csv $default_log -NoTypeInformation
cls
write-host -foregroundcolor yellow "To view results run: import-csv $default_log2 | out-gridview "
write-host "GPO has ACL with Sid that does not resolve. Consider removing Sid acl from GPO. Found: $(($unresolvedsid_results | select GPO -unique | measure).count)"
write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview "
write-host "Unique GPO Count $(($results | select GPO -unique | measure).count)"
write-host "Breakdown of Trustee, review and consider replacing users with groups that manage GPO's"
$results | group trustee | select name, count | out-host
