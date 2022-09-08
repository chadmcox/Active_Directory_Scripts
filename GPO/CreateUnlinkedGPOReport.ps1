<#PSScriptInfo
.VERSION 0.1
.GUID e43c69e5-23f3-4b18-8abc-ada3f3973605
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
.TAGS AD GPO Unused gplink GroupPolicy
.LICENSEURI 
.PROJECTURI 
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
0.1 First go around of the script
.PRIVATEDATA 
#>

#Requires -Module ActiveDirectory
#Requires -Module GroupPolicy
#Requires -version 3.0
#Requires -RunAsAdministrator

<# 
.DESCRIPTION 
 Creates report about Active Directory Stale Computer Objects 
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


function IsNotLinked($xmldata){ 
    If ($xmldata.GPO.LinksTo -eq $null) { 
        Return $true 
    } 
    Return $false 
} 

$unlinkedGPOs = @()
$default_log = "$reportpath\report_UnlinkedGPOs.csv"
If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}
$hash_domain = @{name='Domain';expression={$domain}}
$i = 0
$progress_total = ((get-adforest).domains).count

Foreach($domain in (get-adforest).domains)
    {$i++
    $domain
    Get-GPO -All -domain $domain  | ForEach {
        Write-Progress -Activity "Gathering GPOs" -Status "Reviewing For GPOs In: $($_.DisplayName)" -PercentComplete ($I/$progress_total*100)
        $gpo = $_ ; $_ | Get-GPOReport -ReportType xml -domain $domain | ForEach {
            If(IsNotLinked([xml]$_)){$unlinkedGPOs += $gpo} }
    }
}
$unlinkedGPOs | select DomainName,DisplayName,Owner,Id,GpoStatus,Description,CreationTime,ModificationTime | export-csv $default_log -NoTypeInformation
cls
Write-Progress -Activity "Gathering GPOs" -Status "End" -Completed
write-host -ForegroundColor Green "Found $($unlinkedGPOs.count) Unlinked GPO's"
write-host "Review the results file can be located here: $default_log"
write-host ""
Write-host -ForegroundColor yellow "Run the following to clean up the unused GPO's:"
write-host "--------------------------------------------------------------------------------------"
write-host 'import-csv'"$default_log"'| foreach{$og = ($_).id; $domain = ($_).domainname
get-gpo -guid $og -domain $domain | remove-gpo -domain $domain} 
#consider testing with -whatif at the end of the remove-adobject'
write-host "--------------------------------------------------------------------------------------"
