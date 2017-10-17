
<#PSScriptInfo

.VERSION 0.1

.GUID 8dcf0383-c2a2-4105-996e-c582302c0361

.AUTHOR Chad.Cox@microsoft.com
    https://blogs.technet.microsoft.com/chadcox/

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

.TAGS AD Computer User ConflictObjects CNF 0ACNF

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
#Requires -version 4.0
<# 

.DESCRIPTION 
 This script creates a report for conflict objects that exist in Active Directory.
 At the end of the script is the guidance on how to use the file as the input 
 and the cmdlet syntax to run in order to delete the conflict objects found

#> 
Param($reportpath = "$env:userprofile\Documents")


#conflict objects
$default_log = "$reportpath\report_conflict_objects.csv"
If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}
$i = 0
$progress_total = ((get-adforest).domains).count
$searched_namingContexts = @();$conflict_objects = @()
$hash_domain = @{name='Domain';expression={$domain}}
$hash_NamingContext = @{name='NamingContext';expression={$naming_context}}

Foreach($domain in (get-adforest).domains)
{
    $i++
    get-adrootdse -Server $domain |select -ExpandProperty namingContexts | foreach {
        Write-Progress -Activity "Searching for Conflict Objects" `
            -Status "Searching In Domain: $domain NamingContext: $($_)" -PercentComplete ($I/$progress_total*100)
        if(!($searched_namingContexts -match $_)){ #has the partition already been scanned ie schema, configuration, and forestdnszone
            $searched_namingContexts += $_; $naming_context = $_
            write-debug "Scanning $($_) in $domain"
            $conflict_objects += Get-ADObject -LDAPFilter "(|(cn=*\0ACNF:*)(ou=*CNF:*))" -Properties whenchanged `
				-searchbase $naming_context -server $domain |`
                 Select-Object $hash_domain,$hash_NamingContext,Name,DistinguishedName,WhenChanged,ObjectGUID
        }
    }
}

cls
$conflict_objects | export-csv $default_log -NoTypeInformation
Write-Progress -Activity "Searching for Conflict Objects" -Status "End" -Completed

write-host -ForegroundColor Green "Found $($conflict_objects.count) Conflict Objects"
write-host "Review the results file can be located here: $default_log"
write-host ""
Write-host -ForegroundColor yellow "Run the following to clean up the conflict objects:"
write-host "--------------------------------------------------------------------------------------"
write-host 'import-csv'"$default_log"'| foreach{$og = ($_).objectguid; 
get-adobject -filter {objectguid -eq $og} -Server ($_).domain -searchbase ($_).namingcontext | remove-adobject} 
#consider testing with -whatif at the end of the remove-adobject'
write-host "--------------------------------------------------------------------------------------"
