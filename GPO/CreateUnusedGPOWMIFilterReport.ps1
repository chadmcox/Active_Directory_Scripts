<#PSScriptInfo
.VERSION 0.2
.GUID ec2cec5b-b9b1-4fc3-9097-c341487b6115
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
.TAGS AD Computer
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

<# 
.DESCRIPTION 
 This script gets all ad computers that does not have a spn and not windows 
#> 
Param($defaultlog = "$env:userprofile\Documents\report_unused_wmifilters.csv")


#this hashtable is used to create a calculated property to display domain of the computer
$hash_domain = @{Name="Domain";
    Expression={$domain}}

$unlinked_results = @()

foreach($domain in (get-adforest).domains){
    $gpo_wmi_count = (get-gpo -all).WmiFilter | select name 
    Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' `
        -Properties "msWMI-Name","msWMI-Parm1","msWMI-Parm2",whenCreated,whenChanged -server $domain -PipelineVariable wmi_filter | `
            foreach{
                $unlinked_results += $wmi_filter | select $hash_domain,"msWMI-Name","msWMI-Parm2",whenCreated,whenChanged, `
                @{Name="Linked"; Expression={if($gpo_wmi_count | where name -eq $wmi_filter."msWMI-Name"){$true}else{$false}}},`
                DistinguishedName,ObjectGUID
    }
}

cls
$unlinked_results | export-csv $defaultlog -NoTypeInformation
write-host ""
write-host "Found $(($unlinked_results | where Linked -eq $false | group "msWMI-Name"| select Count).count) unused GPO WMI Filters"
write-host "Default log can be found here $defaultlog"
write-host  ""
write-host "--------------------------------------------------------------------------------------"
write-host -foreground yellow "Open the csv in excel and sort based on the column headers."
write-host -foreground yellow  "*sort on the linked column find and delete any of the unused GPO WMI filters"
write-host ""
write-host "-------------------Script Sample------------------------------------------------------"
write-host 'import-csv'"$defaultlog"' | where linked -eq $false | foreach{$og = ($_).objectguid; 
get-adobject -filter {objectguid -eq $og} -Server ($_).domain | remove-adobject} 
#consider testing with -whatif at the end of the remove-adobject'
write-host "--------------------------------------------------------------------------------------"
