
<#PSScriptInfo

.VERSION 0.1

.GUID 50ac366f-b562-4974-94b4-851ed9acf896

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

.TAGS msonline PowerShell get-adobject get-adorganizationalunit

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
#Requires -version 3.0
#Requires -RunAsAdministrator

<# 

.DESCRIPTION 
 This script is will gather useful information around ad objects including cleanup task.  This script
 will gather unused OU's by using the msds-approx-immed-subordinates attribute.

 -whatif will need to be removed in order to delete the objects
#> 
Param($reportpath = "$env:userprofile\Documents",
[switch]$DeleteUnused)
cls
function CollectADEmptyOUs{
    [cmdletbinding()]
    param()
    process{
        $results = @()
        foreach($domain in (get-adforest).domains){
            try{$results += Get-ADorganizationalunit -filter * -Properties "msds-approx-immed-subordinates", `
                gplink,description,whencreated,whenchanged `
                -server $domain | select $hash_domain, *}
            catch{"CollectADOUs - $domain - $($_.Exception)"}

            if($DeleteUnused){
                foreach($ou in ($results | where {$_."msds-approx-immed-subordinates" -eq 0})){
                    DeleteOU -ou $ou.distinguishedname -domain $ou.domain
                }
            }
            $results | where {$_."msds-approx-immed-subordinates" -eq 0} | select `
            domain,name,$hash_subordinates,$hash_gplink,$hash_whenchanged,$hash_whencreated, `
                description,distinguishedname
        }
    }
}
function DeleteOU{
    [cmdletbinding()]
    param($ou,$domain)
    process{
        Remove-ADOrganizationalUnit $ou -Server $domain -whatif
    }
}
#region hashes
$hash_domain = @{name='Domain';expression={$domain}}
$hash_whenchanged = @{Name="whenchanged";
    Expression={($_.whenchanged).ToString('MM/dd/yyyy')}}
$hash_whencreated = @{Name="whencreated";
    Expression={($_.whencreated).ToString('MM/dd/yyyy')}}
$hash_gplink = @{Name="GPLink";
    Expression={if($_.gplink){$true}}}
$hash_subordinates = @{name='DirectChildObjectCount';expression={$_."msds-approx-immed-subordinates"}}
#endregion

$emptyous = CollectADEmptyOUs

$emptyous | export-csv $("$reportpath\reportEmptyOUs.csv") -NoTypeInformation
write-host "$($emptyous.count) Empty OU's can be found here: $("$reportpath\reportEmptyOUs.csv")
Run this to see results: import-csv $("$reportpath\reportEmptyOUs.csv") | out-gridview"
