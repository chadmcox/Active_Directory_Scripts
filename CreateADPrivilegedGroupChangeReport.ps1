
<#PSScriptInfo

.VERSION 0.1

.GUID 43c7362f-d300-4bf9-a481-622b67e43137

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

.TAGS AD AdminCount Groups

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

<# 

.DESCRIPTION 
 Collects group member ship changes to enterprise admins, domain admins, 
 administrators and other privileged groups including ones nested

#> 
Param($reportpath = "$env:userprofile\Documents")


#https://blogs.technet.microsoft.com/pie/2014/08/25/metadata-2-the-ephemeral-admin-or-how-to-track-the-group-membership/
#https://blogs.technet.microsoft.com/ashleymcglone/2014/12/17/forensics-monitor-active-directory-privileged-groups-with-powershell/

$default_log = "$reportpath\report_privileged_group_changes.csv"
If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}

#region hash calculated properties
#creating hash tables for each calculated property
$hash_domain = @{name='Domain';expression={$domain}}
$hash_sam = @{name='Group';expression={$samaccountname}}
#endregion

$admincount_groups = @()
$privileged_groups = @()

#pulls back the major privileged groups, and all groups with admin count set
$admincount_groups = (get-adforest).domains | foreach{$domain = $_; get-adgroup `
            -filter 'admincount -eq 1 -and iscriticalsystemobject -notlike "*"' `
             -server $domain | select $hash_domain,distinguishedname,SamAccountName}
$privileged_groups = (get-adforest).domains | foreach{$domain = $_; get-adgroup `
            -filter 'admincount -eq 1 -and iscriticalsystemobject -like "*"' `
             -server $domain | select $hash_domain,distinguishedname,SamAccountName}

#creates a legit list of privileged groups, can easily add a else statement to report on groups with
#stale admin count

$privileged_groups | foreach{
    $privileged_group_domain = $_.domain
    $privileged_group_dn = $_.distinguishedname
    $admincount_groups | foreach{
        $admincount_group_dn = $_.distinguishedname
        if(Get-ADgroup -Filter {member -RecursiveMatch $admincount_group_dn} `
            -searchbase $privileged_group_dn -server $privileged_group_domain){
            $privileged_groups += $_
        } 
    }
}

#enumerate through the newest list of legit admincount groups, and pull back the replication metadata
#one addition is if a user's primary group membership is change to the group, it looks like the user
#was removed from the group.  I perform a check to validate

$privileged_groups | select * -Unique | sort domain | foreach{
    $distinguishedname = $_.distinguishedname
    $samaccountname = $_.samaccountname
    $domain = $_.domain
    Get-ADGroup $distinguishedname -Properties msDS-ReplValueMetaData,WhenChanged,SamAccountName -Server $domain `
            -PipelineVariable grp | Select-Object -ExpandProperty "msDS-ReplValueMetaData" |`
        foreach {
            $metadata = [XML]$_.Replace("`0","")
            ($metadata).DS_REPL_VALUE_META_DATA | where { $_.pszAttributeName -eq "member" } | foreach{
                    $_ | select $hash_domain,$hash_sam,`
                    @{name='ftimeLastOriginatingChange';expression={$_.ftimeLastOriginatingChange |  get-date -Format MM/dd/yyyy}}, `
                    @{name='Operation';expression={If($_.ftimeDeleted -ne "1601-01-01T00:00:00Z"){"Removed"}Else{"Added"}}}, `
                    pszAttributeName,pszObjectDn,dwVersion,`
                    @{name='ChangedtoPrimaryGroup';expression={If(Get-ADuser -Identity $($_.pszObjectDn)`
                         -Properties primaryGroupId -server "$($domain):3268" | `
                            where {$_.primaryGroupId -eq ($grp | % {$_.sid.tostring().split("-")[7]})}){$true}else{$false}}} ,`
                    ftimeDeleted,ftimeCreated |`
                     export-csv $default_log -append -NoTypeInformation
        }
    }
}
