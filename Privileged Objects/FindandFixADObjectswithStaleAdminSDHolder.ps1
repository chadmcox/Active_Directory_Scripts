
<#PSScriptInfo

.VERSION 0.3

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
    0.3 Only runs the clean up if it finds stale admin count objects.
        Error handling and log if the fix portion fails.
    0.2 Added query to find all the users and groups
        created report only option

.PRIVATEDATA 

#>

#Requires -Module ActiveDirectory
#Requires -version 4.0
#Requires -RunAsAdministrator

<# 

.DESCRIPTION 
 This script will take a csv file of a domain, gpo and group or user samaccountname and remove that permission from the gpo. 
.EXAMPLE
    To create just the report of stale objects without fixing them run
    .\FindandFixStaleAdminCount.ps1 -reportonly
#> 
Param($reportpath = "$env:userprofile\Documents",[switch]$reportonly)

$orphan_log = "$reportpath\report_ADObjectswithStaleAdminCount.csv"
$default_log = "$reportpath\report_ADObjectsMembersofPrivilegedGroups.csv"
$default_err_log = $reportpath + '\err_log.txt'

Function ADObjectswithStaleAdminCount{
    #users_with_admincount
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADObjectswithStaleAdminCount"
        
        #users with stale admin count
        $results = @();$orphan_results = @();$non_orphan_results  = @()
        $flagged_object = foreach($domain in (get-adforest).domains)
            {get-adobject -filter 'admincount -eq 1 -and iscriticalsystemobject -notlike "*"' `
                    -server $domain `
                    -properties whenchanged,whencreated,admincount,isCriticalSystemObject,"msDS-ReplAttributeMetaData",samaccountname |`
                select @{name='Domain';expression={$domain}},distinguishedname,whenchanged,whencreated,admincount,`
                    SamAccountName,objectclass,isCriticalSystemObject,@{name='adminCountDate';expression={($_ | `
                        Select-Object -ExpandProperty "msDS-ReplAttributeMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_ATTR_META_DATA |`
                        where { $_.pszAttributeName -eq "admincount"}}).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}}}
        $default_admin_groups = foreach($domain in (get-adforest).domains){get-adgroup -filter 'admincount -eq 1 -and iscriticalsystemobject -like "*"'`
                    -server $domain | select @{name='Domain';expression={$domain}},distinguishedname}
        foreach($object in $flagged_object){
            $udn = ($object).distinguishedname
            $results = foreach($group in $default_admin_groups){
                $object | select `
                    @{Name="Group_Domain";Expression={$group.domain}},`
                    @{Name="Group_Distinguishedname";Expression={$group.distinguishedname}},`
                    @{Name="Member";Expression={if(Get-ADgroup -Filter {member -RecursiveMatch $udn} -searchbase $group.distinguishedname -server $group.domain){$True}else{$False}}},`
                    domain,distinguishedname,admincount,adminCountDate,whencreated,objectclass
            }
            if($results | where {$_.member -eq $True}){
                $non_orphan_results += $results | where {$_.member -eq $True}
            }else{
                #$results | select Domain,objectclass,admincount,adminCountDate,distinguishedname | get-unique
                $orphan_results += $results  | select Domain,objectclass,admincount,adminCountDate,distinguishedname | get-unique
            }
        }
        $non_orphan_results  | export-csv $default_log -NoTypeInformation
        $orphan_results | export-csv $orphan_log -NoTypeInformation
        if($orphan_results){
            write-host "Found $(($orphan_results | measure).count) user object that are no longer a member of a priviledged group but still has admincount attribute set to 1"
            write-host "and inheritance disabled."
            $orphan_results | group objectclass | select name,count | Out-Host
            if(!($reportonly)){
                FixStaleAdminCount
            }
        }else{
            write-host "Found 0 Objects with Stale Admin Count"
        }
    }
}

function FixStaleAdminCount{
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function FixStaleAdminCount"
        If (!($(Try { Test-Path $orphan_log } Catch { $true }))){
            write-host "report not found in location: $orphan_log"
        }else{
            $last_domain = $null
            import-csv $orphan_log | foreach{ $domain = $_.domain
                if($_.Domain -ne $last_domain){
                    $last_domain = $_.Domain
                    get-PSDrive -Name ADROOT -ErrorAction SilentlyContinue | Remove-PSDrive -force
                    New-PSDrive -Name ADROOT -PSProvider ActiveDirectory -Server $_.domain -Scope Global -root "//RootDSE/"
                }

                try{get-adobject $_.distinguishedname -server $_.domain | set-adobject -Remove @{admincount=1} -server $_.domain}
                    catch{"Failed Changing AdminCount on $($_.distinguishedname)" | out-file $default_err_log -append
                            $_.Exception| out-file $default_err_log -append }
                $user = "ADROOT:\$(($_).distinguishedname)"
                $SourceACL = Get-ACL -Path $user
                $SourceACL.SetAccessRuleProtection($False,$True)
                try{Set-Acl -Path $user -AclObject $SourceACL}
                    catch{"Failed Changing ACL on $($_.distinguishedname)" | out-file $default_err_log -append
                            $_.Exception| out-file $default_err_log -append}
                
            }
        }
    }
}

$hash_domain = @{name='Domain';expression={$domain}}

ADObjectswithStaleAdminCount
