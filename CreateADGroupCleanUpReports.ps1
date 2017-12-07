
<#PSScriptInfo

.VERSION 0.1

.GUID 5e7bfd24-88b8-4e4d-99fd-c4ffbfcf5be6

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

.TAGS AD Groups

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
 Creates reports about Active Directory Groups 

#> 
Param($reportpath = "$env:userprofile\Documents")

#change current path to the report path
cd $reportpath


function ADPrivilegedGroupsWithSidHistory{
    [cmdletbinding()]
    param()
    process{
        
        write-host "Starting Function ADPrivilegedGroupsWithSidHistory"
        $default_log = "$reportpath\report_ADPrivilegedGroupsWithSidHistory.csv"
        $results = @()
        
        foreach($domain in (get-adforest).domains){
            $results += get-adgroup -filter 'admincount -eq 1 -and iscriticalsystemobject -like "*" -and sIDHistory -like "*"' `
                 -server $domain -properties samaccountname,Name,groupscope,groupcategory,admincount,iscriticalsystemobject,whencreated,whenchanged,description,managedby | `
                 select $hash_domain,samaccountname,Name,groupscope,groupcategory,admincount,iscriticalsystemobject,whencreated,whenchanged,description,managedby,$hash_parentou,distinguishedname
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) Builtin Critical Groups with Sid History."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview "
        }
    }
}
function ADGroupsWithNoMembers{
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADGroupsWithNoMembers"
        $default_log = "$reportpath\report_ADGroupsWithNoMembers.csv"
        $results = @()
        
        foreach($domain in (get-adforest).domains){
            $results += get-adgroup -LDAPFilter "(!(member=*))" `
                 -server $domain -properties samaccountname,Name,groupscope,groupcategory,admincount,`
                 iscriticalsystemobject,whencreated,whenchanged,description,managedby,objectSid | `
                 select $hash_domain,samaccountname,Name,groupscope,groupcategory,admincount,`
                    iscriticalsystemobject,whencreated,whenchanged,description,managedby,$hash_rid,$hash_parentou,distinguishedname | `
                where {$_.Rid -gt 1000}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) Groups currently with no members."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview "
        }
    }
}
function ADGroupsWithCircularNesting{
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADGroupsWithCircularNesting"
        $default_log = "$reportpath\report_ADGroupsWithCircularNesting.csv"
        $results = @(); $groups = @()
        $script:searched_groups = @()
        $script:nested_groups = @()
        $script:expanded_groups = @()
        foreach($domain in (get-adforest).domains){
            get-adgroup -LDAPFilter "(|(member=*)(memberof=*))" `
                 -server $domain -properties memberof | `
                  select $hash_domain,distinguishedname,memberof | foreach{
            $gdn = ($_).DistinguishedName
            $groups += ($_).DistinguishedName 
            if($_.memberof){
                    $_ | Select-Object -ExpandProperty Memberof | foreach {
                        $objtmp = new-object -type psobject
                            $objtmp | Add-Member -MemberType NoteProperty -Name "group" -Value $gdn
                            $objtmp | Add-Member -MemberType NoteProperty -Name "memberof" -Value $_
                         $script:expanded_groups += $objtmp
                    }
                }
            }
        }

        $groups | foreach {
            if(!($script:searched_groups -contains $_)){
                expand-adgroup -groupDN $_ -originalDN $_
            }
        }
        
        $script:nested_groups | export-csv  $default_log -NoTypeInformation

        if($script:nested_groups){
            write-host "Found $(($script:nested_groups | measure).count) Groups currently with circular group nesting. Remove group from the memberof listed.`
             User memberships will not be affected as this is a duplicate link."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview "
        }
    }
}
function expand-adgroup{
    param($groupDN,$originalDN)

    #Links I used to make this
    #http://blogs.msdn.com/b/adpowershell/archive/2009/09/05/token-bloat-troubleshooting-by-analyzing-group-nesting-in-ad.aspx
    #http://www.powershellmagazine.com/2013/11/26/identifying-active-directory-built-in-groups-with-powershell/
    #http://blogs.technet.com/b/heyscriptingguy/archive/2010/07/22/hey-scripting-guy-how-can-i-use-windows-powershell-2-0-to-find-active-directory-domain-services-groups-not-being-used.aspx
    #had a heck of a time with isCriticalSystemObject
    #http://www.jhouseconsulting.com/2015/01/02/script-to-create-an-overview-and-full-report-of-all-group-objects-in-a-domain-1455
    #nice article around powershell parameter validation
    #http://blogs.technet.com/b/heyscriptingguy/archive/2011/05/15/simplify-your-powershell-script-with-parameter-validation.aspx

    Process{
        #write-debug $groupDN
        $script:searched_groups += $groupDN
        #filter where group is same as groupdn loop through all group member of
        $script:expanded_groups | Foreach {
            if($_.group -eq $groupDN){
                #is the parent group 
                #write-debug "member $(($_).memberof)"
                if($script:searched_groups -contains $_.memberof){
                    if(!($script:identified_group -contains $_.group)){
                        #write-debug $True
                        #group already searched
                        if($_.memberof -eq $originalDN){
                            $script:nested_groups += $_
                            $script:identified_group += $_.group
                        }
                    }
                }else{
                    expand-adgroup -groupDN $_.memberof -originalDN $originalDN
                }   
            }        
        }
    }
}
function ADGroupsWithSIDHistoryFromSameDomain{
    [cmdletbinding()]
    param()
    process{
        #https://adsecurity.org/?p=1772
        write-host "Starting Function ADUsersWithSIDHistoryFromSameDomain"
        $default_log = "$reportpath\report_ADUsersWithSIDHistoryFromSameDomain.csv"
        $results = @()
        #Find groups with sid history from same domain
        foreach($domain in (get-adforest).domains){
            [string]$Domain_SID = ((Get-ADDomain $domain).DomainSID.Value)
            $results += Get-ADGroup -Filter {SIDHistory -Like '*'} -server $domain `
                -properties samaccountname,Name,groupscope,groupcategory,admincount,`
                 iscriticalsystemobject,whencreated,whenchanged,description,managedby,SIDHistory | `
                Where { $_.SIDHistory -Like "$domain_sid-*"} | `
                    select $hash_domain,samaccountname,Name,groupscope,groupcategory,admincount,`
                    iscriticalsystemobject,whencreated,whenchanged,description,managedby,$hash_parentou,distinguishedname
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) group object with sidhistory from the same domain."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview "
        }
    }
}
function ADGroupsWithStaleAdminCount{
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADUserswithStaleAdminCount"
        $orphan_log = "$reportpath\report_ADGroupswithStaleAdminCount.csv"
        $default_log = "$reportpath\report_ADGroupsMembersofPrivilegedGroups.csv"
        #groups with stale admin count
        $results = @();$orphan_results = @();$non_orphan_results  = @()
        $flagged_groups = foreach($domain in (get-adforest).domains)
            {get-adgroup -filter 'admincount -eq 1 -and iscriticalsystemobject -notlike "*"' `
                    -server $domain `
                    -properties whenchanged,whencreated,admincount,isCriticalSystemObject,"msDS-ReplAttributeMetaData",samaccountname,managedby,description |`
                select @{name='Domain';expression={$domain}},distinguishedname,whenchanged,whencreated,admincount,managedby,description,`
                    SamAccountName,objectclass,isCriticalSystemObject,@{name='adminCountDate';expression={($_ | `
                        Select-Object -ExpandProperty "msDS-ReplAttributeMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_ATTR_META_DATA |`
                        where { $_.pszAttributeName -eq "admincount"}}).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}}}
        $default_admin_groups = foreach($domain in (get-adforest).domains){get-adgroup -filter 'admincount -eq 1 -and iscriticalsystemobject -like "*"'`
                    -server $domain | select @{name='Domain';expression={$domain}},distinguishedname}
        foreach($grp in $flagged_groups){
            $gdn = ($grp).distinguishedname
            $results = foreach($group in $default_admin_groups){
                $gdn
                $grp | select `
                    @{Name="Group_Domain";Expression={$group.domain}},`
                    @{Name="Group_Distinguishedname";Expression={$group.distinguishedname}},`
                    @{Name="Member";Expression={if(Get-ADgroup -Filter {member -RecursiveMatch $gdn} -searchbase $group.distinguishedname -server $group.domain){$True}else{$False}}},`
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
            write-host "Found $(($orphan_results | measure).count) group object that are no longer a member of a priviledged group but still has admincount attribute set to 1"
            write-host "and inheritance disabled."
            write-host -foregroundcolor yellow "To view results run: import-csv $orphan_log | out-gridview"
        }
    }
}
function ADGroupsNeverUsed{
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADGroupsNeverUsed"
        $default_log = "$reportpath\report_ADGroupsNeverUsed.csv"
        $results = @()
        foreach($domain in (get-adforest).domains){
            $results += get-adgroup -LDAPFilter "(&(!(member=*))(!(memberof=*)))" `
                -Properties "msDS-ReplValueMetaData",whencreated,groupscope,groupcategory,description,managedby,objectSid -server $domain | `
                where {(!($_."msDS-ReplValueMetaData"))} | `
                select $hash_domain,name,samaccountname,groupcategory,groupscope,whencreated,`
                    $hash_ageindays,isCriticalSystemObject,description,managedby,$hash_rid,$hash_parentou,distinguishedname |`
                where {$_.Rid -gt 1000} 

}
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) Groups not ever used."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview "
        }
    }
}
function ADGroupswithMembershipLastChange{
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADGroupswithMembershipLastChange"
        $default_log = "$reportpath\report_ADGroupswithMembershipLastChange.csv"
        $results = @()
        foreach($domain in (get-adforest).domains){
            $results += get-adgroup -LDAPFilter "(&(member=*)(!(IsCriticalSystemObject=TRUE)))" `
                -Properties "msDS-ReplValueMetaData",samaccountname,GroupCategory,GroupScope,"msDS-ReplValueMetaData",`
                    WhenCreated,WhenChanged,description,managedby,objectSid,admincount -server $domain | `
                select $hash_domain,name,samaccountname,groupcategory,groupscope,whencreated,$hash_lastmemchange,`
                    isCriticalSystemObject,admincount,description,managedby,$hash_parentou,distinguishedname 

        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            write-host "Found $(($results | measure).count) Groups with members."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview "
        }
    }
}

#region hash calculated properties
$hash_domain = @{name='Domain';expression={$domain}}
$hash_parentou = @{name='ParentOU';expression={`
    $($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}}
$hash_rid = @{name='Rid';expression={[int]($_.objectsid -split("-"))[7]}}
$hash_ageindays = @{name='AgeinDays';expression={(new-TimeSpan($($_.whencreated)) $(Get-Date)).days}}
$hash_lastmemchange = @{name='MembershipLastChanged';expression={($_ | Select-Object -ExpandProperty "msDS-ReplValueMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_VALUE_META_DATA | where { $_.pszAttributeName -eq "member" }}| select -first 1).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}}
#endregion

cls
ADPrivilegedGroupsWithSidHistory
ADGroupsWithNoMembers
ADGroupsWithCircularNesting
ADGroupsWithSIDHistoryFromSameDomain
ADGroupsWithStaleAdminCount
ADGroupsNeverUsed
ADGroupswithMembershipLastChange
