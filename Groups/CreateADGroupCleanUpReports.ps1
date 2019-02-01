#Requires -Module ActiveDirectory
#Requires -version 3.0
#Requires -RunAsAdministrator

<#PSScriptInfo

.VERSION 0.VERSION 0.15

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

.RELEASENOTES
0.15 created new report that shows last changed from meta data for groups that only have
    users as members
0.14 cleanup of reports created new report that contains details.
0.13 cleaned up dates
0.12 move the circular nesting check to be the last thing ran.  was causing a timeout.
0.11 had to make functions global also added direct member count
0.10 put in option to just import script so only certain functions can be ran
0.9 Search for objects in root level of domain
0.8 Added ou by ou search scope to make impact against dc better.
0.1 First go around of the script


.DESCRIPTION 
 Creates reports about Active Directory Groups



#> 
Param($reportpath = "$env:userprofile\Documents",[switch]$importfunctionsonly)

$reportpath = "$reportpath\ADCleanUpReports"
If (!($(Try { Test-Path $reportpath } Catch { $true }))){
    new-Item $reportpath -ItemType "directory"  -force
}

If (!($(Try { Test-Path "$reportpath\Groups"} Catch { $true }))){
    new-Item "$reportpath\Groups" -ItemType "directory"  -force
}

#change current path to the report path
cd $reportpath
$script:ous = @()
$script:finished = @()
$singleuse_group = $false

function GroupDisplayFunctionResults{
    if($singleuse_group){$script:finished
                write-host "Report Can be found here $reportpath"
                $script:finished = @()
    }
}
Function ADOUList{
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADOUList"
        $script:ou_list = "$reportpath\Groups\ADOUList.csv"
        try{Get-ChildItem $script:ou_list | Where-Object { $_.LastWriteTime -lt $((Get-Date).AddDays(-10))} | Remove-Item -force}catch{}

        If (!(Test-Path $script:ou_list)){
            foreach($domain in (get-adforest).domains){
                try{Get-ADObject -ldapFilter "(|(objectclass=organizationalunit)(objectclass=domainDNS)(objectclass=builtinDomain))" `
                    -Properties "msds-approx-immed-subordinates" -server $domain | where {$_."msds-approx-immed-subordinates" -ne 0} | select `
                     $hash_domain, DistinguishedName  | export-csv $script:ou_list -append -NoTypeInformation}
                catch{"function ADOUList - $domain - $($_.Exception)" | out-file $default_err_log -append}
                try{(get-addomain $domain).UsersContainer | Get-ADObject -server $domain | select `
                     $hash_domain, DistinguishedName | export-csv $script:ou_list -append -NoTypeInformation}
                catch{"function ADOUList - $domain - $($_.Exception)" | out-file $default_err_log -append}
            }
        }

        $script:ous = import-csv $script:ou_list
    }
}
function ADPrivilegedGroupsWithSidHistory{
    [cmdletbinding()]
    param()
    process{
        $function_list += "ADPrivilegedGroupsWithSidHistory"
        write-host "Starting Function ADPrivilegedGroupsWithSidHistory"
        $default_log = "$reportpath\Groups\report_ADPrivilegedGroupsWithSidHistory.csv"
        $results = @()
        
        #Find Users with sid history from same domain
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            $results += get-adgroup -filter 'admincount -eq 1 -and iscriticalsystemobject -like "*" -and sIDHistory -like "*"' `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain `
                 -properties samaccountname,Name,groupscope,groupcategory,admincount,iscriticalsystemobject, `
                    whencreated,whenchanged | `
                 select $hash_domain,samaccountname,groupscope,groupcategory,admincount,iscriticalsystemobject,`
                    $hash_whenchanged,$hash_whencreated,$hash_parentou
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            $script:finished += "Groups that are Builtin Critical Groups with Sid History: $(($results | measure).count)"
            GroupDisplayFunctionResults
        }
    }
}
function ADGroupsWithNoMembers{
    [cmdletbinding()]
    param()
    process{
        $function_list += "ADGroupsWithNoMembers"
        write-host "Starting Function ADGroupsWithNoMembers"
        $default_log = "$reportpath\Groups\report_ADGroupsWithNoMembers.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            $results += get-adgroup -LDAPFilter "(&(!(member=*))(!(IsCriticalSystemObject=TRUE)))" `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain `
                 -properties samaccountname,Name,groupscope,groupcategory,admincount,`
                 iscriticalsystemobject,whencreated,whenchanged,objectSid | `
                 select $hash_domain,samaccountname,groupscope,groupcategory,admincount,`
                    iscriticalsystemobject,$hash_whencreated,$hash_whenchanged,`
                    @{name='Rid';expression={[int]($_.objectsid -split("-"))[7]}},`
                    $hash_parentou,distinguishedname | `
                where {$_.Rid -gt 1000}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            $script:finished += "Groups with no members: $(($results | measure).count)"
            GroupDisplayFunctionResults
        }
    }
}
function ADGroupsWithCircularNesting{
    [cmdletbinding()]
    param()
    process{
        $function_list += "ADGroupsWithCircularNesting"
        write-host "Starting Function ADGroupsWithCircularNesting"
        $default_log = "$reportpath\Groups\report_ADGroupsWithCircularNesting.csv"
        $expanded_groups_log = "$reportpath\Groups\report_ADGroupsMemberof.csv"
        If ($(Try { Test-Path $expanded_groups_log} Catch { $false })){Remove-Item $expanded_groups_log -force}
        $script:full_expanded_groups_log = "$reportpath\Groups\report_ADGroupsFullExpanded.csv"
        If ($(Try { Test-Path $script:full_expanded_groups_log} Catch { $false })){Remove-Item $script:full_expanded_groups_log -force}
        $results = @(); $groups = @()
        $script:searched_groups = @()
        $script:nested_groups = @()
        $script:expanded_groups = @()
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
                get-adgroup -LDAPFilter "(|(member=*)(memberof=*))" `
                     -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain `
                     -properties memberof | `
                        select $hash_domain,distinguishedname,memberof | foreach{
                $gdn = ($_).DistinguishedName
                $groups += ($_).DistinguishedName 
                if($_.memberof){
                        $_ | Select-Object -ExpandProperty Memberof | foreach {
                            $objtmp = new-object -type psobject
                                $objtmp | Add-Member -MemberType NoteProperty -Name "group" -Value $gdn
                                $objtmp | Add-Member -MemberType NoteProperty -Name "memberof" -Value $_
                              $objtmp | export-csv $expanded_groups_log -Append -NoTypeInformation
                        }
                    }
                }
            }
        
        #kicking off a different function to create a report of groups that only have user members
        CreateCleanADGroupMemlastChange
        write-host "Continueing Function ADGroupsWithCircularNesting"
        $script:expanded_groups = import-csv $expanded_groups_log

        $groups | foreach {
            if(!($script:searched_groups -contains $_)){
                expand-adgroup -groupDN $_ -originalDN $_
            }
        }
        
        $script:nested_groups | export-csv  $default_log -NoTypeInformation

        if($script:nested_groups){
            $script:finished += "Groups currently with circular group nesting. Remove group from the memberof listed.`
             User memberships will not be affected as this is a duplicate link.: $(($script:nested_groups | measure).count)"
            GroupDisplayFunctionResults
        }
    }
}
function expand-adgroup{
    param($groupDN,$originalDN,[switch]$expand)

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
                    if($expand){
                        $script:expanded_groups += $_ | select @{Name="group";Expression={$originalDN}},memberof
                        expand-adgroup -groupDN $_.memberof -originalDN $originalDN -expand
                    }else{
                        expand-adgroup -groupDN $_.memberof -originalDN $originalDN}
                }   
            }        
        }
    }
}
function ADGroupsWithSIDHistoryFromSameDomain{
    [cmdletbinding()]
    param()
    process{
        $function_list += "ADGroupsWithSIDHistoryFromSameDomain"
        #https://adsecurity.org/?p=1772
        write-host "Starting Function ADGroupsWithSIDHistoryFromSameDomain"
        $default_log = "$reportpath\Groups\report_ADGroupsWithSIDHistoryFromSameDomain.csv"
        $results = @()
        #Find groups with sid history from same domain
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            [string]$Domain_SID = ((Get-ADDomain $domain).DomainSID.Value)
            $results += Get-ADGroup -Filter {SIDHistory -Like '*'} `
                -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain `
                -properties samaccountname,Name,groupscope,groupcategory,admincount,`
                 iscriticalsystemobject,whencreated,whenchanged,description,managedby,SIDHistory | `
                Where { $_.SIDHistory -Like "$domain_sid-*"} | `
                    select $hash_domain,samaccountname,groupscope,groupcategory,admincount,`
                    iscriticalsystemobject,$hash_whencreated,$hash_whenchanged,description,managedby,$hash_parentou
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            $script:finished += "Groups with sidhistory from the same domain: $(($results | measure).count)"
            GroupDisplayFunctionResults
        }
    }
}
function ADGroupsWithStaleAdminCount{
    [cmdletbinding()]
    param()
    process{
        $function_list += "ADGroupsWithStaleAdminCount"
        write-host "Starting Function ADGroupswithStaleAdminCount"
        $orphan_log = "$reportpath\Groups\report_ADGroupswithStaleAdminCount.csv"
        $default_log = "$reportpath\Groups\report_ADGroupsMembersofPrivilegedGroups.csv"
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
            $results = @()
            foreach($group in $default_admin_groups){
                
             $results += $grp | select `
                    @{Name="Group_Domain";Expression={$group.domain}},`
                    @{Name="Group_Distinguishedname";Expression={$group.distinguishedname}},`
                    @{Name="Member";Expression={if(Get-ADgroup -Filter {member -RecursiveMatch $gdn} -searchbase $group.distinguishedname -server $group.domain){$True}else{$False}}},`
                    domain,distinguishedname,admincount,adminCountDate,whencreated,objectclass
            }
            if($results | where {$_.member -eq $True}){
                $non_orphan_results += $results | where {$_.member -eq $True}
            }else{
                $results | select Domain,objectclass,admincount,adminCountDate,distinguishedname | get-unique
                $orphan_results += $results  | select Domain,objectclass,admincount,adminCountDate,distinguishedname | get-unique
            }
        }
        $non_orphan_results  | export-csv $default_log -NoTypeInformation
        $orphan_results | export-csv $orphan_log -NoTypeInformation
        if($orphan_results){
            $script:finished += "Groups no longer a member of a Protected Privileged Group but still has admincountset: $(($orphan_results | measure).count)"
            GroupDisplayFunctionResults
        }
    }
}
function ADGroupsNeverUsed{
    [cmdletbinding()]
    param()
    process{
        $function_list += "ADGroupsNeverUsed"
        write-host "Starting Function ADGroupsNeverUsed"
        $default_log = "$reportpath\Groups\report_ADGroupsNeverUsed.csv"
        $results = @()
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            $results += get-adgroup -LDAPFilter "(&(!(member=*))(!(memberof=*))(!(IsCriticalSystemObject=TRUE)))" `
                -Properties "msDS-ReplValueMetaData",whencreated,groupscope,groupcategory,description,managedby,objectSid `
                -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | `
                where {(!($_."msDS-ReplValueMetaData"))} | `
                select $hash_domain,name,samaccountname,groupcategory,groupscope,$hash_whencreated,`
                    @{name='AgeinDays';expression={(new-TimeSpan($($_.whencreated)) $(Get-Date)).days}},`
                    isCriticalSystemObject,description,managedby,`
                    @{name='Rid';expression={[int]($_.objectsid -split("-"))[7]}},`
                    $hash_parentou,distinguishedname |`
                where {$_.Rid -gt 1000} 

}
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            $script:finished += "Groups never used: $(($results | measure).count)"
            GroupDisplayFunctionResults
        }
    }
}
function ADGroupswhenMembershipsLastChange{
    [cmdletbinding()]
    param()
    process{
        $function_list += "ADGroupswhenMembershipsLastChange"
        write-host "Starting Function ADGroupswhenMembershipsLastChange"
        $default_log = "$reportpath\Groups\report_ADGroupswhenMembershipsLastChange.csv"
        $results = @()
        foreach($domain in (get-adforest).domains){
            foreach($object_location in (Get-adobject -ldapFilter "(|(objectclass=organizationalunit)(objectclass=container))"`
                -server $domain | where {$_.DistinguishedName -NotLike "*CN=System,DC*"}).DistinguishedName){
                $results += get-adgroup -LDAPFilter "(&(member=*)(!(IsCriticalSystemObject=TRUE)))" `
                    -Properties "msDS-ReplValueMetaData",samaccountname,GroupCategory,GroupScope,"msDS-ReplValueMetaData",`
                        WhenCreated,WhenChanged,objectSid,admincount -server $domain `
                -searchbase $object_location -SearchScope OneLevel | `
                    select $hash_domain,samaccountname,groupcategory,groupscope,$hash_whencreated,$hash_whenchanged,`
                        @{name='MembershipLastChanged';expression={[string]($_ | Select-Object -ExpandProperty "msDS-ReplValueMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_VALUE_META_DATA | where { $_.pszAttributeName -eq "member" }}| select -first 1).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}},`
                        isCriticalSystemObject,admincount,$hash_parentou,distinguishedname
            }
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            $script:finished += "Groups with Membership last changed date: $(($results | measure).count)"
            GroupDisplayFunctionResults
        }
    }
}
function ADGroupsAssignedbyAMACertificate{
    [cmdletbinding()]
    param()
    Process{
        $function_list += "ADGroupsAssignedbyAMACertificate"
        #Authentication Mechanism Assurance https://technet.microsoft.com/en-us/library/dd378897(v=ws.10).aspx
        #https://blogs.technet.microsoft.com/askds/2011/02/25/friday-mail-sack-no-redesign-edition/#amapki
        write-host "Starting Function ADGroupsAssignedbyAMACertificate"
        $default_log = "$reportpath\Groups\report_ADGroupsAssignedbyAMACertificate.csv"
        $results = @()
    
        $results = get-adobject -filter {objectclass -eq "msPKI-Enterprise-Oid"} -properties * `
                     -searchbase $((get-adrootdse).configurationnamingcontext) | `
                            where {($_."msDS-OIDToGroupLink")} | `
                        select DisplayName, msDS-OIDToGroupLink,$hash_whenChanged,$hash_whenCreated,DistinguishedName 
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            $script:finished += "Groups being used for authentication mechanism assuaraunce via msDS-OIDToGroupLink attribute of a certificate object: $(($results | measure).count)"
            GroupDisplayFunctionResults
        }
    }
}
function ADGroupswithPSOApplied{
    [cmdletbinding()]
    param()
    process{
        $function_list += "ADGroupwithPSOApplied"
        write-host "Starting Function ADGroupswithPSOApplied"
        $default_log = "$reportpath\Groups\report_ADGroupswithPSOApplied.csv"
        $results = @()
        foreach($domain in (get-adforest).domains){
            $results += get-adgroup -LDAPFilter "(msDS-PSOApplied=*)" `
                -Properties "msDS-PSOApplied",whencreated,groupscope,groupcategory, `
                    objectSid,isCriticalSystemObject -server $domain | `
                select $hash_domain,samaccountname,groupcategory,groupscope,$hash_whencreated,"msDS-PSOApplied",`
                    isCriticalSystemObject,$hash_parentou

        }
        $results | export-csv $default_log -NoTypeInformation
        if($results){
            $script:finished += "Groups assigned a with Fine Grained Password Policy: $(($results | measure).count)"
            GroupDisplayFunctionResults
        }
    }
}
Function ADGroupsFoundinRootofDomain{
[cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADGroupsFoundinRootofDomain"
        $default_log = "$reportpath\Groups\report_ADGroupsFoundinRootofDomain.csv"
        $results = @()
        foreach($domain in (get-adforest).domains){
            try{$results += Get-ADGroup -Filter * `
                -searchbase $((get-adobject -LDAPFilter '(objectclass=domainDNS)' -server $domain).distinguishedname) `
                    -SearchScope OneLevel -server $domain -Properties whencreated,samaccountname | `
                    Select $hash_domain,samaccountname, $hash_whencreated}
            catch{"function ADGroupsFoundinRootofDomain - $domain - $($_.Exception)" | out-file $default_err_log -append}     
        }
        
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            $script:finished += "Groups that exist in the root of the domain: $(($results | measure).count)"
            GroupDisplayFunctionResults
        }
    }
}
function ADGroupsWithNoDisplayName{
    [cmdletbinding()]
    param()
    process{
        #How to Use PowerShell to Fix Empty DisplayName Attributes for On-premises Mail-Enabled Groups
        #https://social.technet.microsoft.com/wiki/contents/articles/16728.how-to-use-powershell-to-fix-empty-displayname-attributes-for-on-premises-mail-enabled-groups.aspx
        #Fixing problems with directory synchronization for Office 365
        #https://support.office.com/en-us/article/Fixing-problems-with-directory-synchronization-for-Office-365-79c43023-5a47-45ae-8068-d8a26eee6bc2

        $function_list += "ADGroupsWithNoDisplayName"
        write-host "Starting Function ADGroupsWithNoDisplayName"
        $default_log = "$reportpath\Groups\report_ADGroupsWithNoDisplayName.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            $results += get-adgroup -LDAPFilter "(&(!(DisplayName=*))(!(IsCriticalSystemObject=TRUE)))" `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain `
                 -properties samaccountname,groupscope,groupcategory,admincount,`
                 iscriticalsystemobject,whencreated,whenchanged,description,managedby,objectSid | `
                 select $hash_domain,samaccountname,groupscope,groupcategory,admincount,`
                    iscriticalsystemobject,$hash_whencreated,$hash_whenchanged,`
                    @{name='Rid';expression={$([int]($_.objectsid -split("-"))[7])}},`
                    $hash_parentou | `
                where {$_.Rid -gt 1000}
        }
        $results | export-csv $default_log -NoTypeInformation

        if($results){
            $script:finished += "Groups with no Display Name: $(($results | measure).count)"
            GroupDisplayFunctionResults
        }
    }
}
Function ADGroupDetails{
    [cmdletbinding()]
    param()
    process{
        
        $function_list += "ADGroupsDetails"
        write-host "Starting Function ADGroupDetails"
        $default_log = "$reportpath\Groups\report_ADGroupsDetails.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            $results += get-adgroup -filter * `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain `
                 -properties description,managedby,Distinguishedname | `
                 select $hash_domain,samaccountname,Distinguishedname,description,managedby,`
                    $hash_parentou
        }
        $results | export-csv $default_log -NoTypeInformation

        
    }
}
function ADGroupsMemberCount{
    [cmdletbinding()]
    param()
    process{
        #How to Use PowerShell to Fix Empty DisplayName Attributes for On-premises Mail-Enabled Groups
        #https://social.technet.microsoft.com/wiki/contents/articles/16728.how-to-use-powershell-to-fix-empty-displayname-attributes-for-on-premises-mail-enabled-groups.aspx
        #Fixing problems with directory synchronization for Office 365
        #https://support.office.com/en-us/article/Fixing-problems-with-directory-synchronization-for-Office-365-79c43023-5a47-45ae-8068-d8a26eee6bc2

        $function_list += "ADGroupsWithNoDisplayName"
        write-host "Starting Function ADGroupsMemberCount"
        $default_log = "$reportpath\Groups\report_ADGroupsMemberCount.csv"
        $results = @()
        
        if(!($script:ous)){
            ADOUList
        }
        foreach($ou in $script:ous){$domain = ($ou).domain
            $results += get-adgroup -LDAPFilter "(&(member=*)(!(IsCriticalSystemObject=TRUE)))" `
                 -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain `
                 -properties samaccountname,groupscope,groupcategory,admincount,member,`
                 iscriticalsystemobject,whencreated,whenchanged,description,managedby,objectSid | `
                 select $hash_domain,samaccountname,groupscope,groupcategory,admincount,`
                    iscriticalsystemobject,$hash_whencreated,$hash_whenchanged,`
                    @{name='DirectMemberCount';expression={($_.Member).count}},`
                    $hash_parentou
        }
        $results | export-csv $default_log -NoTypeInformation
        $default_log = "$reportpath\groups\report_ADGroupsMembersover50k.csv"
        $results | select Domain,samaccountname,GroupCategory,GroupScope,DirectMemberCount,WhenChanged,WhenCreated,ParentOU | `
          where {($_.DirectMemberCount).toint32($null) -gt 50000} | export-csv $default_log -NoTypeInformation

        if($results){
            $script:finished += "Groups with Over 50K direct Members: $(($results | `
                where {($_.DirectMemberCount).toint32($null) -gt 50000} | measure).count)"
            GroupDisplayFunctionResults
        }
    }
}
Function CreateCleanADGroupMemlastChange{
[cmdletbinding()]
    param()
    process{
    #the goal of this is to only have groups that do not have any groups nested.  
        write-host "Starting Function CreateCleanADGroupMemlastChange"
        $groups_with_group_members = import-csv "$reportpath\Groups\report_ADGroupsMemberof.csv" | select Memberof -Unique
        $groups_with_last_change = import-csv "$reportpath\Groups\report_ADGroupswhenMembershipsLastChange.csv"
        $default_log = "$reportpath\Groups\report_ADGroupswithonlyusermemberslastchanged.csv"
        $results = @()
        foreach($grp in $groups_with_last_change){
            $found = $false
            
            foreach($grpwng in $groups_with_group_members){
                
                if(($grpwng).memberof -eq ($grp).distinguishedname){
                    
                    $found = $true
                    break
                }
            }
            if(!($found)){
                $results += $grp
            }
        }
            $results | export-csv $default_log -NoTypeInformation
    }
}
#region hash calculated properties
$hash_domain = @{name='Domain';expression={$domain}}
$hash_parentou = @{name='ParentOU';expression={`
    $($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}}
$hash_whenchanged = @{Name="whenchanged";
    Expression={($_.whenchanged).ToString('MM/dd/yyyy')}}
$hash_whencreated = @{Name="whencreated";
    Expression={($_.whencreated).ToString('MM/dd/yyyy')}}
#endregion

cls

if(!($importfunctionsonly)){
    $time_log = "$reportpath\groups\runtime.csv"
    (dir function: | where {$_.name -like "adgroup*" -and $_.name -ne "ADGroupsWithCircularNesting"} ).name | sort | foreach{$script_function = $_
        Measure-Command {Invoke-Expression -Command $script_function} | `
            select @{name='RunDate';expression={get-date -format d}},`
            @{name='Function';expression={$script_function}}, `
            @{name='Hours';expression={$_.hours}}, `
            @{name='Minutes';expression={$_.Minutes}}, `
            @{name='Seconds';expression={$_.Seconds}} | export-csv $time_log -append -notypeinformation
    }
    #this one takes the longest broke it out and have it running last
    Measure-Command {ADGroupsWithCircularNesting} | `
        select @{name='RunDate';expression={get-date -format d}},`
        @{name='Function';expression={"ADGroupsWithCircularNesting"}}, `
        @{name='Hours';expression={$_.hours}}, `
        @{name='Minutes';expression={$_.Minutes}}, `
        @{name='Seconds';expression={$_.Seconds}} | export-csv $time_log -append -notypeinformation
    
    $script:finished
    write-host "Report Can be found here $reportpath"
}else{
    $singleuse_group = $True
    write-host -foreground yellow "Type out the function and press enter to run a particular report"
    (dir function: | where name -like adgroup*).name
}
  
