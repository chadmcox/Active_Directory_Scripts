#Requires -Module ActiveDirectory
#Requires -version 3.0
#Requires -RunAsAdministrator

<#PSScriptInfo
.VERSION 0.2
.GUID 5e7bfd24-88b8-4e4d-87fd-c4ffbfcf5be6
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
0.1
.DESCRIPTION 
 Creates reports about Active Directory Groups
 
#> 
Param($path = "$env:userprofile\Documents")

$reportpath = "$path\ADGroupCleanUpReports"
If (!($(Try { Test-Path $reportpath } Catch { $true }))){
    new-Item $reportpath -ItemType "directory"  -force
}

$start_time = get-date

function gatherEmptyADGroups{
    [cmdletbinding()]
    param()
    write-host "Gathering All AD Groups with no members"
    $Group_Properties = @("samaccountname","DisplayName","groupscope","groupcategory","admincount","iscriticalsystemobject", `
                        "whencreated","whenchanged","mail","msDS-ReplValueMetaData","objectSid","ProtectedFromAccidentalDeletion", `
                        "distinguishedname")
    $Select_properties = $Group_Properties + $hash_domain + $hash_parentou

    $results = get-adforest | select -ExpandProperty domains -PipelineVariable domain | foreach{Get-ADOrganizationalUnit `
        -filter * -properties "msds-approx-immed-subordinates" -server $domain -PipelineVariable ou | `
            where {$_."msds-approx-immed-subordinates" -ne 0} | foreach{
                get-adgroup -LDAPFilter "(&(!(member=*))(!(IsCriticalSystemObject=TRUE))(groupType:1.2.840.113556.1.4.803:=2147483648))" `
                    -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain `
                    -properties $Group_Properties | select $Select_properties
            }
    }

    $results | select domain,samaccountname,DisplayName, `
        groupscope,groupcategory,admincount,mail,$hash_whencreated,$hash_whenchanged,$hash_memlastchange, `
        ProtectedFromAccidentalDeletion,$hash_rid,ParentOU | where {$_.Rid -gt 1000 -and $_.parentou -notlike "*CN=Users,DC=*" -and $_.parentou `
            -notlike "*OU=Microsoft Exchange Security Groups,DC=*" -and $_.MembershipLastChanged -like "*"}
}
function gatherPopulatedADGroups{
    [cmdletbinding()]
    param()
    $Group_Properties = @("samaccountname","DisplayName","groupscope","groupcategory","admincount","iscriticalsystemobject", `
                        "whencreated","whenchanged","mail","msDS-ReplValueMetaData","objectSid","ProtectedFromAccidentalDeletion", `
                        "distinguishedname")
    $Select_properties = $Group_Properties + $hash_domain + $hash_parentou

    write-host "Gathering All AD Groups with members"
    $results = get-adforest | select -ExpandProperty domains -PipelineVariable domain | foreach{Get-ADOrganizationalUnit `
        -filter * -properties "msds-approx-immed-subordinates" -server $domain -PipelineVariable ou | `
            where {$_."msds-approx-immed-subordinates" -ne 0} | foreach{
                get-adgroup -LDAPFilter "(&(!(IsCriticalSystemObject=TRUE))(groupType:1.2.840.113556.1.4.803:=2147483648)(member=*))" `
                    -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain `
                    -properties $Group_Properties | select $Select_properties
            }
    }
    $results | select domain,samaccountname,DisplayName, `
    groupscope,groupcategory,admincount,mail,$hash_groupasmember,$hash_whencreated,$hash_whenchanged,$hash_memlastchange, `
    ProtectedFromAccidentalDeletion,$hash_rid,ParentOU | where {$_.Rid -gt 1000 -and $_.parentou -notlike "*CN=Users,DC=*" -and $_.parentou `
            -notlike "*OU=Microsoft Exchange Security Groups,DC=*" -and $_.MembershipLastChanged -like "*"}
}
function dumpADGroupMemberof{
    [cmdletbinding()]
    param()
    $Group_Properties = @("distinguishedname","memberof")
    $Select_properties = $Group_Properties

    write-host "Gathering All AD Groups with memberof"
    get-adforest | select -ExpandProperty domains -PipelineVariable domain | foreach{Get-ADOrganizationalUnit `
        -filter * -properties "msds-approx-immed-subordinates" -server $domain -PipelineVariable ou | `
            where {$_."msds-approx-immed-subordinates" -ne 0} | foreach{
                get-adgroup -LDAPFilter "(&(memberof=*)(!(IsCriticalSystemObject=TRUE))(groupType:1.2.840.113556.1.4.803:=2147483648))" `
                    -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain `
                    -properties $Group_Properties -PipelineVariable group | select -ExpandProperty memberof -PipelineVariable memofdn | `
                        select @{name='group';expression={$grp.distinguishedname}}, `
                        @{name='memberof';expression={$memofdn}}
            }
    }
}
function memberisgroup{
    [cmdletbinding()]
    param($groupDN)
    foreach($parentdn in $unique_group_parents){
        if($groupDN -eq $parentdn){
            write-debug "Found $groupDN"
            return $true
            exit
        }
    }
    write-debug "Not Found $groupDN"
    return $false
}
function archiveresults{
    [cmdletbinding()]
    param($source,$destination)
    Process{
        $source
        $destination
        Add-Type -assembly "system.io.compression.filesystem"
        [io.compression.zipfile]::CreateFromDirectory($source, $destination) 
    }
}

$BogusDate = "01-01-1901" | get-date -format "MM-dd-yyyy"

$hash_domain = @{name='Domain';expression={$domain}}
$hash_parentou = @{name='ParentOU';expression={$ou.distinguishedname}}
$hash_whenchanged = @{Name="whenchanged";
    Expression={($_).whenchanged | get-date -Format 'MM-dd-yyyy'}}
$hash_whencreated = @{Name="whencreated";
    Expression={($_).whencreated | get-date -Format 'MM-dd-yyyy'}}
$hash_memlastchange = @{name='MembershipLastChanged';
        expression={$repdate = ($_ | Select-Object -ExpandProperty "msDS-ReplValueMetaData" | 
            foreach {([XML]$_.Replace("`0","")).DS_REPL_VALUE_META_DATA | where { $_.pszAttributeName -eq "member" }} | 
            select -first 1).ftimeLastOriginatingChange ; if($repdate){$repdate | get-date -format "MM-dd-yyyy"}else{$bogusdate}}}
$hash_rid = @{name='Rid';expression={$([int]($_.objectsid -split("-"))[7])}}
$hash_groupasmember = @{name='ContainsGroupasMember';expression={memberisgroup -groupDN ($_).distinguishedname}}
$hash_containsmember = @{name='Members';expression={if($_.member){$true}else{$false}}}

cls

$query_time = (Measure-Command{$empty_groups = gatherEmptyADGroups}).minutes
write-host "Completed in $query_time minutes"
$query_time = (Measure-Command{$memberof_group_dump = dumpADGroupMemberof}).minutes
write-host "Completed in $query_time minutes"
$unique_group_parents = ($ad_security_groups_memberof | select memberof -unique).memberof
$query_time = (Measure-Command{$populated_groups = gatherpopulatedADGroups}).minutes
write-host "Completed in $query_time minutes"

   


#region empty groups
$date_created_before = (Get-Date).Adddays(-(365))
$report = $empty_groups | where {$_.MembershipLastChanged -eq "01-01-1901" -and $(get-date ($_).whencreated) -lt $date_created_before} 
Write-host "Empty Groups Never Used Older than 1 year: $(($report | measure-object).count)"
$report  | export-csv "$reportpath\Empty_Groups_Never_Used_Older_than_1_year.csv" -NoTypeInformation

$date_created_before = (Get-Date).Adddays(-(1095))
$report = $empty_groups | where {$_.MembershipLastChanged -eq "01-01-1901" -and $(get-date ($_).whencreated) -lt $date_created_before} 
Write-host "Empty Groups Never Used Older than 3 year: $(($report | measure-object).count)"
$report  | export-csv "$reportpath\Empty_Groups_Never_Used_Older_than_3_year.csv" -NoTypeInformation

$date_changed_before = (Get-Date).Adddays(-(365))
$report = $empty_groups | where {$_.MembershipLastChanged -ne "01-01-1901" -and $(get-date ($_).MembershipLastChanged) -lt $date_changed_before} 
Write-host "Empty Groups not change in 1 years: $(($report | measure-object).count)"
$report  | export-csv "$reportpath\Empty_Groups_for_at_least_1_year.csv" -NoTypeInformation

$date_changed_before = (Get-Date).Adddays(-(1095))
$report = $empty_groups | where {$_.MembershipLastChanged -ne "01-01-1901" -and $(get-date ($_).MembershipLastChanged) -lt $date_changed_before} 
Write-host "Empty Groups not change in 3 years: $(($report | measure-object).count)"
$report  | export-csv "$reportpath\Empty_Groups_for_at_least_3_years.csv" -NoTypeInformation

$empty_groups | where {$_.MembershipLastChanged -ne "01-01-1901"} | export-csv "$reportpath\All_Empty_Groups.csv" -NoTypeInformation
$empty_groups | where {$_.MembershipLastChanged -eq "01-01-1901"} | export-csv "$reportpath\All_Never_Used_Empty_Groups.csv" -NoTypeInformation
#endregion

$date_changed_before = (Get-Date).Adddays(-(365))
$report = $populated_groups | where {$_.ContainsGroupasMember -eq $false -and $(get-date ($_).MembershipLastChanged) -lt $date_changed_before}
Write-host "Populated Groups not change in 1 years: $(($report | measure-object).count)"
$report  | export-csv "$reportpath\Populated_Groups_membership_not_changed_in_1_years.csv" -NoTypeInformation

$date_changed_before = (Get-Date).Adddays(-(1095))
$report = $populated_groups | where {$_.ContainsGroupasMember -eq $false -and $(get-date ($_).MembershipLastChanged) -lt $date_changed_before}
Write-host "Populated Groups not change in 3 years: $(($report | measure-object).count)"
$report  | export-csv "$reportpath\Populated_Groups_membership_not_changed_in_3_years.csv" -NoTypeInformation

$date_changed_before = (Get-Date).Adddays(-(1825))
$report = $populated_groups | where {$_.ContainsGroupasMember -eq $false -and $(get-date ($_).MembershipLastChanged) -lt $date_changed_before}
Write-host "Populated Groups not change in 5 years: $(($report | measure-object).count)"
$report  | export-csv "$reportpath\Populated_Groups_membership_not_changed_in_5_years.csv" -NoTypeInformation

$date_changed_before = (Get-Date).Adddays(-(3650))
$report = $populated_groups | where {$_.ContainsGroupasMember -eq $false -and $(get-date ($_).MembershipLastChanged) -lt $date_changed_before}
Write-host "Populated Groups not change in 10 years: $(($report | measure-object).count)"
$report  | export-csv "$reportpath\Populated_Groups_membership_not_changed_in_10_years.csv" -NoTypeInformation

$populated_groups | where {$_.ContainsGroupasMember -eq $false} | export-csv "$reportpath\All_Populated_Groups_with_Only_User_Members.csv" -NoTypeInformation
$populated_groups | where {$_.ContainsGroupasMember -eq $true} | export-csv "$reportpath\All_Populated_Groups_with_Group_Members.csv" -NoTypeInformation

$archive = "$path\Group_Cleanup_Report-ARCHIVE-$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).zip"
archiveresults -source $reportpath -destination $archive

write-host "--"
write-host "There are two types of reports: Empty and Populated."
write-host "--"
write-host "Empty Reports - contain groups that have no group memberships. if a group is NEVER USED that means
that the group has never had a member. This is determined by looking at replication information
that contains information about when a membership of the group has changed.  The other empty reports
show groups that at one time had a member but are currently empty and how long they have been empty for."
write-host "--"
write-host "Populated Reports - contain groups that currently only have users as members.  There are multiple
reports created based on the last time the group has changed its membership.  If a group hasnt had a membership
change in a really long period of time is the group still used."
write-host "--"
Write-host "All Reports can be found here $reportpath):"
write-host "--"
($reportpath | dir).name | out-host

Write-host Script run time $(NEW-TIMESPAN –Start $start_time –End $(get-date))
<#
$ad_security_groups = gatherADGroups
$ad_security_groups_memberof = dumpADGroupMemberof
$formated_ad_security_groups = $ad_security_groups | select domain,samaccountname,DisplayName, `
    groupscope,groupcategory,admincount,mail,$hash_groupasmember,$hash_containsmember,$hash_whencreated,$hash_whenchanged,$hash_memlastchange, `
    ProtectedFromAccidentalDeletion,$hash_rid,ParentOU
#groups never used after 1 year
#empty groups with no membership changes after 3 years
#groups with only members that are users not changed after 5 years
#group
$formated_ad_security_groups | group ContainsGroupasMember | select name, count#>
