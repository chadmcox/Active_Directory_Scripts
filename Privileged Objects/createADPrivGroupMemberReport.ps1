<#PSScriptInfo

.VERSION 0.2

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
0.2 added cert publisher
0.1 First go around of the script

.PRIVATEDATA 

#>

#Requires -Module ActiveDirectory

<# 

.DESCRIPTION 
 Collects group member ship changes to enterprise admins, domain admins, 
 administrators and other privileged groups including ones nested
 ones done via sid history

#> 
Param($reportpath = "$env:userprofile\Documents")


#https://blogs.technet.microsoft.com/pie/2014/08/25/metadata-2-the-ephemeral-admin-or-how-to-track-the-group-membership/
#https://blogs.technet.microsoft.com/ashleymcglone/2014/12/17/forensics-monitor-active-directory-privileged-groups-with-powershell/

$default_log = "$reportpath\report_privileged_group_members.csv"


$privileged_groups = @()


function getPrivilegedGroups{
    write-host "Gathering Privileged Groups"
    $admincount_groups = @()
    $privileged_groups = @()

    #pulls back the major privileged groups, and all groups with admin count set
    $admincount_groups = (get-adforest).domains | foreach{$domain = $_; get-adgroup `
                -filter 'admincount -eq 1 -and iscriticalsystemobject -notlike "*"' `
                 -server $domain -Properties * | select $hash_domain,distinguishedname,SamAccountName,objectSid,GroupRelatedTo,viaSidHistory}
    $privileged_groups = (get-adforest).domains | foreach{$domain = $_; get-adgroup `
                -filter '(admincount -eq 1 -and iscriticalsystemobject -like "*") -or samaccountname -eq "Cert Publishers"' `
                 -server $domain -Properties * | select $hash_domain,distinguishedname,SamAccountName,objectSid,GroupRelatedTo,viaSidHistory}

    #creates a legit list of privileged groups, can easily add a else statement to report on groups with
    #stale admin count

    $privileged_groups | foreach{
        $privileged_group_domain = $_.domain
        $privileged_group_dn = $_.distinguishedname
        $privileged_group_sam = $_.samaccountname
        $admincount_groups | foreach{
            $admincount_group_dn = $_.distinguishedname
            if(Get-ADgroup -Filter {member -RecursiveMatch $admincount_group_dn} `
                -searchbase $privileged_group_dn -server $privileged_group_domain){
                $privileged_groups += $_ | select domain, distinguishedname,samaccountname,objectsid, `
                    @{name='GroupRelatedTo';expression={$privileged_group_sam}},viaSidHistory
            } 
        }
    }

    #grab groups with sid history
    write-host "Gathering Privileged Groups Hidden via SidHistory"
    $privileged_groups += $($privileged_groups | foreach{searchforobjectwithsidhistory -group $_})

    $privileged_groups | select * -Unique | sort domain
}
Function isinProtectedUsers{
    param($udn)
    foreach($pu in $protected_users_groups){
        if(Get-ADgroup -Filter {member -RecursiveMatch $udn} `
            -searchbase $pu.distinguishedname -server $pu.domain){$True;break}
    }

}
Function checkADUserSecurity{
    param($userdn,$domain)
    $userproperties = @("AccountNotDelegated","primaryGroupId","Trustedfordelegation","TrustedToAuthForDelegation","pwdlastset","expired")
    try{$user = Get-Aduser -Identity $($_.pszObjectDn) `
                -Properties $userproperties -server "$($domain):3268"}
    catch{}
    $user
}
Function collectADPrivilegedGroupChanges{
    #enumerate through the newest list of legit admincount groups, and pull back the replication metadata
    #one addition is if a user's primary group membership is change to the group, it looks like the user
    #was removed from the group.  I perform a check to validate

    $results = @()
    $groupproperties = @("msDS-ReplValueMetaData","WhenChanged","SamAccountName")

    if(!($privileged_groups)){
        $privileged_groups = getPrivilegedGroups
    }

    $privileged_groups  | foreach{
        $distinguishedname = $_.distinguishedname
        $samaccountname = $_.samaccountname
        $domain = $_.domain
        Get-ADGroup $distinguishedname -Properties $groupproperties -Server $domain `
                -PipelineVariable grp | Select-Object -ExpandProperty "msDS-ReplValueMetaData" |`
            foreach {
                $metadata = [XML]$_.Replace("`0","")
                ($metadata).DS_REPL_VALUE_META_DATA | where { $_.pszAttributeName -eq "member" } | foreach{
                    $priv_user = checkADUserSecurity -userdn  $($_.pszObjectDn) -domain $domain
                    $results += $_ | select $hash_domain,$hash_sam,`
                    $hash_ftloc,$hash_operation,pszAttributeName,pszObjectDn,dwVersion,$hash_ctpg ,`
                    ftimeDeleted,ftimeCreated 
            }
        }
    }
    $results
}
function searchforobjectwithsidhistory{
    param($group)
    $sid = $group.objectSid
    #$sid 
    foreach($domain in (get-adforest).domains){
        try{get-adobject -filter {sidhistory -eq $sid} -server $domain -Properties * | select `
            $hash_domain,distinguishedname,SamAccountName,objectSid, `
            @{name='GroupRelatedTo';expression={$group.samaccountname}}, `
            @{name='viaSidHistory';expression={$true}}}
        catch{}
    }
}
function searchforprimarygroupmembership{
    param($sid,$domain,$group,$from,$sh)
    $rid = $sid.tostring().split("-")[7]
    try{get-aduser -filter {primaryGroupId -eq $rid} -server $domain -Properties * | select `
        @{name='Domain';expression={$domain}}, `
        @{name='GroupRelatedTo';expression={$from}}, `
        @{name='Group';expression={$group}}, `
        distinguishedname, samaccountname,ObjectClass,enabled,$hash_AccountNotDelegated, `
        $hash_pwdLastSet,$hash_lastLogonTimestamp,$hash_vsh,$hash_protected}catch{}
}
function enumerateGroupMember{
    param($group,$domain,$from,$sh)
    get-adgroup $group -server $domain -Properties members | select -ExpandProperty members | foreach{
        foreach($d in (get-adforest).domains){
            try{get-adobject -filter {distinguishedname -eq $_} -Properties * -server $d | select `
            @{name='Domain';expression={$domain}}, `
            @{name='GroupRelatedTo';expression={$from}}, `
            @{name='Group';expression={$group}}, `
            distinguishedname, samaccountname,ObjectClass,$hash_enabled, `
            $hash_AccountNotDelegated,$hash_pwdLastSet,$hash_lastLogonTimestamp, `
            $hash_vsh,$hash_protected}catch{}
        }
     }
}
function collectPrivilegedUsers{
    $results = @()
    if(!($privileged_groups)){
        $privileged_groups = getPrivilegedGroups
    }
    #enumerate found group members
    write-host "Gathering Privileged Groups Members"
    foreach($pg in $privileged_groups){
        $results += enumerateGroupMember -group $pg.samaccountname -domain $pg.domain `
            -from $pg.GroupRelatedTo -sh $pg.viaSidHistory
    }
    write-host "Gathering Privileged Groups Primary Members "
    #enumerate users with changed primary group
    foreach($pg in $privileged_groups){
        $results += searchforprimarygroupmembership -group $pg.samaccountname -domain $pg.domain `
            -sid $pg.objectsid -from $pg.GroupRelatedTo -sh $pg.viaSidHistory
    }
    $results | sort group
}


#region hash calculated properties
    #creating hash tables for each calculated property
    $hash_AccountNotDelegated = @{name='CannotBeDelegated';expression={if($_.useraccountcontrol -band 1048576){$true}else{$false}}}
    $hash_enabled = @{name='enabled';expression={if($_.useraccountcontrol -band 2){$false}else{$true}}}
    $hash_pwdexpired = @{name='PasswordExpired';expression={if($_.useraccountcontrol -band 8388608){$true}else{$false}}}
    $hash_vsh = @{name='viaSidHistory';expression={$sh}}
    $hash_domain = @{name='Domain';expression={$domain}}
    $hash_sam = @{name='Group';expression={$samaccountname}}
    $hash_ftloc = @{name='ftimeLastOriginatingChange';expression={$_.ftimeLastOriginatingChange |  get-date -Format MM/dd/yyyy}}
    $hash_operation = @{name='Operation';expression={If($_.ftimeDeleted -ne "1601-01-01T00:00:00Z"){"Removed"}Else{"Added"}}}
    $hash_ctpg = @{name='ChangedtoPrimaryGroup';expression={If( $priv_user | `
                                where {$_.primaryGroupId -eq ($grp | % {$_.sid.tostring().split("-")[7]})}){$true}else{$false}}}
    $hash_risk = @{name='SecurityRisk';expression={$securityRisk}}
    $hash_Protected = @{name='ProtectionsEnabled';expression={if($_.objectclass -eq "user"){isinProtectedUsers -udn $_.distinguishedname}}}
    $hash_pwdLastSet = @{Name="pwdLastSet";
        Expression={if($_.PwdLastSet -ne 0 -and $_.objectclass -eq "user"){([datetime]::FromFileTime($_.pwdLastSet).ToString('MM/dd/yyyy'))}}}
    $hash_lastLogonTimestamp = @{Name="LastLogonTimeStamp";
        Expression={if($_.LastLogonTimeStamp -like "*"){([datetime]::FromFileTime($_.LastLogonTimeStamp).ToString('MM/dd/yyyy'))}}}
    $hash_PwdAgeinDays = @{Name="PwdAgeinDays";
        Expression={if($_.PwdLastSet -ne 0){(new-TimeSpan([datetime]::FromFileTimeUTC($_.PwdLastSet)) $(Get-Date)).days}else{0}}}
#endregion

#collectADPrivilegedGroupChanges | out-gridview

$protected_users_groups = foreach($domain in (get-adforest).domains){get-adgroup "Protected Users"`
                    -server $domain | select @{name='Domain';expression={$domain}},distinguishedname}

$results = collectPrivilegedUsers
$results | out-gridview
$results | export-csv $default_log -NoTypeInformation
