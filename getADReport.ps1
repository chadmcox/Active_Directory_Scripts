#Requires -Module ActiveDirectory
#Requires -RunAsAdministrator
#Requires -Version 4

<#PSScriptInfo

.VERSION 0.6

.GUID 28a1bbb8-3870-4b22-82af-70383231a1a9

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

.TAGS msonline PowerShell get-adobject get-aduser get-adcomputer get-addomaincontroller

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


.PRIVATEDATA 


.DESCRIPTION 
 This script is will gather useful information around ad objects including cleanup task. 
.update
    added, sitelink, subnet, site reports
    added new menu option for AD Site Mapping Data


.update I added a 500 ResultPageSize
    Added the users function
    added menu selection and switch to prevent menu
.EXAMPLE 

    .\get-adreport -$SkipUsers

    Does not generate user report

.EXAMPLE 

    .\get-adreport -$Skipcomputers

    Does not generate computer report

.EXAMPLE 

    .\get-adreport -$Skipgroup

    Does not generate group report

.EXAMPLE 

    .\get-adreport -$Skipmenu

    runs everything unless something else is skipped


#>

Param(
$reportpath = "$env:userprofile\Documents\ADReports",
[switch]$SkipUsers,
[switch]$SkipComputers,
[switch]$SkipGroups,
[switch]$skipMenu
)

If (!($(Try { Test-Path $reportpath} Catch {$true}))){
    new-Item $reportpath -ItemType "directory"  -force
}
cls
cd $reportpath
$searchbase = @()
$default_err_log = "$reportpath\err.txt"
$time_log = "$reportpath\runtime.csv"
$forest_sids = ((get-adforest).domains | foreach{get-addomain -Server $_}).DomainSID.value

Function createADSearchBase{
    $searchbase_list = "$reportpath\tmpADSearchBaseList.csv"
    try{Get-ChildItem $searchbase_list | Where-Object { $_.LastWriteTime -lt $((Get-Date).AddDays(-5))} | Remove-Item -force}catch{}
    write-host "Generating Search Base List"
    If (!(Test-Path $searchbase_list)){
        foreach($domain in (get-adforest).domains){
            write-debug "Gathering OUs"
            try{Get-ADObject -ldapFilter "(objectclass=organizationalunit)" `
                -Properties "msds-approx-immed-subordinates" -server $domain -ResultPageSize 500 -ResultSetSize $null |`
                     where {$_."msds-approx-immed-subordinates" -ne 0} | select `
                $hash_domain, DistinguishedName  | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
            try{Get-ADObject -ldapFilter "(objectclass=domainDNS)" `
                -Properties "msds-approx-immed-subordinates" -server $domain -ResultPageSize 500 -ResultSetSize $null |`
                     where {$_."msds-approx-immed-subordinates" -ne 0} | select `
                $hash_domain, DistinguishedName  | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
            try{Get-ADObject -ldapFilter "(objectclass=builtinDomain)" `
                -Properties "msds-approx-immed-subordinates" -server $domain -ResultPageSize 500 -ResultSetSize $null |`
                     where {$_."msds-approx-immed-subordinates" -ne 0} | select `
                $hash_domain, DistinguishedName  | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
            try{(get-addomain $domain).UsersContainer | Get-ADObject -server $domain | select `
                $hash_domain, DistinguishedName | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
            try{(get-addomain $domain).ComputersContainer | Get-ADObject -server $domain | select `
                $hash_domain, DistinguishedName | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
    }
    else{
        Write-host "Reusing Existing Searchbase List"
    }
    $searchbase = import-csv $searchbase_list
    $searchbase
}
Function CollectADForestHistory{
    <#
    .notes
    this is a nice little script borrowed from
    Author: Pierre Audonnet [MSFT]
    Blog: http://blogs.technet.com/b/pie/
    Download: https://gallery.technet.microsoft.com/List-Active-Directory-24d9d346
    #>
    

}
function CollectADDomainControllers{
    write-host "Collecting AD Domain Controllers."
    $results = @()
    foreach($domain in (get-adforest).domains){ 
        try{$Results += get-addomaincontroller -filter *  -server $domain}
        catch{"function CollectADDomainController - $domain - $($_.Exception)" | out-file $default_err_log -append}
    }
       
    $results | select domain,name,operatingsystem,operatingsystemversion,Enabled,IsGlobalCatalog, `
    @{Name="isSchemaMaster";Expression={if($_.OperationMasterRoles -like "*SchemaMaster*"){$True}else{$false}}}, `
    @{Name="isDomainNamingMaster";Expression={if($_.OperationMasterRoles -like "*DomainNamingMaster*"){$True}else{$false}}}, `
    @{Name="isPDCEmulator";Expression={if($_.OperationMasterRoles -like "*PDCEmulator*"){$True}else{$false}}}, `
    @{Name="isRIDMaster";Expression={if($_.OperationMasterRoles -like "*SchemaMaster*"){$True}else{$false}}}, `
    @{Name="isInfrastructureMaster";Expression={if($_.OperationMasterRoles -like "*InfrastructureMaster*"){$True}else{$false}}}, `
    $hash_lastLogonTimestamp,IPv4Address, `
    @{Name="Site";Expression={$_.site}}
}
function CollectADUsers{
    param([switch]$sitemap)
    if(!($SkipComputers)){
        
        $results = @()
        $d = [DateTime]::Today.AddDays(-90)
        $Default_Group_ID = 513
        $userProperties = @("whencreated","lastlogontimestamp","SamAccountName",`
            "UserAccountControl","Enabled","admincount","Trustedfordelegation",`
            "TrustedToAuthForDelegation","PrimaryGroupID","pwdlastset","sidhistory","mail", `
            "PasswordNotRequired","distinguishedname","UserPrincipalname","PasswordExpired","LockedOut", `
            "ProtectedFromAccidentalDeletion","l","st","c","co","countrycode","servicePrincipalName")
        $select_properties = $userProperties + $hash_domain

        if(!($searchbase)){
            #go to function to populate the variable
            
            Measure-Command {$searchbase = createADSearchBase} | `
                select @{name='RunDate';expression={get-date -format d}},`
                @{name='Function';expression={"createADSearchBase"}}, `
                @{name='Hours';expression={$_.hours}}, `
                @{name='Minutes';expression={$_.Minutes}}, `
                @{name='Seconds';expression={$_.Seconds}} | export-csv $time_log -append -notypeinformation
        }
        write-host "Collecting AD Users"
        foreach($sb in $searchbase){$domain = $sb.domain
            try{$results += get-aduser -ldapFilter "(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(IsCriticalSystemObject=TRUE)))" `
                 -Properties $userProperties -SearchBase $sb.distinguishedname -SearchScope OneLevel `
                 -Server $sb.domain -ResultPageSize 500 -ResultSetSize $null | select $select_properties}
            catch{"functionCollectADComputers - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        write-debug "Collected now writing out"
        if(!($sitemap)){
            #this is the default report
            $results | select domain,SamAccountName,UserPrincipalname,mail,UserAccountControl,$hash_PrimaryGroup,`
                Enabled,PasswordExpired,LockedOut,admincount,$hash_userstale,$hash_whencreated,$hash_pwdLastSet, `
                $hash_lastLogonTimestamp, Trustedfordelegation,TrustedToAuthForDelegation, `
                $hash_AccountNotDelegated,$hash_UseDesKeyOnly,$hash_ReversibleEncryption, `
                $hash_DoesNotRequirePreAuth,$hash_PwdAgeinDays,$hash_PasswordNeverExpires,$hash_PasswordNotRequired, `
                $hash_PasswordNeverSet,$hash_SmartCardRequired,$hash_sidhistory,$hash_spn,ProtectedFromAccidentalDeletion, `
                $hash_parentou
        }else{
            #this will only be used if the sitemap switch is being leveraged
            #meant to be a smaller report
            $results | select domain,SamAccountName,Enabled,PasswordExpired,LockedOut,$hash_userstale, `
                $hash_usercity,$hash_userstate,$hash_userc,$hash_userco,$hash_usercountrycode, `
                $hash_lastLogonTimestamp,$hash_whencreated

        }
    }
}
function CollectADUsersTokenCount{
    $results = @()
    $userProperties = @("sid","samaccountname","UserPrincipalName")
    $select_properties = $userProperties + $hash_domain
    foreach($domain in (get-adforest).domains){
        try{$results += get-adusers  -ldapFilter "(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(IsCriticalSystemObject=TRUE)))" | `
            select $select_properties} 
        catch{}
        $results | select domain,samaccountname,userprincipalname, `
            @{name='GroupMemCount';expression={(New-Object System.Security.Principal.WindowsIdentity($_.UserPrincipalName)).Groups.count}}
    }
}
Function CollectADComputers{
    param([switch]$sitemap)
    if(!($SkipComputers)){
        
        $results = @()
        $d = [DateTime]::Today.AddDays(-90)
        $Default_Group_ID = 515
        $ComputerProperties = @("whencreated","lastlogontimestamp","SamAccountName","operatingsystem",`
            "operatingsystemversion","UserAccountControl","Enabled","admincount","Trustedfordelegation",`
            "TrustedToAuthForDelegation","PrimaryGroupID","pwdlastset","IPv4Address","sidhistory","DNSHostName", `
            "PasswordNotRequired","distinguishedname","ProtectedFromAccidentalDeletion")
        $select_properties = $ComputerProperties + $hash_domain

        if(!($searchbase)){
            #go to function to populate the variable
            Measure-Command {$searchbase = createADSearchBase} | `
                select @{name='RunDate';expression={get-date -format d}},`
                @{name='Function';expression={"createADSearchBase"}}, `
                @{name='Hours';expression={$_.hours}}, `
                @{name='Minutes';expression={$_.Minutes}}, `
                @{name='Seconds';expression={$_.Seconds}} | export-csv $time_log -append -notypeinformation
        }
        write-host "Collecting AD Computers"
        foreach($sb in $searchbase){$domain = $sb.domain
            try{$results += get-adcomputer -ldapFilter "(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(IsCriticalSystemObject=TRUE)))" `
                 -Properties $ComputerProperties -SearchBase $sb.distinguishedname -SearchScope OneLevel `
                 -Server $sb.domain -ResultPageSize 500 -ResultSetSize $null | select $select_properties}
            catch{"functionCollectADComputers - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        write-debug "Collected now writing out"
        if(!($sitemap)){
            $results | select domain,SamAccountName,DNSHostName,operatingsystem,UserAccountControl,`
                Enabled,admincount,Trustedfordelegation,TrustedToAuthForDelegation, `
                $hash_PrimaryGroup,IPv4Address, `
                @{Name="Site";Expression={if($_.IPv4Address){(get-ipsite $_.IPv4Address).ADSite}}}, ` 
		        $hash_computerstale,$hash_sidhistory,$hash_pwdLastSet,$hash_lastLogonTimestamp,`
                $hash_whencreated,PasswordNotRequired,ProtectedFromAccidentalDeletion,$hash_parentou
            }else{
                $results | select domain,SamAccountName,DNSHostName,operatingsystem,IPv4Address,`
                $hash_computerstale,$hash_whencreated,`
                @{Name="Site";Expression={if($_.IPv4Address){(get-ipsite $_.IPv4Address).ADSite}}}
            }
    }
}
Function CollectADGroups{
    if(!($skipgroups)){
        
        $results = @()
        $GroupProperties = @("samaccountname","DisplayName","groupscope","groupcategory","admincount","iscriticalsystemobject", `
                        "whencreated","description","managedby","member","memberof","mail","sidhistory", `
                        "msDS-ReplValueMetaData",'msDS-PSOApplied',"objectSid","ProtectedFromAccidentalDeletion")
        $Select_properties = $GroupProperties + $hash_domain
        if(!($searchbase)){
            #go to function to populate the variable
            Measure-Command {$searchbase = createADSearchBase} | `
                select @{name='RunDate';expression={get-date -format d}},`
                @{name='Function';expression={"createADSearchBase"}}, `
                @{name='Hours';expression={$_.hours}}, `
                @{name='Minutes';expression={$_.Minutes}}, `
                @{name='Seconds';expression={$_.Seconds}} | export-csv $time_log -append -notypeinformation
        }
        write-host "Collecting AD Groups"
        foreach($sb in $searchbase){$domain = $sb.domain
            try{$results += get-adgroup -filter * `
                 -Properties $GroupProperties -SearchBase $sb.distinguishedname -SearchScope OneLevel `
                 -Server $sb.domain -ResultPageSize 500 -ResultSetSize $null| select $Select_properties}
            catch{"CollectADGroups - $domain - $($_.Exception)" | out-file $default_err_log -append}

            
        }
        $results | select domain,samaccountname,DisplayName,groupscope,groupcategory,mail,admincount, `
            iscriticalsystemobject,$hash_members,$hash_memberof,$hash_rid,$hash_whencreated,$hash_memlastchange, `
            $hash_sidhistory,ProtectedFromAccidentalDeletion,$hash_parentou
    }
}
Function CollectADPrivilegedGroupChanges{
    #https://blogs.technet.microsoft.com/pie/2014/08/25/metadata-2-the-ephemeral-admin-or-how-to-track-the-group-membership/
    #https://blogs.technet.microsoft.com/ashleymcglone/2014/12/17/forensics-monitor-active-directory-privileged-groups-with-powershell/

    $default_log = "$reportpath\report_privileged_group_changes.csv"
    If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}

    #region hash calculated properties
    #creating hash tables for each calculated property
    write-host "Collecting AD Privileged Group History"
    $hash_sam = @{name='Group';expression={$samaccountname}}
    #endregion
    $results = @()
    $admincount_groups = @()
    $privileged_groups = @()

    #pulls back the major privileged groups, and all groups with admin count set
    $admincount_groups = (get-adforest).domains | foreach{$domain = $_; get-adgroup `
                -filter 'admincount -eq 1 -and iscriticalsystemobject -notlike "*"' `
                 -server $domain | select $hash_domain,distinguishedname,SamAccountName}
    $privileged_groups = (get-adforest).domains | foreach{$domain = $_; get-adgroup `
                -filter '(admincount -eq 1 -and iscriticalsystemobject -like "*") -or samaccountname -eq "Cert Publishers"' `
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
        $results += Get-ADGroup $distinguishedname -Properties msDS-ReplValueMetaData,WhenChanged,SamAccountName -Server $domain `
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
                        ftimeDeleted,ftimeCreated 
            }
        }
    }

    $results 
}
Function CollectADPrivilegedUsers{
    $results = @()
    $d = [DateTime]::Today.AddDays(-90)
    $flagged_object = foreach($domain in (get-adforest).domains)
            {get-adobject -filter 'admincount -eq 1 -and iscriticalsystemobject -notlike "*"' `
                    -server $domain `
                    -properties whenchanged,whencreated,admincount,isCriticalSystemObject, `
                        "msDS-ReplAttributeMetaData",samaccountname |`
                select $hash_domain,distinguishedname,whenchanged,whencreated,admincount,`
                    SamAccountName,objectclass,isCriticalSystemObject,@{name='adminCountDate';expression={($_ | `
                        Select-Object -ExpandProperty "msDS-ReplAttributeMetaData" | foreach { `
                        ([XML]$_.Replace("`0","")).DS_REPL_ATTR_META_DATA |`
                        where { $_.pszAttributeName -eq "admincount"}}).ftimeLastOriginatingChange | `
                         get-date -Format MM/dd/yyyy}}}

}
Function CollectADObjectsCertificates{

}
Function CollectADSiteDetails{
    $results = @()
    write-host "Collecting AD Sites"
    try{$results +=  get-adreplicationsite -filter * -Properties *}
    catch{"CollectADSiteDetails - $domain - $($_.Exception)" | out-file $default_err_log -append}

    $results | select name,$hash_SiteAddress,$hash_SiteCity,$hash_SiteState,$hash_SiteCountry,$hash_subnetcount,`
        $hash_sitelinkcount,$hash_dcinsitecount,$hash_gplink,`
        AutomaticInterSiteTopologyGenerationEnabled,AutomaticTopologyGenerationEnabled,RedundantServerTopologyEnabled,`
        ScheduleHashingEnabled,TopologyCleanupEnabled,TopologyDetectStaleEnabled,TopologyMinimumHopsEnabled,`
        UniversalGroupCachingEnabled,UniversalGroupCachingRefreshSite,WindowsServer2000BridgeheadSelectionMethodEnabled,`
        WindowsServer2000KCCISTGSelectionBehaviorEnabled,WindowsServer2003KCCBehaviorEnabled,`
        WindowsServer2003KCCIgnoreScheduleEnabled,WindowsServer2003KCCSiteLinkBridgingEnabled,`
        $hash_istgOrphaned,$hash_whencreated,$hash_whenchanged,Description,DistinguishedName
}
Function CollectADSubnets{
    $results = @()
    write-host "Collecting AD Subnets"
    try{$results +=  get-adreplicationsubnet -filter * -Properties *}
    catch{"CollectADSiteDetails - $domain - $($_.Exception)" | out-file $default_err_log -append}
    $results | select name,$hash_SubnetSiteName,$hash_whencreated,$hash_whenchanged,Description,DistinguishedName
}
Function CollectADSiteLinks{
    $results = @()
    
    write-host "Collecting AD Site Links"
    try{$siteLinks +=  Get-ADReplicationSiteLink -filter * -Properties *}
    catch{"CollectADSiteDetails - $domain - $($_.Exception)" | out-file $default_err_log -append}
    
    foreach($sitelink in $siteLinks){
        $sites = @();$SiteList = $null
        $sitelink | select -expandproperty sitelist | foreach{
           $sites +=  (Get-ADReplicationSite $_).name
        }
            $sites = $sites | sort
            if($sites){$SiteList = ([string]$sites).replace(" ","|")}
           
            $results += $sitelink | select name,cost,replInterval,options,$hash_SiteCount,`
                $hash_SiteString,$hash_whencreated,$hash_whenchanged,Description,DistinguishedName
    }
    
    $results
}
Function CollectADOUs{
    Write-host "Collecting AD OUs"
    $results = @()
    $OUProperties = @("name","whencreated","ProtectedFromAccidentalDeletion","ManagedBy",'msds-approx-immed-subordinates', `
    "gplink","gpoptions")
    foreach($domain in (get-adforest).domains){
        try{$results += get-adorganizationalunit -filter * `
            -Properties $OUProperties -server $domain | select $hash_domain, *}
        catch{"CollectADOUs - $domain - $($_.Exception)" | out-file $default_err_log -append}
    }
    $results | select domain,name,$hash_oudirectChild,$hash_whencreated,ProtectedFromAccidentalDeletion, `
        $hash_gpLink,$hash_gpOptions,ManagedBy,Distinguishedname
}
Function CollectADisDeletedObjects{
    write-host "Collecting AD isDeleted Objects"
    $searched_namingContexts = @()
    $results = @()
    $deletedProperties = "whencreated"
    Foreach($domain in (get-adforest).domains){
        Foreach($sb in (get-adrootdse -server $domain).namingContexts){
            if(!($searched_namingContexts -match $sb)){
                $searched_namingContexts += $sb
                try{$results += Get-ADObject -IncludeDeletedObjects -filter {deleted -eq $true} `
                    -searchbase $sb -server $domain -Properties $deletedProperties `
                    -ResultPageSize 500 -ResultSetSize $null | `
                    select $hash_domain, *}
                catch{}
            }
        }
    }
    $results | select domain, Name, deleted, objectclass, $hash_whencreated, distinguishedname
}
Function CollectADDisabledObjects{
    
    $results = @()
    $disabledProperties = @("whencreated","lastlogontimestamp","SamAccountName","UserAccountControl" `
        ,"admincount","pwdlastset","objectclass","whenchanged")
    $select_properties = $disabledProperties + $hash_domain

    if(!($searchbase)){
        #go to function to populate the variable
        $searchbase = createADSearchBase
    }
    write-host "Collecting AD Disabled Objects"
    foreach($sb in $searchbase){$domain = $sb.domain
        try{$results += get-adobject -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=2)(|(objectClass=user)(objectClass=computer)))" `
                -Properties $disabledProperties -SearchBase $sb.distinguishedname -SearchScope OneLevel `
                -Server $sb.domain | select $select_properties}
        catch{"functionCollectADDisabledObjects - $domain - $($_.Exception)" | out-file $default_err_log -append}
    }
    $results | select domain,SamAccountName,displayname,objectclass,UserAccountControl,Enabled,admincount, `
        $hash_pwdLastSet,$hash_lastLogonTimestamp,$hash_whencreated,$hash_whenchanged, $hash_parentou
}
function CollectADDomainExtendedRights{
    write-host "Collecting AD Domain Extended Rights"
    $results = @()
    $er = "cn=extended-rights,$((get-adrootdse).configurationnamingcontext)"
    $repextendedrights = get-adobject -filter * -SearchBase $er -Properties * 
    Foreach($domain in (get-adforest).domains){
        try{get-PSDrive -Name ADROOT -ErrorAction SilentlyContinue | Remove-PSDrive -force}catch{}
        $ps_drive = New-PSDrive -Name ADROOT -PSProvider ActiveDirectory -Server $domain -Scope Global -root "//RootDSE/"
        $rootdn = "ADROOT:\" + ($domain | get-addomain).DistinguishedName
        foreach($right in $repextendedrights){
            $rootacls = (Get-ACL $rootdn).access 
            foreach($rootacl in $rootacls){
                if ($rootacl.ObjectType -like $right.rightsGuid){
                    $results += $rootacl | select `
                        @{name='Domain';expression={$domain}},`
                        @{name='IdentityReference';expression={$rootacl.IdentityReference}},`
                        @{name='ExtendedRight';expression={$right.name}},`
                        @{name='Expected';expression={$expected}},AccessControlType
                }   
            }
        }
        try{Remove-PSDrive -Name ADROOT -Force}catch{}
        $results
    }
}
function CollectADSDAdminACLs{
    write-host "Collecting AD SDAdmin Holder ACLs"
    $results = @()
    get-PSDrive -Name ADROOT -ErrorAction SilentlyContinue | Remove-PSDrive -force
    $er = 'cn=extended-rights,' + (get-adrootdse).configurationnamingcontext
    $repextendedrights = get-adobject -filter * -SearchBase $er -Properties * 
    
    Foreach($domain in (get-adforest).domains){
        $ps_drive = New-PSDrive -Name ADROOT -PSProvider ActiveDirectory -Server $domain -Scope Global `
            -root "//RootDSE/"
        $rootdn = "ADROOT:\CN=AdminSDHolder,CN=System," + ($domain | get-addomain).DistinguishedName
        $rootacls = (Get-ACL $rootdn).access 
        foreach($rootacl in ($rootacls | select ObjectType,IdentityReference,ActiveDirectoryRights,`
            accessControlType -unique)){
            $results += $rootacl | select `
                @{name='Domain';expression={$domain}},`
                @{name='Object';expression={"AdminSDHolder"}},`
                @{name='DistinguishedName';expression={$rootdn.Replace("ADROOT:\","")}},`
                IdentityReference,`
                @{name='ActiveDirectoryRights';expression={if($_.ActiveDirectoryRights -ne "ExtendedRight")
                    {$_.ActiveDirectoryRights}else{($repextendedrights | 
                        where {$_.rightsGuid -eq $rootacl.ObjectType}).name}   }},`
                AccessControlType
        }
        Remove-PSDrive -Name ADROOT -Force
    }
    $results
}
Function CollectADConflictObjects{
    <#
    .Notes
    Simple Function to collect conflict objects from each partition in the forest
    #>
    param()
    write-host "Collecting AD Conflict Objects"
    $searched_namingContexts = @()
    $results = @()
    $conflictProperties = "whencreated"
    Foreach($domain in (get-adforest).domains){
        Foreach($sb in (get-adrootdse -server $domain).namingContexts){
            if(!($searched_namingContexts -match $sb)){
                $searched_namingContexts += $sb
                $Results += Get-ADObject -LDAPFilter "(|(cn=*\0ACNF:*)(ou=*CNF:*))" `
                    -searchbase $sb -server $domain `
                    -Properties $conflictProperties | select `
                    $hash_domain, $hash_NamingContext, *
            }
        }
    }
    $results | select domain,NamingContext,Name,DistinguishedName,$hash_Whencreated,ObjectGUID 
}
Function CollectADGPO{
    <#
    .Notes
    Simple Function to collect Each Domain Trust in a forest
    #>
    param()

}
Function CollectADkrbtgtpwdage{
    write-host "Collecting AD KRBTGT PWD Age"
    $results = @()
    (get-adforest).domains | foreach-object {Get-ADDomainController -filter * -server $_  `
        -PipelineVariable dc | foreach {
            $results += $([datetime]::FromFileTime($((Get-aduser krbtgt -server $(($dc).hostname) `
                -properties pwdlastset).pwdlastset))) | select `
            @{name='Domain';expression={$dc.domain}}, `
            @{name='DC';expression={$dc.hostname}}, `
            @{name='Account';expression={"KRBTGT"}}, `
            @{name='PWDLastSet';expression={$_}},`
            @{name='PWDAgeInDays';expression={(new-TimeSpan($_) $(Get-Date)).days}}
           }
     }
     $results 
}
Function CollectADForeignSecurityPrincipals{
    <#
    .Notes
    Simple Function to collect foreignsecurity principals from each domain
    #>
    param()
    write-host "Collecting AD Foreign Security Principals"
    $results = @()
    $trusted_domain_SIDs = @()
    $FSPProperties = @("memberof","whencreated")
    #collect from AD
    Foreach($domain in (get-adforest).domains){
        $trusted_domain_SIDs += (get-adtrust -filter {intraforest -eq $false} -Properties securityIdentifier `
            -server $domain).securityIdentifier.value
        $results += Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -server $domain `
            -Properties $FSPProperties| select $hash_domain, *
    }
    #format for report
    $results | ForEach {$fsp_translate = $null
        if($_.Name -match "^S-\d-\d+-\d+-\d+-\d+-\d+"){$domain_sid = $matches[0]}else{$domain_sid = $null}
        $fsp_translate = try{([System.Security.Principal.SecurityIdentifier] $_.Name).Translate([System.Security.Principal.NTAccount])}catch{"Orphan"}
	    $_ | select Domain,name, `
            @{name='Translate';expression={$fsp_translate}}, `
            @{name='isMemberOfGroup';expression={if($_.memberof){$True}}}, `
            @{name='TrustExist';expression={if($trusted_domain_SIDs -like $domain_sid){$True}}}, `
            $hash_whencreated | where {$_.name -notmatch "^S-\d-\d+-(\d+)$"}
    } 
    
}
Function CollectADTrust{
    <#
    .Notes
    Simple Function to collect Each Domain Trust in a forest
    #>
    param()
    Write-Host "Collecting AD Trusts"
    $results = @()
    $trustproperties = "whencreated"
    #collect from AD
    foreach($domain in (get-adforest).domains){
        if(get-command get-adtrust){
            $results += get-adtrust -Filter * -Server $domain -Properties $trustproperties | select $hash_domain,*
                
        }
    }
    #format for report
    $results | select Domain,Direction,DisallowTransivity,ForestTransitive,IntraForest,IsTreeParent, `
        IsTreeRoot,Name,ObjectClass,ObjectGUID,SelectiveAuthentication,SIDFilteringForestAware, `
        SIDFilteringQuarantined,Source,Target,TGTDelegation,TrustAttributes,TrustedPolicy,TrustingPolicy, `
        TrustType,UplevelOnly,UsesAESKeys,UsesRC4Encryption,$hash_whencreated,DistinguishedName 
}
Function CollectADFGPP{
    write-host "Collecting AD Fine Grain Password Policies"
    $results = @()
    $fgppproperties = "whencreated"
    foreach($domain in (get-adforest).domains){
        try{$results += Get-ADFineGrainedPasswordPolicy -filter *  `
            -Properties $fgppproperties -server $domain | select $hash_domain, *}
        catch{"CollectADFGPP - $domain - $($_.Exception)" | out-file $default_err_log -append}
    }
    $results | select domain,name,ComplexityEnabled,LockoutDuration,LockoutObservationWindow, `
        LockoutThreshold,MaxPasswordAge,MinPasswordAge,MinPasswordLength,PasswordHistoryCount, `
        ReversibleEncryptionEnabled,Precedence,$hash_FGPPAppliesTo,$hash_whencreated
}
Function CollectADDDPP{
    write-host "Collecting AD Default Domain Password Policy"
    $results = @()
    $ddppproperties = "whencreated"
    foreach($domain in (get-adforest).domains){
        try{$results += Get-ADDefaultDomainPasswordPolicy  `
            -server $domain | select $hash_domain, *}
        catch{"CollectADDDPP - $domain - $($_.Exception)" | out-file $default_err_log -append}
    }
    $results | select "Domain","ComplexityEnabled","DistinguishedName","LockoutDuration", `
        "LockoutObservationWindow","LockoutThreshold","MaxPasswordAge","MinPasswordAge","MinPasswordLength", `
        "PasswordHistoryCount","ReversibleEncryptionEnabled"
}
Function CollectADLDAPQueryPolicy{
    write-host "Collecting AD LDAP Query Policies"
    $results=@()
    $query_results = @()
    $searchbase = "CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,$((get-adrootdse).configurationNamingContext)"
    $LDAPQPProperties = @("whenchanged","Whencreated","lDAPAdminLimits")
    $query_results = get-adobject -filter {objectClass -eq "queryPolicy"} -SearchBase $searchbase `
        -properties $LDAPQPProperties
   
    foreach($qp in $query_results){
        foreach($setting in ($qp).lDAPAdminLimits){
            $Results += $qp | select name,$hash_whencreated,$hash_whenchanged, `
                @{name='Setting';expression={$($setting.split("=")[0])}}, `
                @{name='Value';expression={$($setting.split("=")[1])}}
        }
    }
    $results
}
Function runReportArchival{
    param($Achivetokeep=5)
        #count the number of zip files in the directory and delete older zip files
        $achivecount = (Get-ChildItem $archivereportpath *.zip).count - $Achivetokeep
        if($achivecount -gt 0){
            Get-ChildItem $reportpath *.zip  | Sort CreationTime | Select -first $achivecount | Remove-Item -force
        }
        #archive reports
        if(get-command Compress-Archive){
            Write-host "Zipping up the reports"
            gci $reportpath\*.csv | Compress-Archive -DestinationPath "$reportpath\ADReport_$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).zip"
        }     
}
Function runallCollectfunctions{
    (dir function: | where name -like collectAD*).name | foreach{$script_function = "$($_) | export-csv $reportpath\$($_ -Replace("collect","report")).csv -notypeinformation"
     $runtime = Measure-Command {Invoke-Expression -Command $script_function} | `
            select @{name='RunDate';expression={get-date -format d}},`
            @{name='Function';expression={$script_function}}, `
            @{name='Hours';expression={$_.hours}}, `
            @{name='Minutes';expression={$_.Minutes}}, `
            @{name='Seconds';expression={$_.Seconds}}
      $runtime | export-csv $time_log -append -notypeinformation
    }
}
Function runSiteMappingfunctions{
    CollectADDomainControllers | export-csv $reportpath\reportADDomainControllers.csv -notypeinformation
    CollectADUsers -sitemap | export-csv $reportpath\reportADUsers.csv -notypeinformation
    CollectADComputers -sitemap | export-csv $reportpath\reportADComputers.csv -notypeinformation
    CollectADSiteDetails | export-csv $reportpath\reportADSiteDetails.csv -notypeinformation
    CollectADSubnets | export-csv $reportpath\reportADSubnets.csv -notypeinformation
    CollectADSiteLinks | export-csv $reportpath\reportADSiteLinks.csv -notypeinformation
}
function CleanupReports{
    param([switch]$runusercleanup,
    [switch]$rungroupcleanup,
    [switch]$runcomputercleanup,
    [switch]$runallcleanup)

    if($runusercleanup -or $runallcleanup){
        $results = @()
        #Create User Reports
        write-host "Generating Cleanup User Reports"
        $reportfile = "$reportpath\reportADUsers.csv"
        If ($(Try {Test-Path $reportfile} Catch {$false}))
        {
            write-host "Existing User Reports Found"
            $results = import-csv $reportfile
            $results | where sidhistory -eq "Review" | export-csv "$reportpath\cleanupADUsers-SidHistorySameDomain.csv" -NoTypeInformation
            $results | where DoesNotRequirePreAuth -eq $true | export-csv "$reportpath\cleanupADUsers-DoesNotRequirePreAuth.csv" -NoTypeInformation
            $results | where ReversibleEncryption -eq $true | export-csv "$reportpath\cleanupADUsers-ReversibleEncryption.csv" -NoTypeInformation
            $results | where UseDesKeyOnly -eq $true | export-csv "$reportpath\cleanupADUsers-UseDesKeyOnly.csv" -NoTypeInformation
            $results | where Trustedfordelegation -eq $true | export-csv "$reportpath\cleanupADUsers-UnConstrainedKerbDelegationEnabled.csv" -NoTypeInformation
            $results | where TrustedToAuthForDelegation -eq $true | export-csv "$reportpath\cleanupADUsers-KerbDelegationTransitioningEnabled.csv" -NoTypeInformation
            $results | where PasswordNeverSet -eq $true | export-csv "$reportpath\cleanupADUsers-PasswordNeverSet.csv" -NoTypeInformation
            $results | where PasswordNotRequired -eq $true | export-csv "$reportpath\cleanupADUsers-PasswordNotRequired.csv" -NoTypeInformation
            $results | where PasswordNeverExpires -eq $true | export-csv "$reportpath\cleanupADUsers-PasswordNeverExpires.csv" -NoTypeInformation
            $results | where Stale -eq $true | export-csv "$reportpath\cleanupADUsers-Stale.csv" -NoTypeInformation
            $results | where DefaultPrimaryGroup -ne $true | export-csv "$reportpath\cleanupADUsers-PrimaryGroupIDNotDomainUsers.csv" -NoTypeInformation
            #$results | where {$_.SPN -eq $true -and $_.admincount -eq 1} | export-csv "$reportpath\cleanupADUsers-PrimaryGroupIDNotDomainUsers.csv" -NoTypeInformation
            $results | where {[convert]::ToInt32($($_.PwdAgeinDays)) -gt 365} -ErrorAction SilentlyContinue | export-csv "$reportpath\cleanupADUsers-PWDAgeover1Year.csv" -NoTypeInformation
            $results | where {[convert]::ToInt32($($_.PwdAgeinDays)) -gt 1825} | export-csv "$reportpath\cleanupADUsers-PWDAgeover5Year.csv" -NoTypeInformation
            $results | where {[convert]::ToInt32($($_.PwdAgeinDays)) -gt 3650} | export-csv "$reportpath\cleanupADUsers-PWDAgeover10Year.csv" -NoTypeInformation
        }else{
            write-host "Existing User Reports Not Found"
            CollectADUsers | export-csv $reportfile -NoTypeInformation
            CleanupReports -runusercleanup
        }
    }
    if($rungroupcleanup -or $runallcleanup){
        $results = @()
        #Create Group Reports
        write-host "Generating Cleanup Group Reports"
        $reportfile = "$reportpath\reportADGroups.csv"
        If ($(Try {Test-Path $reportfile} Catch {$false}))
        {
            write-host "Existing Group Reports Found"
        }else{
            write-host "Existing Group Reports Not Found"
            CollectADGroups | export-csv $reportfile -NoTypeInformation
            CleanupReports -rungroupcleanup
        }
    }

    if($runcomputercleanup -or $runallcleanup){
        $results = @()
        #Create Group Reports
        write-host "Generating Cleanup Computer Reports"
        $reportfile = "$reportpath\reportADComputers.csv"
        If ($(Try {Test-Path $reportfile} Catch {$false}))
        {
            write-host "Existing Computer Reports Found"
        }else{
            write-host "Existing Computer Reports Not Found"
            CollectADComputers | export-csv $reportfile -NoTypeInformation
            CleanupReports -runcomputercleanup
        }
    }
}
Function showMenu{
    cls
    Write-host -ForegroundColor yellow "Select the AD Report to run:"
    Write-host "   0 - Collect All AD Reports"
    Write-host "   1 - Collect AD Computers"
    Write-host "   2 - Collect AD Groups"
    Write-host "   3 - Collect AD Users"
    Write-host "   4 - Collect AD Site Mapping Data"
    Write-host "   5 - Not Available"
    write-host "   6 - Collect AD Privileged Group History"
    Write-host "   7 - Not Available"
    Write-host "   8 - Not Available"
    Write-host "   9 - Not Available"
    Write-host "   10 - Create Cleanup List from Reports"
    $xMenuChoiceA = read-host "Please enter an option 0 to 10..."

    switch($xMenuChoiceA){
        0{runallCollectfunctions}
        1{#CollectADComputers
        $runtime = Measure-Command {CollectADComputers | export-csv $reportpath\reportADComputers.csv -notypeinformation} | `
                select @{name='RunDate';expression={get-date -format d}},`
                @{name='Function';expression={"CollectADComputers"}}, `
                @{name='Hours';expression={$_.hours}}, `
                @{name='Minutes';expression={$_.Minutes}}, `
                @{name='Seconds';expression={$_.Seconds}}
                $runtime | export-csv $time_log -append -notypeinfor6mation}
        2{#CollectADGroups
        $runtime = Measure-Command {CollectADGroups | export-csv $reportpath\reportADGroups.csv -notypeinformation} | `
                select @{name='RunDate';expression={get-date -format d}},`
                @{name='Function';expression={"CollectADGroups"}}, `
                @{name='Hours';expression={$_.hours}}, `
                @{name='Minutes';expression={$_.Minutes}}, `
                @{name='Seconds';expression={$_.Seconds}} 
                $runtime | export-csv $time_log -append -notypeinformation}
        3{#CollectADUsers
        $runtime = Measure-Command {CollectADUsers | export-csv $reportpath\reportADUsers.csv -notypeinformation} | `
                select @{name='RunDate';expression={get-date -format d}},`
                @{name='Function';expression={"CollectADUsers"}}, `
                @{name='Hours';expression={$_.hours}}, `
                @{name='Minutes';expression={$_.Minutes}}, `
                @{name='Seconds';expression={$_.Seconds}} 
                $runtime|export-csv $time_log -append -notypeinformation}
        4{runSiteMappingfunctions}
        5{}
        6{#CollectadPrivilegedGroupChanges
        $runtime = Measure-Command {CollectADPrivilegedGroupChanges | export-csv $reportpath\reportPrivilegedGroupChanges.csv -notypeinformation} | `
                select @{name='RunDate';expression={get-date -format d}},`
                @{name='Function';expression={"CollectADPrivilegedGroupChanges"}}, `
                @{name='Hours';expression={$_.hours}}, `
                @{name='Minutes';expression={$_.Minutes}}, `
                @{name='Seconds';expression={$_.Seconds}} 
                $runtime|export-csv $time_log -append -notypeinformation}
        10{CleanupReports -runallcleanup}
    }
}
#region Support Functions
function Get-ipSite{
	param([string]$ip
	)
	#Great idea from http://superuser.com/questions/758372/query-site-for-given-ip-from-ad-sites-and-services/758398
	$site = nltest /DSADDRESSTOSITE:$ip /dsgetsite 2>$null
	if ($LASTEXITCODE -eq 0) {
		$split = $site[3] -split "\s+"
		# validate result is for an IPv4 address before continuing
		if ($split[1] -match [regex]"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$") {
			"" | select @{l="ADSite";e={$split[2]}}, @{l="ADSubnet";e={$split[3]}}
		}
	}
}
#endregion
#region hashes
    $hash_domain = @{name='Domain';expression={$domain}}
    $hash_whenchanged = @{Name="whenchanged";
        Expression={($_.whenchanged).ToString('MM/dd/yyyy')}}
    $hash_whencreated = @{Name="whencreated";
        Expression={($_.whencreated).ToString('MM/dd/yyyy')}}
    $hash_NamingContext = @{name='NamingContext';
        expression={$sb}}
    $hash_pwdLastSet = @{Name="pwdLastSet";
        Expression={if($_.PwdLastSet -ne 0){([datetime]::FromFileTime($_.pwdLastSet).ToString('MM/dd/yyyy'))}}}
    $hash_lastLogonTimestamp = @{Name="LastLogonTimeStamp";
        Expression={if($_.LastLogonTimeStamp -like "*"){([datetime]::FromFileTime($_.LastLogonTimeStamp).ToString('MM/dd/yyyy'))}}}
    $hash_parentou = @{name='ParentOU';expression={
        $($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}} 
    $hash_computerstale = @{Name="Stale";Expression={if(((($_.pwdLastSet -lt $d.ToFileTimeUTC()) -or ($_.pwdLastSet -ne 0)) -and 
        (($_.LastLogonTimeStamp -lt $d.ToFileTimeUTC()) -or ($_.LastLogonTimeStamp -notlike "*")) -and ($_.IPv4Address -eq $null)) -and 
        (!($_.serviceprincipalname -like "*MSClusterVirtualServer*"))){$True}else{$False}}}
    $hash_sidhistory = @{Name="sidHistory";Expression={if($_.sidhistory){if($forest_sids -like $_.SIDHistory) 
        {"Review"}else{$True}}else{$False}}}
    $hash_spn = @{Name="SPN";
        Expression={if($_.servicePrincipalName){$True}else{$False}}}
    $hash_PrimaryGroup = @{Name="DefaultPrimaryGroup";
        Expression={if($_.PrimaryGroupID -eq $Default_Group_ID){$True}else{$_.PrimaryGroupID}}}
    $hash_memlastchange = @{name='MembershipLastChanged';
        expression={if($_."msDS-ReplValueMetaData"){($_ | Select-Object -ExpandProperty "msDS-ReplValueMetaData" | 
            foreach {([XML]$_.Replace("`0","")).DS_REPL_VALUE_META_DATA | where { $_.pszAttributeName -eq "member" }} | 
            select -first 1).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}else{"Never Used"}}}
    $hash_rid = @{name='Rid';expression={$([int]($_.objectsid -split("-"))[7])}}
    $hash_members = @{name='Member';
        expression={if($_.Member){$true}}}
    $hash_memberof = @{name='Memberof';expression={if($_.Memberof){$true}}}
    $hash_oudirectChild = @{name='DirectChildCount';
        expression={$_."msds-approx-immed-subordinates"}}
    $hash_gpLink = @{name='Linked GPOs';expression={if($_.gplink){$true}}}
    $hash_gpOptions = @{name='GPO Inheritance';expression={if($_.gpOptions -eq 1){"Blocked"}}}
    $hash_FGPPAppliesTo = @{name='AppliesToSet';expression={if($_.AppliesTo){$true}}}
    $hash_AccountNotDelegated = @{Name="AccountNotDelegated";
        Expression={if($_.UserAccountControl -band 1048576){$True}else{$False}}}
    $hash_UseDesKeyOnly = @{Name="UseDesKeyOnly";Expression={if($_.UserAccountControl -band 2097152){$True}else{$False}}}
    $hash_ReversibleEncryption = @{Name="ReversibleEncryption";
        Expression={if($_.UserAccountControl -band 128){$True}else{$False}}}
    $hash_DoesNotRequirePreAuth = @{Name="DoesNotRequirePreAuth";
        Expression={if($_.UserAccountControl -band 4194304){$True}else{$False}}}
    $hash_PasswordNeverExpires = @{Name="PasswordNeverExpires";
        Expression={if($_.UserAccountControl -band 65536){$True}else{$False}}}
    $hash_PasswordNotRequired = @{Name="PasswordNotRequired";
        Expression={if($_.UserAccountControl -band 32){$True}else{$False}}}
    $hash_PasswordNeverSet = @{Name="PasswordNeverSet";
        Expression={if($_.pwdLastSet -eq 0){$True}else{$False}}}
    $hash_SmartCardRequired = @{Name="SmartCardRequired";
        Expression={if($_.UserAccountControl -band 262144){$True}else{$False}}}
    $hash_AuthNPolicy = @{Name="AuthNPolicy";Expression={if("msDS-AssignedAuthNPolicy"){$True}else{$False}}}
    $hash_AuthNPolicySilo = @{Name="AuthNPolicySilo";
        Expression={if("msDS-AssignedAuthNPolicySilo"){$True}else{$False}}}
    $hash_PwdAgeinDays = @{Name="PwdAgeinDays";
        Expression={if($_.PwdLastSet -ne 0){(new-TimeSpan([datetime]::FromFileTimeUTC($_.PwdLastSet)) $(Get-Date)).days}else{0}}}
    $hash_userstale = @{Name="Stale";Expression={if((($_.pwdLastSet -lt $d.ToFileTimeUTC()) -or ($_.pwdLastSet -ne 0)) -and 
        (($_.LastLogonTimeStamp -lt $d.ToFileTimeUTC()) -or ($_.LastLogonTimeStamp -notlike "*")) -and 
        ($_.whencreated -lt $d)){$True}else{$False}}}
    $hash_istgOrphaned = @{name='istgOrphaned';expression={if($_.interSiteTopologyGenerator -like "*0ADEL*"){$true}else{$false}}}
    $hash_subnetcount = @{name='SubnetCount';expression={($_.siteObjectBL | measure-object).count}}
    $hash_dcinsitecount = @{name='DCinSiteCount';expression={(Get-ADObject -Filter 'objectClass -eq "server"'`
                     -searchbase $_.DistinguishedName | measure-object).count}}
    $hash_sitelinkcount = @{name='SiteLinkCount';expression={$sn = $(($_).name);
        (Get-ADReplicationSiteLink -Filter 'SitesIncluded -eq $sn' | measure-object).count}}
    $hash_SiteAddress = @{name='Address';expression={}}
    $hash_SiteCity =@{name='City';expression={}}
    $hash_SiteState = @{name='State';expression={}}
    $hash_SiteCountry = @{name='Country';expression={}}
    $hash_SubnetSiteName = @{name='SiteName';expression={if($_.siteobject){(Get-ADReplicationSite $_.siteObject).name}else{$false}}}
    $hash_SiteCount = @{name='SiteCount';expression={($_.siteList | measure).count}}
    $hash_SiteString = @{name='Sites';expression={$SiteList}}
    $hash_usercity = @{name='City';expression={$_.l}}
    $hash_userstate = @{name='State';expression={$_.st}}
    $hash_userc = @{name='Country';expression={$_.c}} 
    $hash_userco = @{name='Country1';expression={$_.co}}
    $hash_usercountrycode = @{name='Country2';expression={$_.countryCode}}
#endregion

if(!($skipMenu)){
    showMenu
}else{
    runallCollectfunctions
}

#runs Function to create a compressed version of the script
runReportArchival

$results = $null
write-host "Report Can be found here $reportpath"

dir function: | where name -like collectAD* | remove-item -force
