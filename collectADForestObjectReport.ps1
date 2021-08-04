#Requires -Module ActiveDirectory
#Requires -Module GroupPolicy
#Requires -version 4

<#PSScriptInfo
.VERSION 2021.7.27
.GUID 9e42b849-031e-4b82-9c77-4a18de5d9870
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


#>
param($reportpath=$env:USERPROFILE)

cd $reportpath

function collectADDomainController{
    get-adforest | select -ExpandProperty domains -pv domain | foreach{
        Get-ADDomainController -Filter * -server $domain |  `
            Select Name,OperatingSystem, Domain, Forest, @{Name="OperationMasterRoles";Expression={[string]$_.OperationMasterRoles}}, site
    }
}
function collectADSitesServices{
    $splat_params = @{'filter' = '*';
                    'properties' = '*'}
    $splat_select_params = @{'property' = 'name','Description','AutomaticInterSiteTopologyGenerationEnabled','AutomaticTopologyGenerationEnabled',`
                    'RedundantServerTopologyEnabled','ScheduleHashingEnabled','TopologyCleanupEnabled','TopologyDetectStaleEnabled','TopologyMinimumHopsEnabled',`
                    'UniversalGroupCachingEnabled','UniversalGroupCachingRefreshSite','WindowsServer2000BridgeheadSelectionMethodEnabled',`
                    'WindowsServer2000KCCISTGSelectionBehaviorEnabled','WindowsServer2003KCCBehaviorEnabled',`
                    'WindowsServer2003KCCIgnoreScheduleEnabled','WindowsServer2003KCCSiteLinkBridgingEnabled',`
                    $(@{name='gpLink';expression={if($_.gplink){$true}else{$false}}}),`
                    $(@{name='istgOrphaned';expression={if($_.interSiteTopologyGenerator -like "*0ADEL*"){$true}else{$false}}}),`
                    'whencreated','whenchanged','DistinguishedName'}

    get-adreplicationsite @splat_params | select-object @splat_select_params

}
function collectADSubnets{
    Get-ADReplicationSubnet -Filter * -Properties * -server (get-adforest).name | select name, whencreated,whenchanged, site
}
function CollectADSiteLinks{
    Get-ADReplicationSiteLink -Filter * -Properties * -server (get-adforest).name | select name, options, cost, InterSiteTransportProtocol, `
        ReplicationFrequencyInMinutes, ReplicationSchedule, replInterval, `
            @{Name="OperationMasterRoles";Expression={($_.siteList | foreach{Get-ADReplicationSite -Identity $_}).name -join(",")}}
}
function collectExchangeServers{
    Get-ADObject -LDAPFilter "(objectClass=msExchExchangeServer)" –SearchBase (Get-ADRootDSE).configurationNamingContext | Select  name
}
function collectADDHCPServers{
    Get-ADObject –SearchBase (Get-ADRootDSE).configurationNamingContext -Filter "objectclass -eq 'dhcpclass' -AND Name -ne 'dhcproot'" | select name
}
function collectADTrust{
    get-adforest | select -expandproperty domains -PipelineVariable domain | foreach{
    get-adtrust -filter * -Properties * -server $domain -PipelineVariable trust | select `
        @{name='Domain';expression={$domain}},name,securityIdentifier,Created, `
        Direction,trustType,DisallowTransivity,SelectiveAuthentication, `
        SIDFilteringForestAware, SIDFilteringQuarantined,TGTDelegation, `
        TrustAttributes,UsesAESKeys,UsesRC4Encryption,whenCreated,whenchanged,`
        @{name='trustAuthOutgoing';expression={(Get-ADReplicationAttributeMetadata `
            -filter {attributename -eq "trustAuthOutgoing"} -Server (get-addomain $domain).PDCEmulator `
            -Object ($trust).DistinguishedName).LastOriginatingChangeTime}}, `
        @{name='trustAuthIncoming';expression={(Get-ADReplicationAttributeMetadata `
            -filter {attributename -eq "trustAuthIncoming"} -Server (get-addomain $domain).PDCEmulator `
            -Object ($trust).DistinguishedName).LastOriginatingChangeTime}}}
}
function collectReplicationInformation{
    repadmin /showrepl * /csv | ConvertFrom-Csv
    Repadmin /showbackup | out-file ".\$((get-adforest).name)_adbackup.txt"
}

function collectADContainers{
    get-adforest | select -ExpandProperty domains -PipelineVariable domain | foreach{
        Get-ADOrganizationalUnit -filter * -properties "msds-approx-immed-subordinates" -server $domain -PipelineVariable ou | `
            where {$_."msds-approx-immed-subordinates" -ne 0} | select distinguishedname, `
                @{Name="domain";Expression={$domain}}
            get-adobject -ldapfilter "(objectclass=Container)" -SearchScope OneLevel -server $domain | select distinguishedname, `
                @{Name="domain";Expression={$domain}}}
}

function collectADUsers{
   
    $properties = "msDS-AssignedAuthNPolicySilo","msDS-AssignedAuthNPolicy","Trustedfordelegation","TrustedToAuthForDelegation", `
    "samaccountname","mailNickname","thumbnailPhoto","DisplayName","mail",'msRTCSIP-PrimaryUserAddress',"servicePrincipalName", `
    "UserPrincipalName","description","extensionAttribute7","manager","lastLogonTimestamp","whenchanged","extensionAttribute2", `
    "extensionAttribute1","enabled","AccountExpirationDate","UserAccountControl","PwdLastSet","msExchHomeServerName", `
    "msExchRecipientDisplayType","msExchUMEnabledFlags2","msExchRecipientTypeDetails",'msRTCSIP-UserEnabled','msRTCSIP-OptionFlags','msRTCSIP-Line', `
    "telephoneNumber","extensionAttribute3","extensionAttribute4","c","co","countryCode","extensionAttribute5","extensionAttribute6","physicalDeliveryOfficeName", `
    "extensionAttribute12","title","extensionAttribute11","extensionAttribute13","extensionAttribute8","WhenCreated","CanonicalName", `
    "DistinguishedName","PrimaryGroupID","admincount","sidhistory","PasswordExpired","iscriticalsystemobject","msds-keycredentiallink"
    
    foreach($sb in $searchbases){
        write-host "Scanning $($sb.distinguishedname)"
        try{get-aduser -filter * -Properties * -searchbase $sb.DistinguishedName -SearchScope OneLevel -server $sb.domain  | select $selectproperties}
            catch{}
    }
    

}
function reportADUsers{
    $WH4BProvisioned = @{N="WH4BProvisioned";e={if($_."msds-keycredentiallink"){$true}else{$false}}}
    $sidhistory = @{N="sidHistory";e={if($_.sidhistory){$True}else{$False}}}
    $PasswordNotRequired = @{n='UACPasswordNotRequired';e={$(if($_.UserAccountControl -band 32){$True}else{$false})}}
    $AccountNotDelegated = @{n='UACAccountNotDelegated';e={$(if($_.UserAccountControl -band 1048576){$True}else{$false})}}
    $DoesNotRequirePreAuth = @{n='UACDoesNotRequirePreAuth';e={$(if($_.UserAccountControl -band 4194304){$True}else{$false})}}
    $SmartCardRequired = @{n='UACSmartCardRequired';e={$(if($_.UserAccountControl -band 262144){$True}else{$false})}}
    $CannotChangePassword = @{n='UACCannotChangePassword';e={$(if($_.UserAccountControl -band 64){$True}else{$false})}}
    $UseDesKeyOnly = @{n='UACUseDesKeyOnly';e={$(if($_.UserAccountControl -band 2097152){$True}else{$false})}}
    $ReversibleEncryption = @{n='UACReversibleEncryption';e={if($_.UserAccountControl -band 128){$True}else{$False}}}
    $OU = @{n='OU';e={($_.CanonicalName -split '/')[0..(($_.CanonicalName -split '/').Count – 2)] -join '/'}}
    $PwdLastSet = @{N="PwdLastSet";e={if($_.PwdLastSet -ne 0){(Get-Date([datetime]::FromFileTime($_.PwdLastSet))).ToString('MM/dd/yyyy')}else{"Never"}}}
    $PwdAge = @{N="PwdAge";e={if($_.PwdLastSet -ne 0){(new-TimeSpan([datetime]::FromFileTimeUTC($_.PwdLastSet)) $(Get-Date)).days}else{"NA"}}}
    $PasswordChangeonNextLogon = @{N="PasswordChangeonNextLogon";e={if($_.pwdLastSet -eq 0){$True}else{$false}}}
    $LastLogonTimeStamp = @{N="LastLogonTimeStamp";e={if($_.LastLogonTimeStamp){(Get-Date([datetime]::FromFileTime($_.LastLogonTimeStamp))).ToString('MM/dd/yyyy')}Else{"Never"}}}
    $DoesPasswordExpire = @{n='UACDoesPasswordExpire';e={$(if($_.UserAccountControl -band 65536){$false}else{$true})}}
    $Description = @{n='Description';e={($_).description -replace '[^a-zA-Z0-9\s]', ''}}
    $thumbnailPhotoSize = @{N="thumbnailPhotoSize";e={[math]::round((($_.thumbnailPhoto.count)/1.33)/1kb,2)}}
    $WhenCreated = @{n='WhenCreated';e={(Get-Date($_.WhenCreated)).ToString('MM/dd/yyyy')}}
    $WhenChanged = @{n='WhenChanged';e={(Get-Date($_.WhenChanged)).ToString('MM/dd/yyyy')}}
    $spn = @{N="SPN";e={if($_.servicePrincipalName){$True}else{$False}}}
    
    collectADUsers | select domain, "msDS-AssignedAuthNPolicySilo","msDS-AssignedAuthNPolicy","Trustedfordelegation","TrustedToAuthForDelegation", `
    "samaccountname",$thumbnailPhotoSize,"DisplayName","mail",$spn, "UserPrincipalName",$Description,"manager", `
    "$LastLogonTimeStamp",$WhenChanged, "enabled","AccountExpirationDate",$PwdLastSet,$PwdAge, "telephoneNumber","c","co","countryCode","physicalDeliveryOfficeName", `
    "title",$WhenCreated,$OU, "DistinguishedName","PrimaryGroupID","admincount",$sidhistory,"PasswordExpired","iscriticalsystemobject", `
    $WH4BProvisioned, $DoesPasswordExpire,$PasswordChangeonNextLogon,$ReversibleEncryption,$UseDesKeyOnly,$CannotChangePassword, `
    $SmartCardRequired,$DoesNotRequirePreAuth,$AccountNotDelegated,$PasswordNotRequired, extensionAttribute*,  msExch*, msRTCSIP*

}
function collectADGroups {
    $properties = "distinguishedname","SID","samaccountname","DisplayName","groupscope","groupcategory","admincount", `
        "iscriticalsystemobject","sidhistory", "whencreated","description","managedby","mail","objectSid", `
        "ProtectedFromAccidentalDeletion", "msDS-ReplValueMetaData", `
        "msExchRecipientTypeDetails","whenchanged","CanonicalName"
    $selectproperties = $properties + @{Name="domain";Expression={$sb.domain}}
    foreach($sb in $searchbases){
        write-host "Scanning $($sb.distinguishedname)"
        get-adgroup -filter * -Properties $properties -searchbase $sb.DistinguishedName -SearchScope OneLevel -server $sb.domain `
            -ResultPageSize 256 -ResultSetSize $null | select $selectproperties
    }
}

function collectEmptyADGroups{
    foreach($sb in $searchbases){
        write-host "Scanning $($sb.distinguishedname)"
        get-adgroup -ldapfilter "(!(member=*))" -searchbase $sb.DistinguishedName -SearchScope OneLevel -server $sb.domain `
            -ResultPageSize 256 -ResultSetSize $null
    }
}

function reportADGroup{
    $emptygroups = @{}
    collectEmptyADGroups | foreach{
        $emptygroups.add($_.distinguishedname,$true)
    }
    $MembershipLastChanged = @{name='MembershipLastChanged';expression={[string]($_ | Select-Object -ExpandProperty "msDS-ReplValueMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_VALUE_META_DATA | where { $_.pszAttributeName -eq "member" }}| select -first 1).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}}
    $sidhistory = @{N="sidHistory";e={if($_.sidhistory){$True}else{$False}}}
    $OU = @{n='OU';e={($_.CanonicalName -split '/')[0..(($_.CanonicalName -split '/').Count – 2)] -join '/'}}
    $Description = @{n='Description';e={($_).description -replace '[^a-zA-Z0-9\s]', ''}}
    $WhenCreated = @{n='WhenCreated';e={(Get-Date($_.WhenCreated)).ToString('MM/dd/yyyy')}}
    $WhenChanged = @{n='WhenChanged';e={(Get-Date($_.WhenChanged)).ToString('MM/dd/yyyy')}}
    $Member = @{n='containsMembers';e={!($emptygroups.containskey($_.DistinguishedName))}}
    $rid = @{n='rid';e={[int]($_.objectSid.value -split("-"))[-1]}}

    collectADGroups | select domain, "distinguishedname","SID","samaccountname","DisplayName","groupscope","groupcategory","admincount", `
    "iscriticalsystemobject",$sidhistory, $WhenCreated,$Description,"managedby","mail",$rid, "ProtectedFromAccidentalDeletion", `
    $MembershipLastChanged,$Member, $WhenChanged,$OU, extensionAttribute*, msExch*

}
function collectADComputer {
        
    foreach($sb in $searchbases){
        write-host "Scanning $($sb.distinguishedname)"
        try{get-adcomputer -filter * -Properties ipv4address, ipv6address, LastLogonTimeStamp, pwdlastset,dnshostname, OperatingSystem, enabled,whencreated, `
            primaryGroupID,PasswordNotRequired,managedBy,admincount,Trustedfordelegation,sidHistory,usercertificate,TrustedToAuthForDelegation, `
            UseDESKeyOnly,userAccountControl, description,iscriticalsystemobject -searchbase $sb.DistinguishedName -SearchScope OneLevel -server $sb.domain  | `
            select @{N="Domain";E={$sb.domain}}, samaccountname, name, dnshostname,iscriticalsystemobject, operatingsystem, enabled, `
                @{N="PwdAgeinDays";E={if($_.PwdLastSet -ne 0){(new-TimeSpan([datetime]::FromFileTimeUTC($_.PwdLastSet)) $(Get-Date)).days}else{0}}}, `
                @{N="pwdLastSet";E={if(!($_.pwdlastset -eq 0)){([datetime]::FromFileTime($_.pwdLastSet))}}}, `
                @{N="LastLogonTimeStamp";E={if($_.LastLogonTimeStamp){([datetime]::FromFileTime($_.LastLogonTimeStamp))}}}, `
                @{N="sidHistory";E={[string]$($_.sidhistory)}}, `
                whencreated,Ipv4Address, Ipv6Address, primaryGroupID,PasswordNotRequired,admincount,Trustedfordelegation,TrustedToAuthForDelegation, `
                UseDESKeyOnly,userAccountControl, @{Name="userCertificateCount";Expression={$_.usercertificate.count}}, `
                sid,@{n='Description';e={$(($_).description -replace '[^a-zA-Z0-9\s]', '')}},@{n='ParentOU';e={$sb.DistinguishedName}},managedBy}
                    catch{}
    }
}
function collectADGPOLinks{
    $hash_gpo = get-adforest | select -expandproperty domains -PipelineVariable domain | foreach{get-gpo -All -Domain $domain} | group Id -AsHashTable -AsString
    get-adforest | select -expandproperty domains -PipelineVariable domain | foreach{
        get-adobject -filter {gplink -like "*"} -properties gplink -server $domain -PipelineVariable location | foreach{
            [array]$array_gplink = $($location.gplink).split("`\[") 
            [array]$array_gplink | foreach{
                $gpo_state =$null;[string]$gpo_state = (($_).split(";"))[1] -replace "]",""
                if($_){
                $guid = $_ -match "(([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12})"
                $location | select @{Name="Domain";Expression={$domain}},@{Name="DistinguishedName";Expression={$location.distinguishedname}}, `
                    @{Name="ObjectClass";Expression={$location.objectclass}},`
                    @{Name="GPOName";Expression={$hash_gpo[$matches[0]].DisplayName}},`
                    @{Name="Resolved";Expression={$hash_gpo.ContainsKey($matches[0])}},`
                    @{Name="GPOState";Expression={if($gpo_state -eq 0){"Normal"}elseif($gpo_state -eq 1){"GPO Disabled"}elseif($gpo_state -eq 2){"GPO Enforced"}else{"Block Inheritance"}}}, `
                    @{Name="GPOStatus";Expression={$hash_gpo[$matches[0]].GPOStatus}}
                }
            }
        }
    }
    get-adobject -filter {gplink -like "*"} -properties gplink -Searchbase $((Get-ADRootDSE).ConfigurationNamingContext) -PipelineVariable location | foreach{
        [array]$array_gplink = $($location.gplink).split("`\[") 
            [array]$array_gplink | foreach{
                $gpo_state =$null;[string]$gpo_state = (($_).split(";"))[1] -replace "]",""
                if($_){
                $guid = $_ -match "(([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12})"
                $location | select @{Name="Domain";Expression={$domain}},@{Name="DistinguishedName";Expression={$location.distinguishedname}}, `
                    @{Name="ObjectClass";Expression={$location.objectclass}},`
                    @{Name="GPOName";Expression={$hash_gpo[$matches[0]].DisplayName}},`
                    @{Name="Resolved";Expression={$hash_gpo.ContainsKey($matches[0])}},`
                    @{Name="GPOState";Expression={if($gpo_state -eq 0){"Normal"}elseif($gpo_state -eq 1){"GPO Disabled"}elseif($gpo_state -eq 2){"GPO Enforced"}else{"Block Inheritance"}}}, `
                    @{Name="GPOStatus";Expression={$hash_gpo[$matches[0]].GPOStatus}}
                }
            }
        }
    
}

function collectADPrivGroups{
    param()
        get-adforest | select -ExpandProperty domains -pv domain | foreach{
        #try{get-adgroup -filter 'admincount -eq 1 -and iscriticalsystemobject -notlike "*"' `
        #    -server $domain -Properties * | select $hash_domain,distinguishedname,SamAccountName,objectSid,admincount,iscriticalsystemobject,Members}
        #    catch{write-host "error connecting to $domain" -ForegroundColor Red}
        try{get-adgroup -filter '(admincount -eq 1 -and iscriticalsystemobject -like "*") -or samaccountname -eq "Cert Publishers"' `
            -server $domain -Properties * | select @{name='Domain';expression={$domain}},distinguishedname,SamAccountName,objectSid,admincount,iscriticalsystemobject, `
                Members}
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
    
        try{get-adgroup -filter 'samaccountname -eq "Schema Admins" -or samaccountname -eq "Group Policy Creator Owners" -or samaccountname -eq "Key Admins" -or samaccountname -eq "Enterprise Key Admins" -or samaccountname -eq "Remote Desktop Users" -or samaccountname -eq "Cryptographic Operators"' `
            -server $domain -Properties * | select @{name='Domain';expression={$domain}},distinguishedname,SamAccountName,objectSid,admincount,iscriticalsystemobject, `
                Members}
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
    
        try{get-adgroup -filter '(iscriticalsystemobject -like "*") -and (samaccountname -ne "Domain Users") -and (samaccountname -ne "Users") -and (samaccountname -ne "Domain Controllers")' `
            -server $domain -Properties * | select @{name='Domain';expression={$domain}},distinguishedname,SamAccountName,objectSid,admincount,iscriticalsystemobject, `
            Members}
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
    }
}

function collectADAdministrators{
    $gc = (Get-ADDomainController -Discover -Service "GlobalCatalog" | select hostname -First 1).HostName
    foreach($pg in collectADPrivGroups){
        $pg | select -ExpandProperty members -pv mem | foreach{
        get-adobject -Identity $mem -server "$gc`:3268" | select @{name='Domain';expression={$pg.domain}}, @{name='Group';expression={$pg.samaccountname}}, `
            @{name='Member';expression={$_.name}}, @{name='MemberDN';expression={$_.distinguishedname}},ObjectClass
        }
    }
}
function collectADPWDPolicy{
    Get-ADDefaultDomainPasswordPolicy
}

$searchbases = collectADContainers
write-host "Starting collectADDomainController"
collectADDomainController | export-csv ".\$((get-adforest).name)_addomaincontroller.csv" -NoTypeInformation
write-host "Starting collectADSitesServices"
collectADSitesServices  | export-csv ".\$((get-adforest).name)_adsites.csv" -NoTypeInformation
write-host "Starting collectADSubnets"
collectADSubnets | export-csv ".\$((get-adforest).name)_adsubnets.csv" -NoTypeInformation
write-host "Starting collectADSiteLinks"
collectADSiteLinks | export-csv ".\$((get-adforest).name)_adsitelinks.csv" -NoTypeInformation
write-host "Starting collectExchangeServers"
collectExchangeServers | export-csv ".\$((get-adforest).name)_adexchangeservers.csv" -NoTypeInformation
write-host "Starting collectADDHCPServers"
collectADDHCPServers | export-csv ".\$((get-adforest).name)_addhcpservers.csv" -NoTypeInformation
write-host "Starting collectADTrust"
collectADTrust | export-csv ".\$((get-adforest).name)_adtrust.csv" -NoTypeInformation
write-host "Starting collectReplicationInformation"
collectReplicationInformation | export-csv ".\$((get-adforest).name)_adreplication.csv" -NoTypeInformation
write-host "StartingreportADUsers "
reportADUsers | export-csv ".\$((get-adforest).name)_adusers.csv" -NoTypeInformation
write-host "Starting reportADGroup"
reportADGroup | export-csv ".\$((get-adforest).name)_adgroups.csv" -NoTypeInformation
write-host "Starting collectADComputer"
collectADComputer | export-csv ".\$((get-adforest).name)_adcomputers.csv" -NoTypeInformation
write-host "Starting collectADGPOLinks"
collectADGPOLinks | export-csv ".\$((get-adforest).name)_adgpolinks.csv" -NoTypeInformation
write-host "Starting collectADAdministrators"
collectADAdministrators | export-csv ".\$((get-adforest).name)_adadministrators.csv" -NoTypeInformation
write-host "Starting collectADPWDPolicy"
collectADPWDPolicy | export-csv ".\$((get-adforest).name)_adpasswordpolicy.csv" -NoTypeInformation

Compress-Archive -Path ".\$((get-adforest).name)*" -DestinationPath ".\report_$((get-adforest).name).zip" -force
write-host "Reports found here: $reportpath"
