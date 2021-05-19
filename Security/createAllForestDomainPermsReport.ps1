#Requires -Module ActiveDirectory, GroupPolicy
#Requires -version 3.0
#Requires -RunAsAdministrator

<#PSScriptInfo
.VERSION 2021.5.19
.GUID 5e7bfd24-88b9-4e4d-99fd-c4ffbfcf5be6
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
.DESCRIPTION 
 this helps locate most permission end points and expands group membership
#> 
Param($reportpath = "$env:userprofile\Documents")

cd $reportpath

function getAllDomains{
    get-adforest | select -expandproperty domains -PipelineVariable domain | where {get-addomain -server $domain}
    get-adforest | select -expandproperty domains -PipelineVariable domain | foreach {(get-adtrust -filter * -Server $domain).name} | where {try{get-addomain -server $_}catch{$false}}
}

function getAllPrivgroups{
    param()
        foreach($domain in $domains){
        #try{get-adgroup -filter 'admincount -eq 1 -and iscriticalsystemobject -notlike "*"' `
        #    -server $domain -Properties * | select $hash_domain,distinguishedname,SamAccountName,objectSid,admincount,iscriticalsystemobject,Members}
        #    catch{write-host "error connecting to $domain" -ForegroundColor Red}
        try{get-adgroup -filter '(admincount -eq 1 -and iscriticalsystemobject -like "*") -or samaccountname -eq "Cert Publishers"' `
            -server $domain -Properties * | select $hash_domain,distinguishedname,SamAccountName,objectSid,admincount,iscriticalsystemobject, `
                Members,@{name='RelationShip';expression={"Privileged Group Membership"}}}
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
    
        try{get-adgroup -filter 'samaccountname -eq "Schema Admins" -or samaccountname -eq "Group Policy Creator Owners" -or samaccountname -eq "Key Admins" -or samaccountname -eq "Enterprise Key Admins" -or samaccountname -eq "Remote Desktop Users" -or samaccountname -eq "Cryptographic Operators"' `
            -server $domain -Properties * | select $hash_domain,distinguishedname,SamAccountName,objectSid,admincount,iscriticalsystemobject, `
                Members,@{name='RelationShip';expression={"Privileged Group Membership"}}}
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
    
        try{get-adgroup -filter '(iscriticalsystemobject -like "*") -and (samaccountname -ne "Domain Users") -and (samaccountname -ne "Users") -and (samaccountname -ne "Domain Controllers")' `
            -server $domain -Properties * | select $hash_domain,distinguishedname,SamAccountName,objectSid,admincount,iscriticalsystemobject, `
            Members,@{name='RelationShip';expression={"Privileged Group Membership"}}}
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
    }
    if(test-path .\pgpo.tmp){
        write-host "attempting: $($_.samaccountname)"
        import-csv .\pgpo.tmp -pv perm | where {$_.objectClass -eq "Group"} | select domain, samaccountname -unique | foreach{
            try{get-adgroup -identity $_.samaccountname -server $_.domain -Properties * | `
                select @{name='Domain';expression={$perm.domain}},distinguishedname,SamAccountName,objectSid,admincount,iscriticalsystemobject, `
                    Members,@{name='RelationShip';expression={"GPO ACL Group Membership"}}}
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
        }
    }
    if(test-path .\dacl.tmp){
        import-csv .\dacl.tmp -pv perm | select domain, samaccountname -unique | foreach{
            write-host "attempting: $($_.samaccountname)"
            try{get-adgroup -identity $_.samaccountname -server $_.domain -Properties * | `
                select @{name='Domain';expression={$perm.domain}},distinguishedname,SamAccountName,objectSid,admincount,iscriticalsystemobject, `
                    Members,@{name='RelationShip';expression={"AD ACL Group Membership"}}}
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
        }
    }
    
    if(test-path .\dcura.tmp){
        import-csv .\dcura.tmp -pv perm | select domain, samaccountname -unique | foreach{
            write-host "attempting: $($_.samaccountname)"
            try{get-adgroup -identity $_.samaccountname -server $_.domain -Properties * | `
                select @{name='Domain';expression={$perm.domain}},distinguishedname,SamAccountName,objectSid,admincount,iscriticalsystemobject, `
                    Members,@{name='RelationShip';expression={"DC User Right Group Membership"}}}
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
        }
    }
}

function getschemaguids{
    foreach($domain in $domains){
    write-host "$domain"
    try{Get-ADObject -SearchBase (Get-ADRootDSE  -Server $domain).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID  -server $domain | `
    ForEach-Object {try{$global:schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}catch{}}}
        catch{write-host "error connecting to $domain" -ForegroundColor Red}

    try{Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE -Server $domain).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' `
    -Properties name, rightsGUID -server $domain | `
    ForEach-Object {try{$global:schemaIDGUID.add([System.GUID]$_.rightsGUID,$_.name)}catch{}}}
        catch{write-host "error connecting to $domain" -ForegroundColor Red}
    }
}

function getADPermissions{
    param()
    foreach($domain in $domains){
        write-host "$domain"
        try{Get-ADObject "CN=AdminSDHolder,$((get-addomain -Server $domain).SystemsContainer)" -server $domain -Properties "msds-approx-immed-subordinates",nTSecurityDescriptor -pv container | `
            select DistinguishedName -ExpandProperty nTSecurityDescriptor | select @{name='Domain';expression={$domain}},distinguishedname -expandproperty access -pv perm }
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
        try{Get-ADObject "$((get-addomain -Server $domain).DistinguishedName)" -server $domain -Properties "msds-approx-immed-subordinates",nTSecurityDescriptor -pv container | `
            select DistinguishedName -ExpandProperty nTSecurityDescriptor | select @{name='Domain';expression={$domain}},distinguishedname -expandproperty access -pv perm }
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
        try{Get-ADObject "$((get-addomain -Server $domain).DomainControllersContainer)" -server $domain -Properties "msds-approx-immed-subordinates",nTSecurityDescriptor -pv container | `
            select DistinguishedName -ExpandProperty nTSecurityDescriptor | select @{name='Domain';expression={$domain}},distinguishedname -expandproperty access -pv perm }
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
        Get-ADReplicationSite -filter * -server $domain -pv site | foreach{
            try{Get-ADObject "$($site.DistinguishedName)" -server $domain -Properties "msds-approx-immed-subordinates",nTSecurityDescriptor -pv container | `
            select DistinguishedName -ExpandProperty nTSecurityDescriptor | select @{name='Domain';expression={$domain}},distinguishedname -expandproperty access -pv perm }
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
        }
    }
}
function getADAcls{
    
    getADPermissions | select @{name='ScopeDomain';expression={$_.domain}}, `
        @{name='ScopeSAM';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$global:schemaIDGUID.Item($_.objectType)}}}, `
        @{name='ScopeDN';expression={$_.DistinguishedName}},@{name='ScopeSID';expression={}},@{name='RelationShip';expression={"ADPermission"}}, `
        @{name='Domain';expression={if((($_.IdentityReference -split "\\").count -gt 1) -and (($_.IdentityReference -split "\\")[0] -notin "NT AUTHORITY","Everyone","BUILTIN")){($_.IdentityReference -split "\\")[0]}else{$_.domain}}}, @{name='distinguishedname';expression={}}, `
        @{name='samAccountname';expression={if(($_.IdentityReference -split "\\").count -gt 1){($_.IdentityReference -split "\\")[1]}else{$_.IdentityReference}}}, `
        objectClass, @{name='Permission';expression={$_.ActiveDirectoryRights}}
        
}

function getGpoPermissions{
    foreach($domain in $domains){
        write-host "$domain"
        try{Get-GPO -all -domain $domain -Server $domain -pv gpo | foreach{
            Get-GPPermissions -Name $gpo.DisplayName -all -DomainName $gpo.DomainName -server $gpo.domainname -pv gpp
        } | select @{name='ScopeDomain';expression={$domain}}, `
                @{name='ScopeSAM';expression={$gpo.DisplayName}},@{name='ScopeDN';expression={$gpo.path}}, `
                @{name='ScopeSID';expression={}},@{name='RelationShip';expression={"GPOPermission"}}, `
                @{name='Domain';expression={if($gpp.trustee.domain -eq "NT AUTHORITY"){$domain}else{$gpp.trustee.domain}}},distinguishedname, `
                @{name='samAccountname';expression={$gpp.trustee.name}}, `
                @{name='objectClass';expression={$gpp.trustee.SidType}},@{name='objectSid';expression={$gpp.trustee.sid}}, `
                @{name='Permission';expression={$gpp.Permission}} | where {$_.permission -notin "gporead","gpoapply"}}
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
    }
}

function getDCGPOURA{
    foreach($domain in $domains){
    get-adorganizationalunit "$((get-addomain -Server $domain).DomainControllersContainer)" -server $domain -Properties gplink | select -ExpandProperty gplink | foreach{
    $_ -split "," | foreach{if($_ -match "[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"){
    #$matches[0]
    [xml]$report = Get-GPOReport -guid $matches[0] -ReportType Xml -Domain $domain -ErrorAction SilentlyContinue 
    foreach($userright in ($report.GPO.Computer.extensiondata.extension.UserRightsAssignment)){
    $userright | select -ExpandProperty member | foreach{
    $_.name.'#text' | select @{name='ScopeDomain';expression={$domain}}, `
                @{name='ScopeSAM';expression={$report.GPO.Name}},@{name='ScopeDN';expression={}}, `
                @{name='ScopeSID';expression={$matches[0]}}, `
                @{name='RelationShip';expression={"Domain Controller User Right Assignment"}}, `
                @{name='Domain';expression={if((($_ -split "\\").count -gt 1) -and (($_ -split "\\")[0] -notin "NT AUTHORITY","Everyone","BUILTIN","NT SERVICE")){
                    ($_ -split "\\")[0]}else{$domain}}}, distinguishedname , `
                @{name='samAccountname';expression={if(($_ -split "\\").count -gt 1){($_ -split "\\")[1]}else{$_}}}, `
                @{name='objectClass';expression={}},@{name='objectSid';expression={}}, `
                @{name='Permission';expression={$userright.Name}}
}}}}}}}



function getsidhistory{
    foreach($group in ($groups | select samaccountname, objectsid -Unique)){
        $objsid = $null; $objsid = $group.objectsid.value
        foreach($domain in $domains){
        write-host "$domain"
        try{get-adobject -filter {sidhistory -eq $objsid}  -Properties * -server $domain | select @{name='ScopeDomain';expression={}}, `
                @{name='ScopeSAM';expression={$group.SamAccountName}},@{name='ScopeDN';expression={}}, `
                @{name='ScopeSID';expression={$group.objectsid}},@{name='RelationShip';expression={"SidHistory"}}, `
                @{name='Domain';expression={$domain}},distinguishedname, samaccountname,ObjectClass,objectsid, `
                @{name='enabled';expression={if($_.useraccountcontrol -band 2){$false}else{$true}}}}
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
        }
    }

    import-csv .\pgm.tmp | select Domain,distinguishedname,samaccountname,objectsid -unique -pv obj | `
        where {$_.objectsid -notin $groups.objectsid} | foreach{$objsid = $null; $objsid = $obj.objectsid
            foreach($domain in $domains){
            #write-host "looking for sid: $objsid in $domain"
            try{get-adobject -filter {sidhistory -eq $objsid}  -Properties * -server $domain | select @{name='ScopeDomain';expression={$obj.domain}}, `
                @{name='ScopeSAM';expression={$obj.SamAccountName}},@{name='ScopeDN';expression={$obj.distinguishedname}}, `
                @{name='ScopeSID';expression={$obj.objectsid}},@{name='RelationShip';expression={"SidHistory"}}, `
                @{name='Domain';expression={$domain}},distinguishedname, samaccountname,ObjectClass,objectsid, `
                @{name='enabled';expression={if($_.useraccountcontrol -band 2){$false}else{$true}}}}
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
    }}
}
function getPrimaryGroup{
    import-csv .\pgm.tmp | select Domain,distinguishedname,samaccountname,objectsid -unique -pv obj | foreach{
        $rid = $null; $rid = ($obj.objectsid -split "-")[-1]
        try{get-adobject -filter {primaryGroupID -eq $rid}  -Properties * -server $obj.domain | select @{name='ScopeDomain';expression={$obj.domain}}, `
                @{name='ScopeSAM';expression={$obj.SamAccountName}},@{name='ScopeDN';expression={$obj.distinguishedname}}, `
                @{name='ScopeSID';expression={$obj.objectsid}},@{name='RelationShip';expression={"PrimaryGroup"}}, `
                @{name='Domain';expression={$obj.domain}},distinguishedname, samaccountname,ObjectClass,objectsid, `
                @{name='enabled';expression={if($_.useraccountcontrol -band 2){$false}else{$true}}}}
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
    }
    foreach($group in ($groups | select Domain,distinguishedname,samaccountname,objectsid -Unique)){
        $objsid = $null; $objsid = $group.objectsid.value
        foreach($domain in $domains){
        #write-host "$domain"
        try{get-adobject -filter {sidhistory -eq $objsid}  -Properties * -server $domain | select @{name='ScopeDomain';expression={$group.Domain}}, `
                @{name='ScopeSAM';expression={$group.SamAccountName}},@{name='ScopeDN';expression={$group.distinguishedname}}, `
                @{name='ScopeSID';expression={$group.objectsid}},@{name='RelationShip';expression={"PrimaryGroup"}}, `
                @{name='Domain';expression={$domain}},distinguishedname, samaccountname,ObjectClass,objectsid, `
                @{name='enabled';expression={if($_.useraccountcontrol -band 2){$false}else{$true}}}}
            catch{write-host "error connecting to $domain" -ForegroundColor Red}
        }
    }
}
function findObject{
    param($odn, $domain)
    #Write-Host "Starting $odn in $domain"
    if(!($script:alreadyEnumerated.containskey($odn))){
    $script:alreadyEnumerated.add($odn,$true)
    $found_obj = try{get-adobject $odn -Properties * -server $domain | select @{name='Domain';expression={$domain}}, *}catch{}
   
    for($i=0; $found_obj -eq $null ; $i++){
        #write-host "looking in $($domains[$i]) for $odn"
        $found_obj = try{get-adobject $odn -Properties * -server $domains[$i] | select @{name='Domain';expression={$domains[$i]}}, *}catch{}
    }
            
        if($found_obj.ObjectClass -eq "Group"){
            write-host "Expanding: $($found_obj.samaccountname)"
            $found_obj
            $found_obj | select -ExpandProperty member | foreach{
                findObject -odn $_ -domain $found_obj.domain
            }
        }else{$found_obj}
    }
}

function expandGroups{
    foreach($group in $groups){
        $group | select -expandProperty members | foreach{
            $script:alreadyEnumerated = @{}
            findObject -odn $_ -domain $group.domain | select @{name='ScopeDomain';expression={$group.domain}}, `
                @{name='ScopeSAM';expression={$group.SamAccountName}},@{name='ScopeDN';expression={$group.distinguishedname}}, `
                @{name='ScopeSID';expression={$group.objectsid}},@{name='Relationship';expression={$group.RelationShip}}, `
                domain,distinguishedname, samaccountname,ObjectClass,objectsid, `
                @{name='enabled';expression={if($_.useraccountcontrol -band 2){$false}else{$true}}}, `
                @{Name="pwdLastSet";
                    Expression={if($_.PwdLastSet -ne 0 -and $_.objectclass -eq "user"){([datetime]::FromFileTime($_.pwdLastSet).ToString('MM/dd/yyyy'))}}}, `
                @{Name="PwdAgeinDays";
                    Expression={if($_.PwdLastSet -ne 0){(new-TimeSpan([datetime]::FromFileTimeUTC($_.PwdLastSet)) $(Get-Date)).days}else{0}}}, `
                @{Name="LastLogonTimeStamp";
                    Expression={if($_.LastLogonTimeStamp -like "*"){if($_.objectclass -ne "group"){([datetime]::FromFileTime($_.LastLogonTimeStamp).ToString('MM/dd/yyyy'))}}}}, `
                @{name='CannotBeDelegated';expression={if($_.useraccountcontrol -band 1048576){$true}}}, `
                @{name='inProtectUsersGroup';expression={if($_.objectclass -eq "user"){isinProtectedUsers -udn $_.distinguishedname}}}, `
                @{Name="PasswordNeverExpires";Expression={if($_.objectclass -ne "group"){if($_.UserAccountControl -band 65536){$True}else{$False}}}}, `
                @{name='EncryptionType';expression={if($_.useraccountcontrol -band 2097152){"DES"}
                    else{if($_."msds-supportedencryptiontypes" -band 16){"AES256-HMAC"}
                    elseif($_."msds-supportedencryptiontypes" -band 8){"AES128-HMAC"}
                    else{if($_.objectclass -ne "group"){"RC4-HMAC"}}}}}
        }
    }
}

$hash_domain = @{name='Domain';expression={$domain}}
cls
write-host "Gathering all Domains in Forest and Trusted Domains"
$domains = getAllDomains | select -unique
write-host "Gathering GPO Permissions"
getGpoPermissions | export-csv .\pgpo.tmp -NoTypeInformation
write-host "Gathering GPO Settings"
getDCGPOURA | export-csv .\dcura.tmp -NoTypeInformation
write-host "Gathering Schema guids to translate AD Acls"
$global:schemaIDGUID = @{}
getSchemaGuids
write-host "Gathering Important AD ACLS"
getADAcls | export-csv .\dacl.tmp -NoTypeInformation
write-host "Gathering all ​​​​​​​Privileged  Groups"
$groups = getAllPrivgroups | select * -unique
#$groups | export-csv .\gp.tmp -notypeinformation
write-host "Getting all Group Members"
expandGroups | export-csv .\pgm.tmp -notypeinformation
write-host "Looking for sid history"
getsidhistory | export-csv .\pgsid.tmp -NoTypeInformation
write-host "Looking for non domain user primary group assignment"
getPrimaryGroup | export-csv .\pgsp.tmp -NoTypeInformation
import-csv @(dir *.tmp) | select ScopeDomain,ScopeSAM,ScopeDN,ScopeSID,RelationShip,Domain,DistinguishedName,sAMAccountName,ObjectClass, `
    objectSid,enabled,permission,pwdLastSet,PwdAgeinDays,LastLogonTimeStamp,CannotBeDelegated,inProtectUsersGroup,PasswordNeverExpires,EncryptionType | `
        export-csv ".\ImportantADPermissions_$(get-date -Format yyyyMMdd).csv" -notypeinformation


dir *.tmp | Compress-Archive -DestinationPath ".\privileged_$(get-date -Format yyyyMMdd).zip" -force
dir *.tmp | remove-item -force


write-host "Report found here: $reportpath\ImportantADPermissions_$(get-date -Format yyyyMMdd).csv "
write-host "Archive here: $reportpath\privileged_$(get-date -Format yyyyMMdd).zip"
