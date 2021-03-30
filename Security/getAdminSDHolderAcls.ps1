#Requires -Module ActiveDirectory
#Requires -version 3.0
#Requires -RunAsAdministrator

<#PSScriptInfo
.VERSION 2021.3.30
.GUID 96d7fd43-c37c-4c03-bafa-b282b4572926
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
 use this to find out who has ability to change settings, etc on admin creds.
#> 

param($reportpath = "$env:userprofile\Documents")
$schemaIDGUID = @{}
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID | `
    ForEach-Object {try{$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}catch{}}

Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' `
    -Properties name, rightsGUID | `
    ForEach-Object {try{$schemaIDGUID.add([System.GUID]$_.rightsGUID,$_.name)}catch{}}

function enumGroup {
    param($identity,$domain)
    if(($identity -split "\\")[0] -in "NT AUTHORITY","Everyone"){

    }elseif(($identity -split "\\")[0] -eq "BUILTIN"){
        try{get-adgroupmember -Identity ($identity -split "\\")[1] -Recursive -Server $domain}catch{}
    }else{
        try{get-adgroupmember -Identity ($identity -split "\\")[1] -Recursive -Server ($identity -split "\\")[0]}catch{}
    }
}

function gatherAdminSDHolder {
    $results = get-adforest | select -ExpandProperty domains -pv domain | foreach {
        $hash_domain = @{name='Domain';expression={$domain}}
        Get-ADObject "CN=AdminSDHolder,$((get-addomain -Server $domain).SystemsContainer)" -Properties "msds-approx-immed-subordinates",nTSecurityDescriptor -server $domain -pv container | `
            select DistinguishedName -ExpandProperty nTSecurityDescriptor | select distinguishedname -expandproperty access -pv perm | foreach{
                $_ | select $hash_domain,`
                DistinguishedName, IdentityReference, `
                AccessControlType, ActiveDirectoryRights, IsInherited, `
                @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaIDGUID.Item($_.objectType)}}}, `
                @{name='inheritedObjectTypeName';expression={$schemaIDGUID.Item($_.inheritedObjectType)}}, @{name='memberofGroup';expression={}}
    }}
    foreach($obj in $results){
        $obj
        enumGroup -identity $obj.IdentityReference -domain $obj.domain | select @{name='Domain';expression={$obj.domain}}, `
            @{name='DistinguishedName';expression={$obj.DistinguishedName}}, @{name='IdentityReference';expression={$_.samaccountname}}, `
            @{name='AccessControlType';expression={$obj.AccessControlType}}, @{name='ActiveDirectoryRights';expression={$obj.ActiveDirectoryRights}}, `
            @{name='IsInherited';expression={$obj.IsInherited}}, @{name='objectTypeName';expression={$obj.objectTypeName}}, `
            @{name='inheritedObjectTypeName';expression={$obj.inheritedObjectTypeName}},@{name='memberofGroup';expression={$obj.IdentityReference}}
    }
}

gatherAdminSDHolder | export-csv $reportpath\AdminSDHolder_permissions.csv -NoTypeInformation
