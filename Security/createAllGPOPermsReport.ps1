#Requires -Module ActiveDirectory
#Requires -Module GroupPolicy
#Requires -version 3.0
#Requires -RunAsAdministrator
<#PSScriptInfo

.VERSION 2021.30.30

.GUID bafabea1-77fa-4507-aa57-1acc77fb9b9c

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

.DESCRIPTION 
 This script gets all gpo's in a forest and reports on the permissions. 
https://technet.microsoft.com/en-us/library/ee461018.aspx

Two reports one shows all the gpo's and the acl being applied.
Other is report with gpo and any instance of a unresolved sid.
#> 
Param($reportpath = "$env:userprofile\Documents")

#report Name

function enumGroup {
    param($identity,$domain)
    write-host "$identity"
    if($domain -in "NT AUTHORITY","Everyone"){

    }elseif($domain -eq "BUILTIN"){
        try{get-adgroup -Identity $identity -Properties members -Server $domain | select -ExpandProperty members | foreach{
            $fnd = $null; $fnd = get-adobject -identity $_ -Properties samaccountname,objectsid -server "$domain`:3268"
                if($fnd.objectclass -eq "Group"){$fnd;enumGroup -identity $fnd.samaccountname -domain $domain}else{$fnd} 
            }}catch{}
    }else{
        try{get-adgroup -Identity $identity -Properties members -Server $domain | select -ExpandProperty members | foreach{
            $fnd = $null; $fnd = get-adobject -identity $_ -Properties samaccountname,objectsid -server "$domain`:3268"
                if($fnd.objectclass -eq "Group"){$fnd;enumGroup -identity $fnd.samaccountname -domain $domain}else{
                $fnd} 
            }}catch{}
    }

}

function dumpgpoacls{
    get-adforest | select -ExpandProperty domains -pv domain | foreach{
        Get-GPO -all -domain $domain -pv gpo | foreach{
            Get-GPPermissions -Name $_.displayname -All -DomainName $domain -pv gpp | foreach{
            $_ | select `
                @{name='Domain';expression={$domain}},`
                @{name='GPO';expression={$gpo.DisplayName}},`
                @{name='Trustee';expression={$_.trustee.name}}, `
                @{name='TrusteeDomain';expression={$_.trustee.Domain}}, `
                @{name='TrusteeSid';expression={$_.trustee.Sid}}, `
                Denied,Inherited,Permission, @{name='memberofGroup';expression={}}

            enumGroup -identity $_.Trustee.name -domain $_.Trustee.domain | select `
                @{name='Domain';expression={$domain}},`
                @{name='GPO';expression={$gpo.DisplayName}},`
                @{name='Trustee';expression={$_.samaccountname}}, `
                @{name='TrusteeDomain';expression={}}, `
                @{name='TrusteeSid';expression={$_.objectsid}}, `
                @{name='Denied';expression={$gpp.Denied}}, `
                @{name='Inherited';expression={$gpp.Inherited}}, `
                @{name='Permission';expression={$gpp.Permission}}, `
                @{name='memberofGroup';expression={"$($gpp.trustee.Domain)\$($gpp.trustee.name)"}}
            }
        }
    }
}

dumpgpoacls | export-csv $reportpath\gpo_permissions.csv -NoTypeInformation
