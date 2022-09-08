#requires -runasadministrator
#requires -module gpo,activedirectory
#requires -version 3.0
<#PSScriptInfo
.VERSION 0.1
.GUID 43c7363f-d300-4bf9-a481-622c67e43137
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
.PRIVATEDATA 
.DESCRIPTION 
 Collects group member ship changes to enterprise admins, domain admins, 
 administrators and other privileged groups including ones nested
 ones done via sid history
#> 

$default_log = "$env:userprofile\Documents\report_gpo_deny_rights.csv"
$results = @()

$denyuserrights = "SeDenyBatchLogonRight","SeDenyInteractiveLogonRight","SeDenyNetworkLogonRight","SeDenyRemoteInteractiveLogonRight","SeDenyServiceLogonRight"
Foreach($domain in (get-adforest).domains){  
    write-host "Reading GPOs from $domain"
    foreach ($GPO in (get-gpo -ALL -Domain $domain).displayname) {
        write-host "Reading GPO: $gpo"
        [xml]$report = Get-GPOReport -Name $GPO -ReportType Xml -Domain $domain -ErrorAction SilentlyContinue
        foreach($userright in ($report.GPO.Computer.extensiondata.extension.UserRightsAssignment)){
            foreach($right in $denyuserrights){
                if($userright.Name -eq $right){
                    foreach($member in ($userright.member)){
                        $results += $objtmp = new-object -type psobject
                        $objtmp | Add-Member -MemberType NoteProperty -Name "Domain" -Value $domain
                        $objtmp | Add-Member -MemberType NoteProperty -Name "GPO" -Value $GPO
                        $objtmp | Add-Member -MemberType NoteProperty -Name "UserRight" -Value $userright.Name
                        $objtmp | Add-Member -MemberType NoteProperty -Name "Account" -Value $member.name.'#text'
                    }
                }
            }
        }
    }
}
$results | export-csv $default_log -append -NoTypeInformation
write-host "Results can be found here $default_log"
