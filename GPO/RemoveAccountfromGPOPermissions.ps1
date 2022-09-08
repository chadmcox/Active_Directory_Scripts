<#PSScriptInfo
.VERSION 0.1
.GUID ef4ab110-eece-430a-91af-d5066877e086
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
.TAGS Active Directory PowerShell Get-GPO Group Policy get-gppermissions
.LICENSEURI 
.PROJECTURI 
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
.PRIVATEDATA 
#>

#Requires -Module ActiveDirectory
#Requires -Module GroupPolicy

<# 
.DESCRIPTION 
 This script will look for a samaccountname, being acl'ed on every GPO, and remove it. 
#> 
Param($samaccountname)
if(!($samaccountname)){
    $samaccountname = Read-Host "Enter samaccountname you want to remove from every gpo"
}


$found = @()
if($samaccountname){
    
    foreach($domain in (get-adforest).domains){
        Get-GPO -domain $domain -All | foreach-object { 
            if($_ | Get-GPPermissions -TargetName $samaccountname -TargetType user -ErrorAction SilentlyContinue) {
                $found += $_
                $_ | Set-GPPermissions -Replace -PermissionLevel none -TargetName $samaccountname -TargetType user }
            }
    }
}

write-host "$samaccountname was acled on $(($found | measure-object).count) group policies.  Removed!"
