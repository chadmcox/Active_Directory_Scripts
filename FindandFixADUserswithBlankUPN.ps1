
<#PSScriptInfo

.VERSION 0.1

.GUID 3f08ea97-540a-4637-b2bb-dd173839b949

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

.TAGS Active Directory PowerShell

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
#Requires -version 4.0
#Requires -RunAsAdministrator

<# 

.DESCRIPTION 
 This script will look for Users with no UPN defiend and will set a default UPN of SAMAAccountName @ DomainName. 

#> 
Param()

foreach($domain in (get-adforest).domains){
    foreach($user in (get-aduser -ldapFilter "(&(!(userprincipalname=*))(!(IsCriticalSystemObject=TRUE)))")){
        $newupn = "$($user.samaccountname)@$domain)"; $newupn
        $user | set-aduser -UserPrincipalName $newupn
    }
}
