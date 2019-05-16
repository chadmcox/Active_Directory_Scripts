#Requires -Module ActiveDirectory
#Requires -version 3.0

<#PSScriptInfo

.VERSION 2019.16.5

.GUID 242ff6b3-bde7-4a9a-b29e-667a22cc0f7c

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
 

 
#> 
param($path = "$env:userprofile\Documents")
[byte[]]$hours = @(255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255)

@(get-adforest | select -ExpandProperty domains -PipelineVariable domain | foreach {
    get-aduser -filter {logonhours -ne $hours -and logonhours -like "*"} -Properties logonhours -server $domain | select `
        samaccountname,Enabled,DistinguishedName
        
}) | export-csv "$path\ad_users_with_logonhours.csv"
