#Requires -Module ActiveDirectory
#Requires -version 3.0
#Requires -RunAsAdministrator

<#PSScriptInfo

.VERSION 0.1

.GUID 5e7bfd24-88b8-5d4d-87fd-c4ffbfcf5be6

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
0.1

.DESCRIPTION 
 finds cnf objects

 
#> 
Param($path = "$env:userprofile\Documents")
get-adforest | select -expandproperty domains -pipelinevariable domain | foreach{
    get-addomain $domain | select -ExpandProperty SubordinateReferences -PipelineVariable partition | foreach{
        Get-ADObject -LDAPFilter "(|(cn=*\0ACNF:*)(ou=*CNF:*))" -Server $domain -SearchBase $partition | select Distinguishedname
    }
} | export-csv "$path\ad_conflict_objects.csv" -notypeinformation
