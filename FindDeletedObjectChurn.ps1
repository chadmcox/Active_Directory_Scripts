#Requires -Module ActiveDirectory
#Requires -version 3.0
#Requires -RunAsAdministrator

<#PSScriptInfo

.VERSION 0.1

.GUID 5e7bfd30-88b8-4f4d-99fd-c4ffbfcf5be6

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

#>

$results = get-adforest -pipelinevariable forest | select -ExpandProperty domains -PipelineVariable domain | foreach{
    Get-ADObject -IncludeDeletedObjects -filter {deleted -eq $true}  -properties whencreated -server $domain | select objectclass, whencreated
    get-addomain -server $domain | select -ExpandProperty SubordinateReferences -PipelineVariable partition | foreach{
        write-host "Searching $partition in $domain"
        Get-ADObject -IncludeDeletedObjects -filter {deleted -eq $true}  -properties whencreated -searchbase $partition -server $domain | select objectclass, whencreated
    }
}

Write "Object deletions by date"
$results | select @{Name="whencreated";Expression={($_.whencreated).ToString('yyyy-MM-dd')}} | sort whencreated | group whencreated | select name,count
Write "Object deletions by objectclass"
$results | group objectclass | select name,count
