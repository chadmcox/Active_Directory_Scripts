#Requires -Modules activedirectory
<#PSScriptInfo

.VERSION 0.1

.GUID 4b43aafc-97d0-44e4-95e6-d2b729c5b449

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
 helps discover issues around 
 https://support.microsoft.com/en-us/help/2671874/heavy-wan-usage-after-you-restart-centralized-windows-server-2008-r2-b
 https://support.microsoft.com/en-us/help/2789917/heavy-wan-and-domain-controller-cpu-usage-when-you-perform-system-stat

#> 

<#

#>
Write-host "Gathering Schema Change Dates"
$log_file = "$env:userprofile\Documents\resultsAggregatedSchemaChangedTimeStamp.csv"
$namingContexts = "CN=Aggregate,$((Get-ADRootDSE).schemaNamingContext)","$((Get-ADRootDSE).schemaNamingContext)"
$results = get-adforest -PipelineVariable forest | select -ExpandProperty domains |  foreach-object {$domain = $_
    Write-host "From Domain: $domain"
    Get-ADDomainController -filter * -server $_  -PipelineVariable domaincontroller | foreach {
        Write-host "From Domain Controller: $($domaincontroller.hostname)"
        foreach($nc in $namingContexts){
        try{get-adobject $nc -properties * -server $domaincontroller.hostname | select `
            @{Name="Domain";Expression={$domain}}, `
            @{Name="DomainController";Expression={$domaincontroller.name}}, `
            DistinguishedName,ModifyTimeStamp,whenchanged}catch{}
        }
    }
}
$results | export-csv $log_file -NoTypeInformation
write-host "Results are here $log_file"
<#

#>
Write-host "Gathering dSASignature Date"
$log_file = "$env:userprofile\Documents\resultsdSASignatureChangeTime.csv"
$results = get-adforest -PipelineVariable forest | select -ExpandProperty domains |  foreach-object {$domain = $_
    Write-host "From Domain: $domain"
    Get-ADDomainController -filter * -server $_  -PipelineVariable domaincontroller | select -ExpandProperty partitions | foreach {
        Write-host "From Domain Controller: $($domaincontroller.hostname)"
        try{Get-ADReplicationAttributeMetadata -Object $_ -Properties dSASignature -Server $domaincontroller.hostname | select `
        Server, object, version, LastOriginatingChangeTime}catch{}
    }
}
$results | export-csv $log_file -NoTypeInformation
write-host "Results are here $log_file"
