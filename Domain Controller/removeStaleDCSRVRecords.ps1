<#PSScriptInfo
.VERSION 0.2
.GUID 8580e442-6a53-44cc-b821-2fe2d7fda178
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

.description
this will pull all current domaincontrollers and their IP into an array
it then list through all the zones and if a srv record doenst exist in the array it 
passes the object to the remove command
Leverage this script to report
https://github.com/chadmcox/Active_Directory_Scripts/blob/master/Domain%20Controller/gatherDCSRVRecords.ps1
#>

$dc = Get-ADForest | select -ExpandProperty domains -pv domain | foreach{(Get-ADDomainController -filter * -server $domain).hostname | foreach{"$($_)."}}
$dc += Get-ADForest | select -ExpandProperty domains -pv domain | foreach{(Get-ADDomainController -filter * -server $domain).IPv4Address}

Get-DnsServerZone | where IsReverseLookupZone -eq $false -pv zone | foreach{
    Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -RRType Srv | where {$_.RecordData.IPv4Address -notin $dc -and $_.RecordData.NameServer -notin $dc -and $_.RecordData.DomainName -notin $dc} | `
        remove-DnsServerResourceRecord -ZoneName $zone.ZoneName -WhatIf
}
