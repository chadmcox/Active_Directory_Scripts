#Requires -modules activedirectory
<#PSScriptInfo

.VERSION 2020.3.9

.GUID 657fdc2d-4d6d-4370-a5ac-3244715349d1

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

.TAGS Azure Active Directory PowerShell

.DESCRIPTION 
 #collect Application Direct and Delegated Permissions
#> 
<#
using Get-ADReplicationAttributeMetadata to get last time anything has replicated with the trust.
#>

Param($reportpath = "$env:userprofile\Documents")

$report = "$reportpath\report_ADTrust.csv"


get-adforest | select -expandproperty domains -PipelineVariable domain | foreach{
get-adtrust -filter * -Properties * -server $domain -PipelineVariable trust | select `
    @{name='Domain';expression={$domain}},name,securityIdentifier,Created, `
    Direction,trustType,DisallowTransivity,SelectiveAuthentication, `
    SIDFilteringForestAware, SIDFilteringQuarantined,TGTDelegation, `
    TrustAttributes,UsesAESKeys,UsesRC4Encryption,whenCreated,whenchanged,`
    @{name='trustAuthOutgoing';expression={(Get-ADReplicationAttributeMetadata `
        -filter {attributename -eq "trustAuthOutgoing"} -Server (get-addomain $domain).PDCEmulator `
        -Object ($trust).DistinguishedName).LastOriginatingChangeTime}}, `
    @{name='trustAuthIncoming';expression={(Get-ADReplicationAttributeMetadata `
        -filter {attributename -eq "trustAuthIncoming"} -Server (get-addomain $domain).PDCEmulator `
        -Object ($trust).DistinguishedName).LastOriginatingChangeTime}}} | export-csv $report -NoTypeInformation


