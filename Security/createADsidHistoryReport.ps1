#Requires -Module ActiveDirectory
#Requires -version 3.0
#Requires -RunAsAdministrator
<#PSScriptInfo
.VERSION 2021.30.31
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
this script will provide a list of dates on when sidhistory was added to an account.

#> 
Param($reportpath = "$env:userprofile\Documents")
function retrieveADContainers{
    get-adforest | select -ExpandProperty domains -PipelineVariable domain | foreach{
        Get-ADOrganizationalUnit -filter * -properties "msds-approx-immed-subordinates" -server $domain -PipelineVariable ou | `
            where {$_."msds-approx-immed-subordinates" -ne 0} | select distinguishedname, `
                @{Name="domain";Expression={$domain}}
            get-adobject -ldapfilter "(objectclass=Container)" -SearchScope OneLevel -server $domain | select distinguishedname, `
                @{Name="domain";Expression={$domain}}}
}

function retrieveObjectsSidHistory {
    $searchbases = retrieveADContainers
    foreach($sb in $searchbases){
        write-host "Scanning $($sb.distinguishedname)"
            get-adobject -ldapfilter "(sidhistory=*)" -Properties SamAccountName,sidhistory,msDS-ReplAttributeMetaData,ObjectClass,Enabled,name `
                -searchbase $sb.DistinguishedName -SearchScope OneLevel -server $sb.domain | `
                    select SamAccountName,sidhistory,msDS-ReplAttributeMetaData,objectclass,Enabled,name,@{n='Domain';e={$sb.domain}}
            
    }
}

retrieveObjectsSidHistory | select Domain,samaccountname, name, objectclass, `
    @{name='sidHistoryDate';expression={($_ | Select-Object -ExpandProperty "msDS-ReplAttributeMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_ATTR_META_DATA | where { $_.pszAttributeName -eq "sidhistory"}}).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}}, `
    @{name='SidHistoryDomainSid';expression={($_ | select -ExpandProperty sidhistory).AccountDomainSid}}, `
    @{name='SidHistory';expression={($_ | select -ExpandProperty sidhistory).value}} | export-csv "$reportpath\$((get-adforest).RootDomain)_sidhistory.csv"
