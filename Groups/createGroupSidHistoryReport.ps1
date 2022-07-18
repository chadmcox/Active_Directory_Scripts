<#-----------------------------------------------------------------------------
Example code for

Chad Cox, Microsoft Premier Field Engineer
https://blogs.technet.microsoft.com/chadcox/

LEGAL DISCLAIMER
This Sample Code is provided for the purpose of illustration only and is not
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
against any claims or lawsuits, including attorneys’ fees, that arise or result
from the use or distribution of the Sample Code.


This will pull anything with sid history
-----------------------------------------------------------------------------#>


$_default_log = "$env:userprofile\downloads\sid_history_inventory.csv"


get-adforest | select -ExpandProperty domains -pv domain | foreach{
    Get-ADObject -ldapFilter "(|(objectclass=organizationalunit)(objectclass=container))" -server $domain -pv ou | foreach{
        Get-ADobject -LDAPFilter "(&(sidhistory=*)(|(objectclass=user)(objectclass=group)))" -properties "msDS-ReplAttributeMetaData",whencreated,whenchanged,sidhistory,samaccountname,objectclass,DistinguishedName,groupType `
            -searchbase $ou.DistinguishedName -SearchScope OneLevel -server $domain | select DistinguishedName,whencreated,samaccountname,objectclass,groupType,`
                @{name='sidHistory';expression={[string]($_).sidhistory[0]}},`
                @{name='domainSid';expression={([string]($_).sidhistory[0]).Split("-")[0..(([string]($_).sidhistory[0]).Split("-").count -2)]  -join '-'}},`
                @{name='sidHistoryAddedOn';expression={($_ | Select-Object -ExpandProperty "msDS-ReplAttributeMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_ATTR_META_DATA | where { $_.pszAttributeName -eq "sidhistory"}}).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}},`
                @{name='ParentOU';expression={$($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}}
    }
} | export-csv $_default_log -NoTypeInformation
