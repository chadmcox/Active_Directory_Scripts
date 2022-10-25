<#PSScriptInfo
.VERSION 2021.10
.GUID 368f7248-347a-46d9-ba35-3ae42890daed
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
from the use or distribution of the Sample 
.Note

#>
$reportpath = "$env:USERPROFILE\Downloads"
cd $reportpath
$searchbase = @()
$default_err_log = "$reportpath\err.txt"
$time_log = "$reportpath\runtime.csv"


#https://gist.githubusercontent.com/bill-long/43ea5863469f7585fbba/raw/360ea41e1a0786c22762bf1b8276b6ab1d8f54d2/Get-TokenGroups.ps1

function gettokengroups{
    [cmdletbinding()]
    param($gcName, $adobject)
    $dn = $adobject.distinguishedname
Add-Type @"
    using System;
    public class TokenEntry {
        public string SID;
        public string Name;
    }
"@

    $searchRoot = [ADSI]("GC://" + $gcName + "/" + $dn)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot, "(objectClass=*)", @("tokenGroups"), [System.DirectoryServices.SearchScope]::Base)
    $result = $searcher.FindOne()
    if ($result -eq $null)
    {
        return
    }

    ""
    $result.Path
    foreach ($sidBytes in $result.Properties["tokenGroups"])
    {
        $translated = $null
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidbytes, 0)
        try {
        $translated = $sid.Translate("System.Security.Principal.NTAccount").ToString()
        }
        catch {
        try {
            $adObject = ([ADSI]("LDAP://<SID=" + $sid.ToString() + ">"))
            $translated = $adObject.Properties["samAccountName"][0].ToString()
        }
        catch { }
        }

        $tokenEntry = New-Object TokenEntry;
        $tokenEntry.SID = $sid.ToString();
        $tokenEntry.Name = $translated;
        $tokenEntry | select @{name='group';expression={$_.Name}}, @{name='object';expression={$adobject.samaccountname}}, `
            @{name='objectclass';expression={$adobject.objectclass}} | export-csv .\ADGroupMemberExport.csv -NoTypeInformation -Append
        $tokenEntry 
    }
}
Function createADSearchBase{
    [cmdletbinding()] 
    param()
    $hash_domain = @{name='Domain';expression={$domain}}
    $searchbase_list = "$reportpath\tmpADSearchBaseList.csv"
    try{Get-ChildItem $searchbase_list | Where-Object { $_.LastWriteTime -lt $((Get-Date).AddDays(-5))} | Remove-Item -force}catch{}
    write-host "Generating Search Base List"
    If (!(Test-Path $searchbase_list)){
        foreach($domain in (get-adforest).domains){
            write-debug "Gathering OUs"
            try{Get-ADObject -ldapFilter "(objectclass=organizationalunit)" `
                -Properties "msds-approx-immed-subordinates" -server $domain -ResultPageSize 500 -ResultSetSize $null | `
                     where {$_."msds-approx-immed-subordinates" -ne 0} | select `
                $hash_domain, DistinguishedName  | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
            try{Get-ADObject -ldapFilter "(objectclass=domainDNS)" `
                -Properties "msds-approx-immed-subordinates" -server $domain -ResultPageSize 500 -ResultSetSize $null | `
                     where {$_."msds-approx-immed-subordinates" -ne 0} | select `
                $hash_domain, DistinguishedName  | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
            try{Get-ADObject -ldapFilter "(objectclass=builtinDomain)" `
                -Properties "msds-approx-immed-subordinates" -server $domain -ResultPageSize 500 -ResultSetSize $null | `
                     where {$_."msds-approx-immed-subordinates" -ne 0} | select `
                $hash_domain, DistinguishedName  | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
            try{(get-addomain $domain).UsersContainer | Get-ADObject -server $domain | select `
                $hash_domain, DistinguishedName | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
            try{(get-addomain $domain).ComputersContainer | Get-ADObject -server $domain | select `
                $hash_domain, DistinguishedName | export-csv $searchbase_list -append -NoTypeInformation}
            catch{"function CollectionADSearchBase - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
    }
    else{
        Write-host "Reusing Existing Searchbase List"
    }
    $searchbase = import-csv $searchbase_list
    $searchbase
}

function exportadobjects{
    [cmdletbinding()] 
    param()
    if(!($searchbase)){
        $searchbase = createADSearchBase
    }
    foreach($sb in $searchbase){$domain = $sb.domain
        write-host "exporting objects $($sb.distinguishedname)"
        get-adobject -ldapFilter "(&(memberof=*)(|(objectCategory=person)(objectCategory=group)))" -SearchBase $sb.distinguishedname -SearchScope OneLevel `
                -Server $sb.domain -Properties samaccountname,objectSid | select `
                    @{n='domain';e={$sb.domain}}, distinguishedname, objectclass, samaccountname,objectSid 
    }
}
function createreports{
    [cmdletbinding()] 
    param()
    try{Get-ChildItem .\ADGroupMemberExport.csv | Remove-Item -force}catch{}
    $count = (import-csv "$reportpath\tmpADObjectList.csv").count
    import-csv "$reportpath\tmpADObjectList.csv" -pv ado | foreach{$i++
        write-host "exporting $i / $count groups for $($ado.distinguishedname)"
        $ado | select @{n='domain';e={$ado.domain}},
            @{n='samaccountname';e={$ado.samaccountname}}, `
            @{n='objectclass';e={$ado.objectclass}}, `
            @{n='tokenGroupCount';e={(gettokengroups -gcName $dc -adobject $ado | measure-object).count}}
    }
}
$dc = (get-addomaincontroller -Discover).hostname
exportadobjects | export-csv .\tmpADObjectList.csv -NoTypeInformation
createreports | export-csv .\ADObjectGroupTokenSummary.csv -NoTypeInformation
write-host "Results found here: $reportpath"
