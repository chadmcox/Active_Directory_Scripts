#requires -version 4.0
#requires -modules activedirectory
<#PSScriptInfo

.VERSION 2020.4.17

.GUID 30793b69-d59f-41e4-a274-13d6b3fc0795

.AUTHOR Chad.Cox@microsoft.com
    https://blogs.technet.microsoft.com/chadcox/ (retired)
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
    This script will disable computer objects that have pwdlastset greater than daysinactive
    and lastlogontimestamp greater than daysinactive
    and not a clustert object
    and is enabled
    and not a critical system object like a domain controller
    and is a windows machine.

    !!!! Test first, Remove -whatif after the disable-adaccount cmdlet for to actually disable the account !!!!!!!

    Here are scenerios to look for:
    -Primary group is none standard should be 515
    -Computer's PasswordNotRequired set to true
    -Computer's with Trustedfordelegation "unconstrain delegation"
    -Computer's with Sid history from the same domain
    -Non Domain controllers with admin count
    -Watch for computer's with large amount of certificates
    - https://docs.microsoft.com/en-us/azure/active-directory/connect/active-directory-aadconnectsync-largeobjecterror-usercertificate
    -Stale Computer's
    -Computer's with Duplicate SID
    - https://support.microsoft.com/en-us/help/314828/the-microsoft-policy-for-disk-duplication-of-windows-installations
    - https://support.microsoft.com/en-us/help/816099/how-to-find-and-clean-up-duplicate-security-identifiers-with-ntdsutil

.EXAMPLE
    .\create_computer_object_report.ps1

.EXAMPLE
    .\create_computer_object_report.ps1 -logpath "c:\temp"


#> 
Param($DaysInactive=90,$logpath = $(Split-Path -parent $PSCommandPath))

$utc_stale_date = ([DateTime]::Today.AddDays(-$DaysInactive)).ToFileTimeUTC()
$log_file_date = $(get-date -Format yyyyMMddHHmm)
"$(Get-Date -Format o) - exporting out all OU's" | add-content -Path "$logpath\run.log"
#remove all but previous results
get-childitem "$logpath\active_directory_computer*.csv" | sort lastwritetime -Descending | select -Skip 3 | Remove-Item -Force
#remove all but last 6 zip files
get-childitem "$logpath\active_directory_computer*.zip" | sort lastwritetime -Descending | select -Skip 6 | Remove-Item -Force
#remove log file if bigger than 5mb
Get-ChildItem "$logpath\run.log" | Where { $_.Length / 1MB -gt 5 } | Remove-Item -Force

#retrieve all containers and OU that contain objects in AD to query for computer objects.
get-adforest | select -ExpandProperty domains -pv domain | foreach {
    Get-ADObject -ldapFilter "(|(objectclass=organizationalunit)(objectclass=container))" -Properties "msds-approx-immed-subordinates" `
        -server $domain -PipelineVariable ou | where {$_."msds-approx-immed-subordinates" -ne 0} | `
            select @{N="Domain";E={$domain}},DistinguishedName}  | export-csv -Path "$logpath\tOUlist.csv" -NoTypeInformation

#Using previous list retrieve all enabled computers objects and specific information
"$(Get-Date -Format o) - Gathering all computers" | add-content -Path "$logpath\run.log"
import-csv "$logpath\tOUlist.csv" -pv ou | foreach {
    "$(Get-Date -Format o) - Gathering Stale Computer Objects from $($ou.domain)" | add-content -Path "$logpath\run.log"
    get-adcomputer -filter {(iscriticalsystemobject -notlike $true)} -searchbase $ou.DistinguishedName -SearchScope OneLevel `
        -server $ou.domain -properties ipv4address, ipv6address, LastLogonTimeStamp, pwdlastset,dnshostname, OperatingSystem, enabled,whencreated, `
            primaryGroupID,PasswordNotRequired,managedBy,admincount,Trustedfordelegation,sidHistory,usercertificate,TrustedToAuthForDelegation, `
            UseDESKeyOnly,userAccountControl | select @{N="Domain";E={$ou.domain}}, samaccountname, name, dnshostname, operatingsystem, enabled, `
            @{N="PwdAgeinDays";E={if($_.PwdLastSet -ne 0){(new-TimeSpan([datetime]::FromFileTimeUTC($_.PwdLastSet)) $(Get-Date)).days}else{0}}}, `
            @{N="pwdLastSet";E={if(!($_.pwdlastset -eq 0)){([datetime]::FromFileTime($_.pwdLastSet))}}}, `
            @{N="LastLogonTimeStamp";E={if($_.LastLogonTimeStamp){([datetime]::FromFileTime($_.LastLogonTimeStamp))}}}, `
            @{N="sidHistory";E={[string]$($_.sidhistory)}}, `
            whencreated,Ipv4Address, Ipv6Address, primaryGroupID,PasswordNotRequired,admincount,Trustedfordelegation,TrustedToAuthForDelegation, `
            UseDESKeyOnly,userAccountControl, @{Name="userCertificateCount";Expression={$_.usercertificate.count}}, `
            @{n='ParentOU';e={$ou.DistinguishedName}},managedBy,sid
} | export-csv -Path "$logpath\active_directory_computer_export_$log_file_date.csv" -NoTypeInformation

#create a stale computer report
"$(Get-Date -Format o) - Gathering Stale Computer Objects from forest" | add-content -Path "$logpath\run.log"
get-adforest | select -ExpandProperty domains -pv domain | foreach {
    "$(Get-Date -Format o) - Gathering Stale Computer Objects from $domain" | add-content -Path "$logpath\run.log"
    get-adcomputer -filter {(LastLogonTimeStamp -lt $utc_stale_date -or LastLogonTimeStamp -notlike "*")
        -and (pwdlastset -lt $utc_stale_date -or pwdlastset -eq 0) -and (enabled -eq $true)
        -and (iscriticalsystemobject -notlike $true) -and (OperatingSystem -like 'Windows*')
        -and ((ServicePrincipalName -notlike "*") -or (ServicePrincipalName -notlike "*MSClusterVirtualServer*"))} `
        -server $domain -properties ipv4address, ipv6address, LastLogonTimeStamp, pwdlastset,dnshostname, OperatingSystem, enabled,whencreated, `
            managedBy,admincount | select @{N="Domain";E={$domain}}, samaccountname, name, dnshostname, operatingsystem, enabled, `
            @{N="PwdAgeinDays";E={if($_.PwdLastSet -ne 0){(new-TimeSpan([datetime]::FromFileTimeUTC($_.PwdLastSet)) $(Get-Date)).days}else{0}}}, `
            @{N="pwdLastSet";E={if(!($_.pwdlastset -eq 0)){([datetime]::FromFileTime($_.pwdLastSet))}}}, `
            @{N="LastLogonTimeStamp";E={if($_.LastLogonTimeStamp){([datetime]::FromFileTime($_.LastLogonTimeStamp))}}}, `
            whencreated,Ipv4Address, Ipv6Address,admincount, `
            @{n='ParentOU';e={$($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}},managedBy
} | export-csv -Path "$logpath\active_directory_computer_stale_export_$log_file_date.csv" -NoTypeInformation

#create a list of all disabled computers.
"$(Get-Date -Format o) - Gathering Disabled Computer Objects from forest" | add-content -Path "$logpath\run.log"
get-adforest | select -ExpandProperty domains -pv domain | foreach {
    "$(Get-Date -Format o) - Gathering Disabled Computer Objects from $domain" | add-content -Path "$logpath\run.log"
    get-adcomputer -filter {(enabled -eq $false)} `
        -server $domain -properties ipv4address, ipv6address, LastLogonTimeStamp, pwdlastset,dnshostname, OperatingSystem, enabled,whencreated, `
            managedBy,whenchanged | select @{N="Domain";E={$domain}}, samaccountname, name, dnshostname, operatingsystem, enabled, `
            @{N="pwdLastSet";E={if(!($_.pwdlastset -eq 0)){([datetime]::FromFileTime($_.pwdLastSet))}}}, `
            @{N="LastLogonTimeStamp";E={if($_.LastLogonTimeStamp){([datetime]::FromFileTime($_.LastLogonTimeStamp))}}}, `
            whencreated,whenchanged,Ipv4Address, Ipv6Address, `
            @{n='ParentOU';e={$($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}},managedBy
} | export-csv -Path "$logpath\active_directory_computer_disabled_export_$log_file_date.csv" -NoTypeInformation

"$(Get-Date -Format o) - Complete" | add-content -Path "$logpath\run.log"

#compress results into zip file to share
$compress_file = "$logpath\Active Directory_Computer_Extract_$(get-date -Format yyyyMMddHHmm).zip"
Compress-Archive -Path "$logpath\active_directory_computer*.csv","$logpath\run.log" -CompressionLevel Fastest -DestinationPath $compress_file


