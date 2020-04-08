
<#
.VERSION 2020.4.8

.GUID 809ca830-a28a-45ea-887f-aa200e857d98

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
    This script will move disable computer objects that have pwdlastset greater than daysinactive
    and lastlogontimestamp greater than daysinactive
    and is disabled
    and not a critical system object like a domain controller.

    !!!! Test first, Remove -whatif after the move-adobject cmdlet to actually move the account !!!!!!!

.EXAMPLE
    .\move_disabled_computers_to_ou.ps1

.EXAMPLE
    .\move_disabled_computers_to_ou.ps1 -DaysInactive 180 -domain "contoso.com" -logpath "c:\temp" -destination "ou=disabled computers,dc=contoso,dc=com"


#> 
Param($DaysInactive=90,
    $domain="$((get-addomain).dnsroot)",
    $logpath = $(Split-Path -parent $PSCommandPath),
    $destination)

$log = "$path\$(($domain.Split("."))[0])_move_disabled_computers_to_ou.log"

#this takes the daysinactive and subtracts it from today's date. 
#Then converts in format used by pwdlastset and lastlogontimestamp
$utc_stale_date = ([DateTime]::Today.AddDays(-$DaysInactive)).ToFileTimeUTC()

write-host "Searching $domain"
if(!($destination)){
    write-host "No destination specified use the -destination parameter with the desired ou distinguishedname"
    exit
}

#get list of disabled stale computers, store in variable
$stale_computers = get-adcomputer -filter {(LastLogonTimeStamp -lt $utc_stale_date -or LastLogonTimeStamp -notlike "*")
    -and (pwdlastset -lt $utc_stale_date -or pwdlastset -eq 0) -and (enabled -eq $false)
    -and (iscriticalsystemobject -notlike $true)} `
    -server $domain -properties ipv4address, ipv6address, LastLogonTimeStamp, pwdlastset | where {!($_.distinguishedname -like "*$destination")}

write-host "In $domain found $(($stale_computers | measure-object).count) stale computers"

#Disable Stale Computer Accounts
$stale_computers | foreach {
    "$(Get-Date -Format o) - Moving $(($_).samaccountname), Destination $($destination), pwdlastset = $([datetime]::FromFileTime($_.pwdLastSet)), lastlogontimestamp = $([datetime]::FromFileTime($_.LastLogonTimeStamp))" | Add-Content -Path $log
    try{
        #!!!!!!! reminder to remove -whatif!!!!!!!
        $_ | move-adobject -targetpath $destination -server $domain -whatif
    }catch{"$(Get-Date -Format o) - Error Moving - $(($_).samaccountname) "}
}
