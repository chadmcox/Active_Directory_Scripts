
<#PSScriptInfo

.SYNOPSIS


.DESCRIPTION 
 This script finds all stale windows computers in active directory and disables them. 
 use the reportonly switch just to get a list of computers that will get disabled.

 !!!remove the -whatif after you test it.

.EXAMPLE
.\Findanddisablestaleadcomputers.ps1 

.\Findanddisablestaleadcomputers.ps1 -reportonly

.\Findanddisablestaleadcomputers.ps1 -$DaysInactive 120

.VERSION 0.2

.GUID 2b49ab62-9f8e-4542-b890-329b42c15d75

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

.TAGS msonline PowerShell

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


.PRIVATEDATA


#>

#Requires -Module ActiveDirectory
#Requires -version 4.0
#Requires -RunAsAdministrator


Param($DaysInactive=90,$reportpath = "$env:userprofile\Documents",[switch]$reportonly)

$default_err_log = $reportpath + '\err_log.txt'
$default_log = "$reportpath\report_ADWindowsComputerswithStalePWDAgeAndLastLogon.csv"

Function ADComputerswithStalePWDAgeAndLastLogon{
    #report_computers_stale
    [cmdletbinding()]
    param()
    process{
        write-host "Starting Function ADComputerswithStalePWDAgeAndLastLogon"
        
        $script:results = @()
        $utc_stale_date = (Get-Date).Adddays(-($DaysInactive)).ToFileTimeUTC() 

        foreach($domain in (get-adforest).domains){
            try{$script:results += get-adcomputer -filter {(LastLogonTimeStamp -lt $utc_stale_date -or LastLogonTimeStamp -notlike "*")
                        -and (pwdlastset -lt $utc_stale_date -or pwdlastset -eq 0) -and (enabled -eq $true)
                        -and (iscriticalsystemobject -notlike $true) -and (OperatingSystem -like 'Windows*')
                        -and ((ServicePrincipalName -notlike "*") -or (ServicePrincipalName -notlike "*MSClusterVirtualServer*"))} `
                    -properties IPv4Address,OperatingSystem,serviceprincipalname,LastLogonTimeStamp,pwdlastset, `
                        enabled,whencreated,PasswordLastSet `
                    -server $domain | where {$_.IPv4Address -eq $null} | `
                    select $hash_domain, name,samaccountname,OperatingSystem,enabled,$hash_pwdLastSet, `
                        $hash_lastLogonTimestamp,$hash_whencreated,$hash_parentou}
            catch{"function ADComputerswithStalePWDAgeAndLastLogon - $domain - $($_.Exception)" | `
                out-file $default_err_log -append}
        }
        
        $script:results | export-csv $default_log -NoTypeInformation
        if($script:results){
            write-host "Found $(($script:results | measure).count) Stale Windows Computer Objects."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
            if(!($reportonly)){
                DisableADComputers
            }
        }
    }
}
Function DisableADComputers{
    [cmdletbinding()]
    param()
    process{
        write-host "Disabling Stale Windows Computer Objects"
        $script:results | foreach{
            try{Disable-ADAccount ($_).samaccountname -server ($_).domain -whatif}
            catch{"Failed"; "$(Get-Date) - $_.domain - Failed to disable $(($_).samaccountname) - $($_.Exception)" | `
                out-file $default_err_log -append}
        }
    }
}
$hash_whencreated = @{Name="whencreated";
    Expression={($_.whencreated).ToString('MM/dd/yyyy')}}
$hash_pwdLastSet = @{Name="pwdLastSet";
    Expression={if($_.PwdLastSet -ne 0){([datetime]::FromFileTime($_.pwdLastSet).ToString('MM/dd/yyyy'))}}}
$hash_lastLogonTimestamp = @{Name="LastLogonTimeStamp";
    Expression={if($_.LastLogonTimeStamp -like "*"){([datetime]::FromFileTime($_.LastLogonTimeStamp).ToString('MM/dd/yyyy'))}}}
$hash_domain = @{Name="Domain";
    Expression={$domain}}
$hash_parentou = @{name='ParentOU';expression={`
    $($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}}

ADComputerswithStalePWDAgeAndLastLogon
