<#PSScriptInfo

.VERSION 0.1

.GUID 0c644c9a-9eb3-45e1-a711-4c1d05651f03

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

#>
param($reportpath = "$($env:userprofile)\Documents")

$stale_date = [DateTime]::Today.AddDays(-60)

$hash_pwdLastSet = @{Name="pwdLastSet";
    Expression={([datetime]::FromFileTime($_.pwdLastSet))}}

$hash_pwdAge = @{Name="PwdAge";
    Expression={if($_.PwdLastSet -ne 0){(new-TimeSpan([datetime]::FromFileTimeUTC($_.PwdLastSet)) $(Get-Date)).days}else{0}}}

$hash_lastLogonTimestamp = @{Name="LastLogonTimeStamp";
    Expression={([datetime]::FromFileTime($_.LastLogonTimeStamp))}}

$hash_domain = @{name='Domain';expression={$domain}}

$hash_parentou = @{name='ParentOU';expression={$ou.distinguishedname}}

$hash_computerou = @{name='ParentOU';expression={(get-addomain $domain).ComputersContainer}}

$hash_isComputerStale = @{Name="Stale";
    Expression={if(($_.LastLogonTimeStamp -lt $stale_date.ToFileTimeUTC() -or $_.LastLogonTimeStamp -notlike "*") `
        -and ($_.pwdlastset -lt $stale_date.ToFileTimeUTC() -or $_.pwdlastset -eq 0) `
        -and ($_.enabled -eq $true) -and ($_.whencreated -lt $stale_date) `
        -and ($_.IPv4Address -eq $null) -and ($_.OperatingSystem -like "Windows*") `
        -and (!($_.serviceprincipalname -like "*MSClusterVirtualServer*"))){$True}else{$False}}}
        
        
$ou = "CN=Computers,DC=contoso,DC=com"  #*******place the OU Distinguished Name Here *******
$results = get-adcomputer -filter * -server $domain -searchbase $ou -SearchScope OneLevel `
    -properties PwdLastSet,whencreated,SamAccountName,LastLogonTimeStamp,Enabled,IPv4Address,operatingsystem,serviceprincipalname | select `
    $hash_domain,SamAccountName,$hash_isComputerStale,$hash_pwdLastSet,$hash_pwdAge,whencreated,LastLogonTimeStamp,Enabled,IPv4Address,operatingsystem

$results | export-csv "$reportpath\ad_computer_report.csv"
