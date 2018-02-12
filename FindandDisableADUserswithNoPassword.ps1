
<#PSScriptInfo

.VERSION 0.1

.GUID d9e27f07-95e9-4ad9-b7c6-fb27ce762515

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

.TAGS Active Directory PowerShell get-aduser disable-adaccount

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

<# 

.DESCRIPTION 
 This script will look for users that have no password set and disabled them if they are older than 60 days.
 
 !!!remove the -whatif after you test it.

.EXAMPLE
.\FindanddisableADUserswithnoPassword.ps1 

.\FindanddisableADUserswithnoPassword.ps1 -reportonly

#> 
[cmdletbinding()]
Param($DaysInactive=0,$reportpath = "$env:userprofile\Documents",[switch]$reportonly)


$default_log = "$reportpath\report_ADUserswithPwdNotSet.csv"
$default_err_log = $reportpath + '\err_log.txt'
cd $reportpath

Function ADUserswithPwdNotSet{
    #users_pwd_never_set
    [cmdletbinding()]
    param()
    process{
        $ctime = (Get-Date).Adddays(-($DaysInactive))
        write-host "Starting Function ADUserswithPwdNotSet"
        
        $results = @()
        
        foreach($domain in (get-adforest).domains){
            try{$results += Get-ADUser -Filter {(pwdlastset -eq 0) -and (iscriticalsystemobject -notlike "*") 
                -and (whencreated -lt $ctime)} `
                -Properties admincount,enabled,PasswordExpired,pwdLastSet,whencreated, `
                    whenchanged,"msDS-ReplAttributeMetaData",lastLogonTimestamp `
                -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled, `
                        PasswordExpired,$hash_pwdLastSet,@{name='MetapwdLastSet';expression={($_ | `
                        Select-Object -ExpandProperty "msDS-ReplAttributeMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_ATTR_META_DATA |`
                        where { $_.pszAttributeName -eq "pwdLastSet"}}).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}}, `
                        $hash_lastLogonTimestamp,$hash_whencreated,$hash_parentou}
            catch{"function ADUserswithPwdNotSet - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation
        
        if($results){
            write-host "Found $(($results | measure).count) user object with password not set."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
            if(!($reportonly)){
                #DisableADUsers
            }
        }
        
    }
}
Function DisableADUsers{
    [cmdletbinding()]
    param()
    process{
        write-host "Disabling AD Users"
        If (!($(Try { Test-Path $default_log } Catch { $true }))){
            write-host "report not found in location: $default_log"
        }else{
            $last_domain = $null
            import-csv $default_log | where {$_.enabled -eq $True} | foreach{
                try{Disable-ADAccount ($_).samaccountname -server ($_).domain -whatif}
                catch{"Failed"; "$(Get-Date) - $_.domain - Failed to disable $(($_).samaccountname) - $($_.Exception)" | `
                    out-file $default_err_log -append}
            }
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

ADUserswithPwdNotSet
