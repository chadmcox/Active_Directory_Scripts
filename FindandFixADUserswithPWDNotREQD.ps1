
<#PSScriptInfo

.VERSION 0.1

.GUID 29129768-81ac-415f-8235-17784f9b4b42

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

.TAGS msonline PowerShell get-adobject get-aduser

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

<# 

.DESCRIPTION 
 This script will find and fix all users that have passwordnotreqd flag set. 
 !!!remove the -whatif after you test it.

.EXAMPLE
.\FindanddisableADUserswithPWDNotReqd.ps1 

.\FindanddisableADUserswithPWDNotReqd.ps1 -reportonly

#> 

[cmdletbinding()]
Param($reportpath = "$env:userprofile\Documents",[switch]$reportonly)


$default_log = "$reportpath\report_ADUserswithPWDnotREQD.csv"
$default_err_log = $reportpath + '\err_log.txt'
cd $reportpath

Function ADUserswithPWDnotREQD{
    #users_pwd_never_set
    [cmdletbinding()]
    param()
    process{
        $ctime = (Get-Date).Adddays(-($DaysInactive))
        write-host "Starting Function ADUserswithPWDnotREQD"
        
        $results = @()
        
        foreach($domain in (get-adforest).domains){
            try{$results += get-aduser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=32)(!(IsCriticalSystemObject=TRUE)))"`
                -Properties admincount,enabled,PasswordExpired,pwdLastSet,whencreated,passwordnotrequired, `
                    whenchanged,lastLogonTimestamp `
                -server $domain | `
                    select $hash_domain, samaccountname,admincount,enabled,passwordnotrequired, `
                        PasswordExpired,$hash_pwdLastSet, $hash_lastLogonTimestamp,$hash_whencreated,$hash_parentou}
            catch{"function ADUserswithPwdNotRQD - $domain - $($_.Exception)" | out-file $default_err_log -append}
        }
        $results | export-csv $default_log -NoTypeInformation
        
        if($results){
            write-host "Found $(($results | measure).count) user object with password not required."
            write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
            if(!($reportonly)){
                #RemovePWDNotRQDFlag
            }
        }
        
    }
}
Function RemovePWDNotRQDFlag{
    [cmdletbinding()]
    param()
    process{
        #code not available yet
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

ADUserswithPWDnotREQD
