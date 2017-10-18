
<#PSScriptInfo

.VERSION 0.6

.GUID 5472afc8-ceed-4cb4-ba76-c4e0898b4aa3

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

.TAGS AD

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
0.1 First go around of the script
0.5 lots of changes.  Biggest changes is pulling the capital smtp address from porxyaddress field and using it as the primary.
This is to make sure the mail attribute.

.PRIVATEDATA 

#> 

#Requires -Module ActiveDirectory
#Requires -Version 3


<# 

.DESCRIPTION 
This Script finds all users with email proxy addresses defined and sip addresses and checks to see if they match the upn of user objects.

#> 
Param($path = "$env:USERPROFILE\Documents\")

$results = "$($path)results_adusers_O365_discovery.csv"
$upn_cleanup = "$($path)results_upn_cleanup.csv"
If ($(Try { Test-Path $results} Catch { $false })){Remove-Item $results -force}

Function validate-EmailCharacter{
    Param([string] $emailaddress)
    #this was the HasInvalidChar function
    #email regex strings http://www.regexlib.com/Search.aspx?k=email
    
    Process{
        write-debug "Validating Email Address Characters"
        $regex = '^(([A-Za-z0-9]+_+)|([A-Za-z0-9]+\-+)|([A-Za-z0-9]+\.+)|([A-Za-z0-9]+\++))*[A-Za-z0-9]+@((\w+\-+)|(\w+\.))*\w{1,63}\.[a-zA-Z]{2,6}$'
        if($emailaddress -notmatch $regex){
            return $true
        }Else{
            return $false
        }
    }
}

#storing to an array so that the connection is kept open to the dc while the foreach is done to format the results.
#the filter scope is to pull back user objects with proxyaddresses or sip skype addresses
$users = get-aduser -filter {proxyaddresses -like "*" -or msRTCSIP-PrimaryUserAddress -like "*"} `
    -properties mail,userprincipalname,"msRTCSIP-UserEnabled",msExchRecipientTypeDetails,enabled,proxyaddresses,`
        "msRTCSIP-PrimaryUserAddress",LockedOut,PasswordExpired

#originally had this go straight to csv but decided it was better to write to variable to create a final summary.
$final_users = $users | foreach{ $primary_email = $null
            write-debug $_.samaccountname
            $primary_email = $_.proxyaddresses | foreach{if($_ -cmatch "SMTP:"){$_}}
            $primary_email = $primary_email -replace "SMTP:",""
            $_ | select `
            distinguishedname,samaccountname,userprincipalname,mail,`
            @{Name="MailDomain";Expression={$($_.mail.split('@')[1])}},`
            @{Name="MailEnabled";Expression={if($_.msExchRecipientTypeDetails){$True}Else{$false}}},`
            @{Name="MailBoxType";Expression={$_.msExchRecipientTypeDetails}},
            @{Name="PrimaryEmailAddress";Expression={$primary_email}},`
            @{Name="PrimaryEmailDomain";Expression={$primary_email.split('@')[1]}},`
            @{Name="PrimaryEmailMatchUPN";Expression={if($primary_email -match $_.userprincipalname){$True}Else{$false}}},`
            @{Name="PrimaryEmailMatchMail";Expression={if($primary_email -match $_.mail){$True}Else{$false}}},`
            @{Name="PrimaryEmailMatchSIP";Expression={if($_."msRTCSIP-PrimaryUserAddress" -match $primary_email){$True}Else{$false}}},`
            @{Name="SIPEnabled";Expression={if($_."msRTCSIP-UserEnabled"){$True}Else{$false}}},` 
            @{Name="SIPADDRESS";Expression={$_."msRTCSIP-PrimaryUserAddress"}},`
            @{Name="InvalidCharacterinPrimaryEmail";Expression={$(validate-EmailCharacter -emailaddress $primary_email)}},`
            enabled,PasswordExpired,lockedout
        }

cls

$final_users | export-csv $results -append -NoTypeInformation
Write-host "Results are here $results"

write-host "Accounts with PrimaryEmail matching UPN" -foregroundcolor yellow
$final_users | group PrimaryEmailMatchUPN | select name, count | ft -AutoSize
write-host "Accounts with PrimaryEmail matching Mail" -foregroundcolor yellow
$final_users | group PrimaryEmailMatchMail | select name, count | ft -AutoSize
write-host "Accounts with PrimaryEmail matching SIP" -foregroundcolor yellow
$final_users | group PrimaryEmailMatchSIP | select name, count | ft -AutoSize
write-host "Accounts Mail Enabled" -foregroundcolor yellow
$final_users | group MailEnabled | select name, count | ft -AutoSize
write-host "Accounts Skype Enabled" -foregroundcolor yellow
$final_users | group sipEnabled | select name, count | ft -AutoSize
write-host "Primaryemail Domain Breakdown" -foregroundcolor yellow
$final_users | group PrimaryEmailDomain | select name, count| sort count -Descending | ft -AutoSize
