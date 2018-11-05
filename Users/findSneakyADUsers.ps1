#Requires -Module activedirectory
#Requires -version 4.0

<#PSScriptInfo

.VERSION 1.0

.GUID 31adb560-b189-4b0c-86a7-7862d8e78094

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

.TAGS 

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


.EXAMPLE 
    .\findSneakyAccounts.ps1
    Returns all user accounts that have spn's defined

.EXAMPLE 
    .\findSneakyAccounts.ps1 -OnlySensitiveAccounts
    Returns Only Senstive Accounts that have defined SPNs

.EXAMPLE 
    .\findSneakyAccounts.ps1 -OnlySensitiveAccounts
    Returns Only Senstive Accounts that have defined SPNs
.EXAMPLE 
    .\findSneakyAccounts.ps1 -offlinespnreport
    Includes a report to show which SPN's are not showing online.

.DESCRIPTION 
 #https://adsecurity.org/?p=3466
 #https://raw.githubusercontent.com/cyberark/RiskySPN/master/Find-PotentiallyCrackableAccounts.ps1

 This script could be used to assist in finding possible kerberoasting accounts.
 It could also be used to assist in finding possible stale accounts

 this does require the ActiveDirectory module and at least version 4.0 powershell installed
 
 This will install activedirectory module
  Add-WindowsFeature RSAT-AD-PowerShell


#>



Param([switch]$offlineSPNReport,
[switch]$OnlySensitiveAccounts,
$reportpath = "$env:userprofile\Documents")

cls
$serviceAccounts = @()
$results = @()

Function collectADUserswithSPN{
    $results = @()
    Write-host "Gathering List of AD Users"    
    $userProperties = @("whencreated","lastlogontimestamp","SamAccountName",`
        "UserAccountControl","Enabled","admincount","Trustedfordelegation",`
        "TrustedToAuthForDelegation","PrimaryGroupID","pwdlastset","sidhistory","mail", `
        "PasswordNotRequired","distinguishedname","UserPrincipalname","PasswordExpired","LockedOut", `
        "ProtectedFromAccidentalDeletion","servicePrincipalname","msds-supportedencryptiontypes", `
        "msds-allowedtodelegateto")

    $select_properties = $userProperties + $hash_domain

    foreach($domain in (get-adforest).domains){
        $results += get-aduser -ldapfilter "(&(servicePrincipalName=*)(!(samaccountname=KRBTGT)))" `
            -Properties $userProperties -server $domain | select $select_properties
    }
    $results
}
function validateprivgroupmembership{
    param($object)
    $result = $false
    $odn = $object.distinguishedname
    $default_admin_groups = foreach($domain in (get-adforest).domains){get-adgroup `
        -filter {admincount -eq 1 -and iscriticalsystemobject -like "*"} `
        -server $domain | select $hash_domain,distinguishedname}
    foreach($group in $default_admin_groups){
        if(Get-ADgroup -Filter {member -RecursiveMatch $odn} -searchbase $group.distinguishedname `
            -server $group.domain){$result = $True}
    }
    $result
}
Function validatespnconnection{
    param($object)
    $results = @()
    $spn = @()
    [array]$SPNs = $object.serviceprincipalname -replace ":.*"  | Get-Unique
    foreach($spn in $spns){
        $spn = $SPN -split("/")
        $objtmp = new-object -type psobject
            $objtmp | Add-Member -MemberType NoteProperty -Name "Account" -Value $object.samaccountname
            $objtmp | Add-Member -MemberType NoteProperty -Name "Computer" -Value $($spn[1])
            $objtmp | Add-Member -MemberType NoteProperty -Name "Online" `
                -Value $(if(Test-Connection -ComputerName $($spn[1]) -Quiet -Count 1){"Ping"}
                    elseif(Test-netConnection -ComputerName $($spn[1]) -commontcpport RDP `
                        -informationlevel Quiet -WarningAction SilentlyContinue){"RDP"}
                    elseif(Test-netConnection -ComputerName $($spn[1]) -commontcpport SMB `
                        -informationlevel Quiet -WarningAction SilentlyContinue){"SMB"}
                    elseif(Test-netConnection -ComputerName $($spn[1]) -commontcpport WINRM `
                        -informationlevel Quiet -WarningAction SilentlyContinue){"WINRM"}
                    elseif(Test-netConnection -ComputerName $($spn[1]) -commontcpport HTTP `
                        -informationlevel Quiet -WarningAction SilentlyContinue){"HTTP"}
                    elseif(Test-netConnection -ComputerName $($spn[1]) -port 1433 `
                        -informationlevel Quiet -WarningAction SilentlyContinue){"SQL"}
                    Else{$false})

        $results += $objtmp
        #$objtmp | out-host
    }
    if($OfflineSPNReport){
        $results | export-csv "$reportpath\reportPossibleUnusedSPNs.csv" -NoTypeInformation
    }
    "$(($results | where Online -eq $false |  measure-object).count)"
}
#region hash
$Default_Group_ID = 513
$hash_domain = @{name='Domain';expression={$domain}}
$hash_EncryptionType = @{name='EncryptionType';
    expression={if($_.useraccountcontrol -band 2097152){"DES"}
        else{if($_."msds-supportedencryptiontypes" -band 16){"AES256-HMAC"}
        elseif($_."msds-supportedencryptiontypes" -band 8){"AES128-HMAC"}
        else{"RC4-HMAC"}}}}
$hash_PasswordNeverExpires = @{Name="PasswordNeverExpires";
        Expression={if($_.UserAccountControl -band 65536){$True}else{$False}}}
$hash_UseDesKeyOnly = @{Name="UseDesKeyOnly";Expression={if($_.UserAccountControl -band 2097152){$True}else{$False}}}
$hash_PrimaryGroup = @{Name="DefaultPrimaryGroup";
        Expression={if($_.PrimaryGroupID -eq $Default_Group_ID){$True}else{$_.PrimaryGroupID}}}
$hash_privgroupmembership = @{name='PrivilegedGroupMember';expression={validateprivgroupmembership -object $_}}
$hash_spnvalidate = @{name='SPNEntriesOffline';expression={validatespnconnection -object $_}}
$hash_spnentriescount = @{name='SPNEntriesCount';
    expression={($_.serviceprincipalname -replace ":.*"  | Get-Unique | measure-object).count}}
$hash_kerbdelegationtype = @{name='DelegationType';
    expression={if($_.TrustedToAuthForDelegation){"Constrained"}Elseif($_.Trustedfordelegation){"UnConstrained"}else{"NA"}}}
$hash_pwdLastSet = @{Name="pwdLastSet";
        Expression={if($_.PwdLastSet -ne 0){([datetime]::FromFileTime($_.pwdLastSet).ToString('MM/dd/yyyy'))}}}
$hash_whencreated = @{Name="whencreated";
        Expression={($_.whencreated).ToString('MM/dd/yyyy')}}
$hash_lastLogonTimestamp = @{Name="LastLogonTimeStamp";
        Expression={if($_.LastLogonTimeStamp -like "*"){([datetime]::FromFileTime($_.LastLogonTimeStamp).ToString('MM/dd/yyyy'))}}}
$hash_PwdAgeinDays = @{Name="PwdAgeinDays";
        Expression={if($_.PwdLastSet -ne 0){(new-TimeSpan([datetime]::FromFileTimeUTC($_.PwdLastSet)) $(Get-Date)).days}else{"NA"}}}
#endregion


$accountswithspn = collectADUserswithSPN | select domain,samaccountname,enabled,PasswordExpired,LockedOut, `
    $hash_EncryptionType,$hash_PasswordNeverExpires,$hash_UseDesKeyOnly, `
    $hash_PrimaryGroup,$hash_privgroupmembership,$hash_kerbdelegationtype,TrustedToAuthForDelegation,Trustedfordelegation, `
    $hash_spnvalidate,$hash_spnentriescount,$hash_PwdAgeinDays,$hash_pwdLastSet,$hash_lastLogonTimestamp,$hash_whencreated

if($OnlySensitive){
    $accountswithspn | where {$_.PrivilegedGroupMember -eq $true -and ($_.TrustedToAuthForDelegation -eq $true `
        -or $_.Trustedfordelegation -eq $true)}
    $accountswithspn | where {$_.PrivilegedGroupMember -eq $true -and ($_.TrustedToAuthForDelegation -eq $true `
        -or $_.Trustedfordelegation -eq $true)} | `
            export-csv "$reportpath\reportOnlySensativeSneakyAccounts.csv" -NoTypeInformation
}else{
    $accountswithspn
    $accountswithspn | export-csv "$reportpath\reportAllAccountswithSPNs.csv" -NoTypeInformation
}
write-host "Reports can be found here: $reportpath"
