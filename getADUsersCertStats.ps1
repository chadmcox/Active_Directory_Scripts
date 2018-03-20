
<#PSScriptInfo

.VERSION 0.1

.GUID 8235cbe1-3f8b-443e-a46b-8c10145dae84

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

.TAGS get-aduser

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


.PRIVATEDATA 

#>

#Requires -Module activedirectory
#Requires -Version 4

<# 

.DESCRIPTION 
 This script will find all users with certifcates and provide a count in each attribute. 

 to run against one user do the following

 .\collectADUsersCertState.ps1 -samaccountname [samaccountname] -domain [domainname]
#> 
Param($samaccountname,$domain,$reportpath = "$env:userprofile\Documents")

function ADUserswithCertificates{
    write-host "Counting AD Users Certificates."
    $results = @()
    foreach($domain in (get-adforest).domains){ 
        try{$results += get-aduser -LDAPFilter "(|(usercertificate=*)(userSMIMECertificate=*))"`
                 -Properties enabled,PasswordExpired,pwdLastSet,lastlogontimestamp,usercertificate,userSMIMECertificate,whencreated,whenchanged `
                  -server $domain | `
                    select $hash_domain, *}
        catch{}
    }
       
    $results | select domain,samaccountname,$hash_usercertificatecount,$hash_usersmimecount,enabled, `
        passwordexpired,$hash_pwdLastSet,$hash_lastLogonTimestamp,$hash_whenchanged,$hash_whencreated
}

Function ADUserswithExpiredCertificates{
    write-host "Looking for Expired Certificates."
    $users = @()
    $results = @()
    foreach($domain in (get-adforest).domains){ 
        try{$users += get-aduser -LDAPFilter "(|(usercertificate=*)(userSMIMECertificate=*))"`
                 -Properties usercertificate,userSMIMECertificate `
                 -server $domain | `
                    select $hash_domain, *}
        catch{}
    }

    foreach($user in $users){
        if(($user).usercertificate){
            ($user).usercertificate | foreach {
                $results += getcertdate -cert $_ | select `
                    @{name='Domain';expression={$user.domain}},`
                    @{name='Samaccountname';expression={$user.samaccountname}},`
                    @{name='Attribute';expression={"usercertificate"}}, `
                    CertExpired,CertThumbprint
            }
        }
        if(($user).userSMIMECertificate){
            ($user).userSMIMECertificate | foreach {
                $results += getcertdate -cert $_ | select `
                    @{name='Domain';expression={$user.domain}},`
                    @{name='Samaccountname';expression={$user.samaccountname}},`
                    @{name='Attribute';expression={"userSMIMECertificate"}}, `
                    CertExpired,CertThumbprint
            }
        }
    }
    $results
}
Function GetCertDate{
    param($cert)
    [int] $days = 0
    try{$converted = [System.Security.Cryptography.X509Certificates.X509Certificate2] $cert}catch{}
    if ($converted.NotAfter -lt [datetime]::Today.AddDays($days)) {
        $results = @{}
        $results.CertThumbprint=$converted.Thumbprint
        $results.CertExpired=$converted.NotAfter
        new-object -TypeName psobject -prop $results
    }
}
Function ScanSingleUser{
    param($domain,$samaccountname)
    $user = get-aduser $samaccountname `
        -Properties enabled,PasswordExpired,pwdLastSet,lastlogontimestamp,usercertificate,userSMIMECertificate,whencreated,whenchanged `
        -server $domain | `
            select $hash_domain, *

    $user | select domain,samaccountname,$hash_usercertificatecount,$hash_usersmimecount,enabled, `
        passwordexpired,$hash_pwdLastSet,$hash_lastLogonTimestamp,$hash_whenchanged,$hash_whencreated | fl
    if(($user).usercertificate){Write-host "userCertificate expirations"
        ($user).usercertificate | foreach {
            getcertdate -cert $_
        }
    }
    if(($user).userSMIMECertificate){Write-host "userSMIMECertificate expirations"
        ($user).userSMIMECertificate | foreach {
            getcertdate -cert $_
        }
    }

}

#region hashes
    $hash_domain = @{name='Domain';expression={$domain}}
    $hash_whenchanged = @{Name="whenchanged";
        Expression={($_.whenchanged).ToString('MM/dd/yyyy')}}
    $hash_whencreated = @{Name="whencreated";
        Expression={($_.whencreated).ToString('MM/dd/yyyy')}}
    $hash_pwdLastSet = @{Name="pwdLastSet";
        Expression={if($_.PwdLastSet -ne 0){([datetime]::FromFileTime($_.pwdLastSet).ToString('MM/dd/yyyy'))}}}
    $hash_lastLogonTimestamp = @{Name="LastLogonTimeStamp";
        Expression={if($_.LastLogonTimeStamp -like "*"){([datetime]::FromFileTime($_.LastLogonTimeStamp).ToString('MM/dd/yyyy'))}}}
    $hash_parentou = @{name='ParentOU';expression={
        $($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}} 
    $hash_usercertificatecount = @{Name="usercertificateCount";
        Expression={$_.usercertificate.count}}
    $hash_usersmimecount = @{Name="userSMIMECertificateCount";
        Expression={$_.userSMIMECertificate.count}}
#endregion

if($samaccountname){
    if(!($domain)){$domain = (get-addomain).name}
        ScanSingleUser -samaccountname $samaccountname -domain $domain
    
}else{
    ADUserswithCertificates | export-csv "$reportpath\reportADUserCertStats.csv" -NoTypeInformation
    ADUserswithExpiredCertificates | export-csv "$reportpath\reportADUserExpiredCerts.csv" -NoTypeInformation
    write-host "2 Reports found here: $reportpath"
}
