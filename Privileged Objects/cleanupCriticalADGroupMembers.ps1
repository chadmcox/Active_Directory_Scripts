#Requires -Module ActiveDirectory
#Requires -version 3.0
#Requires -RunAsAdministrator

<#PSScriptInfo

.VERSION 0.1

.GUID 5e7bfd30-88b8-4f4d-99fd-c4ffbfcf5be6

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

.RELEASENOTES

.DESCRIPTION 
 Creates reports about Active Directory Groups

.Parameter silentcleanup
    If exclusion list is populated then, group member will be placed in protected users group, 128/256 encryption will be enabled,
    and account is sensitive do not delegate will be enabled.

.Parameter ReportPath
    changes default location to something other than the account that is running it documents folder.

#> 

Param($reportpath = "$env:userprofile\Documents",[switch]$silentcleanup)

$Exclusion_file = "$reportpath\privuserexclusions.txt"
$log_file = "$reportpath\privgroup.log"
$results_file = "$reportpath\criticalprivgroupreport.csv"



$Privileged_groups = @("Domain Admins","Enterprise Admins","Administrators","Schema Admins")
#$exclusionlist = @("chad","ryan")
$exclusionlist = get-content $Exclusion_file
$SERVER_TRUST_ACCOUNT = 0x2000  
$TRUSTED_FOR_DELEGATION = 0x80000  
$TRUSTED_TO_AUTH_FOR_DELEGATION= 0x1000000  
$PARTIAL_SECRETS_ACCOUNT = 0x4000000

if(($exclusionlist | measure-object).count -lt 1 -and $silentcleanup -eq $true){
    Add-Content -path $log_file -value "$(Get-date) : No Exclusions in place cleanup switch requires exclusion file to be populated."
    write-host "run script without cleanup script to define accounts to exclude as part of clean up.  Then run  second time with clean up switch."
    exit
}

function getgroupMembers{
    [cmdletbinding()]
    param($groupdomain,$group)
    foreach($domain in (get-adforest).domains){
        foreach($pg in $Privileged_groups) {
             $members = try{Get-ADGroupMember $pg -Recursive -Server $domain | where Objectclass -eq "User" | select samaccountname}catch{}

             foreach($mem in $members){
                 getuserinfofromcorrectdomain -samaccountname ($mem).samaccountname | select `
                    $hash_grp_domain,$hash_grp,domain,displayname, samaccountname,lastLogonTimestamp,pwdLastSet,PwdAgeinDays,PasswordExpired, `
                        enabled,EncryptionType,CannotBeDelegated,fullDelegation,constrainedDelegation,resourceDelegation,inProtectUsersGroup
            }
        }
    }
}
function getuserinfofromcorrectdomain{
    [cmdletbinding()]
    param($samaccountname)
    write-host "Searching for $samaccountname"
        foreach($domain in (get-adforest).domains){
            $user = get-aduser -filter {sAMAccountName -eq $samaccountname} -Properties * -server $domain | select `
                $hash_domain,displayname, samaccountname, $hash_lastLogonTimestamp,$hash_pwdLastSet,$hash_PwdAgeinDays, `
                    $hash_pwdexpired,$hash_enabled,$hash_EncryptionType,$hash_AccountNotDelegated,$hash_fullDelegation, `
                    $hash_constrainedDelegation,$hash_resourceDelegation,$hash_Protected
            if($user){return $user;exit} 
        }
    
}
function showdomaingroupcounts{
    [cmdletbinding()]
    param()
    Add-Content -path $log_file -value "------------------"
    write-host "Group Member Count By Domain"
    foreach($domain in ($group_members | select GroupDomain -Unique).GroupDomain){
        write-host " $domain"
        Add-Content -path $log_file -value "$(Get-date) : $domain"
        foreach($group in ($group_members | where GroupDomain -eq $domain | select group -Unique).group){
            write-host "  $group : $(($group_members | where {$_.group -eq $group -and $_.GroupDomain -eq $domain} | measure-object).count)"
            Add-Content -path $log_file -value "$(Get-date) : $group : $(($group_members | `
                where {$_.group -eq $group -and $_.GroupDomain -eq $domain} | measure-object).count)"
        }
        write-host "------------------"
    }

}
function showsummary{
    [cmdletbinding()]
    param()
    Add-Content -path $log_file -value "------------------"
    $results = "Total Unique Objects Found: $(($group_members | select samaccountname -Unique | Measure-Object).count)"
    Write-host $results
    Add-Content -path $log_file -value "$(Get-date) : $results"

    $results = "Total Remaining after removing exclusions: $(($remaining_members | select samaccountname -Unique | Measure-Object).count)"
    write-host $results
    Add-Content -path $log_file -value "$(Get-date) : $results"

    #with password gtr than 90 days
    $results = "Total with pwd older than 90 days: $(($remaining_members | where PwdAgeinDays -gt 90 | select samaccountname -Unique | Measure-Object).count)"
    write-host $results
    Add-Content -path $log_file -value "$(Get-date) : $results"

    #with password greater than 365 days
    $results = "Total with pwd older than 365 days: $(($remaining_members | where PwdAgeinDays -gt 365 | select samaccountname -Unique | Measure-Object).count)"
    write-host $results
    Add-Content -path $log_file -value "$(Get-date) : $results"

    #with expired password
    $results = "Total with expired pwd: $(($remaining_members | where PasswordExpired -eq $true | select samaccountname -Unique | Measure-Object).count)"
    write-host $results
    Add-Content -path $log_file -value "$(Get-date) : $results"

    #accounts disabled
    $results = "Total disabled: $(($remaining_members | where enabled -eq $false | select samaccountname -Unique | Measure-Object).count)"
    write-host $results
    Add-Content -path $log_file -value "$(Get-date) : $results"

    #not using 128 or 256
    $results = "Total not using 128 or 256: $(($remaining_members | where {$_.EncryptionType -ne "AES256-HMAC" -or $_.EncryptionType -ne "AES128-HMAC"} | select samaccountname -Unique | Measure-Object).count)"
    write-host $results
    Add-Content -path $log_file -value "$(Get-date) : $results"

    #using des
    $results = "Total using DES: $(($remaining_members | where {$_.EncryptionType -eq "DES"} | select samaccountname -Unique | Measure-Object).count)"
    write-host $results
    Add-Content -path $log_file -value "$(Get-date) : $results"

    #account is sensitive do not delegate
    $results = "Total Account is Sensitive do not delegate not enabled: $(($remaining_members | where {$_.CannotBeDelegated -eq $false} | select samaccountname -Unique | Measure-Object).count)"
    write-host $results
    Add-Content -path $log_file -value "$(Get-date) : $results"

    #not in protected user group
    $results = "Total not in Protected Users group: $(($remaining_members | where {$_.inProtectUsersGroup -eq $false} | select samaccountname -Unique | Measure-Object).count)"
    write-host $results
    Add-Content -path $log_file -value "$(Get-date) : $results"
}
function silentCleanup{
    [cmdletbinding()]
    param()
    if($remaining_members){
        foreach($member in $remaining_members){
            if($member.inProtectUsersGroup -eq $false){
        
                try{get-adgroup "Protected Users" -server ($member).GroupDomain | add-ADGroupMember -Members ($member).samaccountname
                    Add-Content -path $log_file -value "$(Get-date) : Add $(($member).samaccountname) to the Protected Users Group"}
                    catch{Add-Content -path $log_file -value "$(Get-date) : Failed to Add $(($member).samaccountname) to the Protected Users Group"}
        
            }
            if($member.EncryptionType -eq "DES"){
        
                try{Set-ADAccountControl -identity ($member).samaccountname -usedeskeyonly $false -server ($member).Domain
                Add-Content -path $log_file -value "$(Get-date) : Disable DES on $(($member).samaccountname)"}
                catch{Add-Content -path $log_file -value "$(Get-date) : Failed to Disable DES on $(($member).samaccountname)"}
        
            }
            if($member.EncryptionType -ne "AES256-HMAC" -or $member.EncryptionType -ne "AES128-HMAC"){
        
                    try{set-aduser ($member).samaccountname -KerberosEncryptionType "AES128,AES256" -server ($member).Domain
                    Add-Content -path $log_file -value "$(Get-date) : Enable 128 and 256 encryption on $(($member).samaccountname)"}
                    catch{Add-Content -path $log_file -value "$(Get-date) : Failed to Enable 128 and 256 encryption on $(($member).samaccountname)"}

            }
            if($member.CannotBeDelegated -eq $false){
        
                    try{Set-ADAccountControl -identity ($member).samaccountname -accountnotdelegated $true -server ($member).Domain
                        Add-Content -path $log_file -value "$(Get-date) : Enable Account is sensitive do not delegate on $(($member).samaccountname)"}
                        catch{Add-Content -path $log_file -value "$(Get-date) : Failed to Enable Account is sensitive do not delegate on $(($member).samaccountname)"}
        
            }
        }
    }
}
function startcleanup{
    [cmdletbinding()]
    param()
    if($remaining_members){
        foreach($member in $remaining_members){ write-host "------------------"
            $member | fl
            Write-host "Remove $(($member).samaccountname) from $(($member).group)" 
            
            if($(Read-Host -Prompt "Remove $(($member).samaccountname) from $(($member).group). y for yes, n for no") -eq 'y'){
                try{get-adgroup ($member).group -server ($member).GroupDomain | Remove-ADGroupMember -Members ($member).samaccountname -WhatIf
                    Add-Content -path $log_file -value "$(Get-date) : Remove $(($member).samaccountname) from $(($member).group)"}
                    catch{Write-host "Failed to remove $(($member).samaccountname) from $(($member).group)"
                        Add-Content -path $log_file -value "$(Get-date) : Failed to remove $(($member).samaccountname) from $(($member).group)"}
            }else{
                if($member.inProtectUsersGroup -eq $false){
                    if($(Read-Host -Prompt "Add $(($member).samaccountname) to the Protected Users Group. y for yes, n for no") -eq 'y'){
                        try{get-adgroup "Protected Users" -server ($member).Domain | add-ADGroupMember -Members ($member).samaccountname
                            Add-Content -path $log_file -value "$(Get-date) : Add $(($member).samaccountname) to the Protected Users Group"}
                            catch{Write-host "Failed to add $(($member).samaccountname) to Protected Users"
                                Add-Content -path $log_file -value "$(Get-date) : Failed to Add $(($member).samaccountname) to the Protected Users Group"}
                    }
                }
                if($member.EncryptionType -eq "DES"){
                    if($(Read-Host -Prompt "Disable DES on $(($member).samaccountname). y for yes, n for no") -eq 'y'){
                        try{Set-ADAccountControl -identity ($member).samaccountname -usedeskeyonly $false -server ($member).Domain
                        Add-Content -path $log_file -value "$(Get-date) : Disable DES on $(($member).samaccountname)"}
                        catch{Write-host "Failed to Disable DES on $(($member).samaccountname)"
                                Add-Content -path $log_file -value "$(Get-date) : Failed to Disable DES on $(($member).samaccountname)"}
                    }
                }
                if($member.EncryptionType -ne "AES256-HMAC" -or $member.EncryptionType -ne "AES128-HMAC"){
                    if($(Read-Host -Prompt "Enable 128 and 256 encryption on $(($member).samaccountname). y for yes, n for no") -eq 'y'){
                        try{set-aduser ($member).samaccountname -KerberosEncryptionType "AES128,AES256" -server ($member).Domain
                        Add-Content -path $log_file -value "$(Get-date) : Enable 128 and 256 encryption on $(($member).samaccountname)"}
                        catch{Write-host "Failed to Enable 128 and 256 encryption on $(($member).samaccountname))"
                                Add-Content -path $log_file -value "$(Get-date) : Failed to Enable 128 and 256 encryption on $(($member).samaccountname)"}

                    }
                }
                if($member.CannotBeDelegated -eq $false){
                    if($(Read-Host -Prompt "Enable Account is sensitive do not delegate on $(($member).samaccountname). y for yes, n for no") -eq 'y'){
                        try{Set-ADAccountControl -identity ($member).samaccountname -accountnotdelegated $true -server ($member).Domain
                         Add-Content -path $log_file -value "$(Get-date) : Enable Account is sensitive do not delegate on $(($member).samaccountname)"}
                         catch{Write-host "Failed to Enable Account is sensitive do not delegate on $(($member).samaccountname)"
                                Add-Content -path $log_file -value "$(Get-date) : Failed to Enable Account is sensitive do not delegate on $(($member).samaccountname)"}
                    }
                }
                #add account to the exclusion list?
                if($(Read-Host -Prompt "Add $(($member).samaccountname) to the exclusion list? y for yes, n for no") -eq 'y'){
                        try{Add-Content -path $Exclusion_file -value $(($member).samaccountname)
                            Add-Content -path $log_file -value "$(Get-date) : Add $(($member).samaccountname) to the exclusion list"}
                            catch{Write-host "Failed to Add $(($member).samaccountname) to the exclusion list"
                                Add-Content -path $log_file -value "$(Get-date) : Add $(($member).samaccountname) to the exclusion list"}
                    }       
            }
        }
    }
}
#region hash variables for calculated properties
$hash_Protected = @{name='inProtectUsersGroup';expression={isProtectedUser -domain $domain -dn ($_).distinguishedname}}
$hash_grp = @{name="Group";expression={$pg}}
$hash_grp_domain = @{name="GroupDomain";expression={$domain}}
$hash_domain = @{name='Domain';expression={$domain}}
$hash_EncryptionType = @{name='EncryptionType';
            expression={if($_.useraccountcontrol -band 2097152){"DES"}
                else{if($_."msds-supportedencryptiontypes" -band 16){"AES256-HMAC"}
                elseif($_."msds-supportedencryptiontypes" -band 8){"AES128-HMAC"}
                else{"RC4-HMAC"}}}}
$hash_pwdLastSet = @{Name="pwdLastSet";
    Expression={if($_.PwdLastSet -ne 0 -and $_.objectclass -eq "user"){([datetime]::FromFileTime($_.pwdLastSet).ToString('MM/dd/yyyy'))}}}
$hash_lastLogonTimestamp = @{Name="LastLogonTimeStamp";
    Expression={if($_.LastLogonTimeStamp -like "*"){([datetime]::FromFileTime($_.LastLogonTimeStamp).ToString('MM/dd/yyyy'))}}}
$hash_PwdAgeinDays = @{Name="PwdAgeinDays";
    Expression={if($_.PwdLastSet -ne 0){(new-TimeSpan([datetime]::FromFileTimeUTC($_.PwdLastSet)) $(Get-Date)).days}else{0}}}
$hash_enabled = @{name='enabled';expression={if($_.useraccountcontrol -band 2){$false}else{$true}}}
$hash_pwdexpired = @{name='PasswordExpired';expression={if($_.useraccountcontrol -band 8388608){$true}else{$false}}}
$hash_fullDelegation = @{name='fullDelegation';expression={($_.useraccountcontrol -band $TRUSTED_FOR_DELEGATION) -ne 0}} 
$hash_constrainedDelegation = @{name='constrainedDelegation';expression={($_.'msDS-AllowedToDelegateTo').count -gt 0}}  
$hash_resourceDelegation = @{name='resourceDelegation';expression={$_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null}}
$hash_AccountNotDelegated = @{name='CannotBeDelegated';expression={if($_.useraccountcontrol -band 1048576){$true}else{$false}}}
#endregion

cls
#this starts the process of dumping all critical admin groups 
#and gathering information about the accounts
$group_members = getgroupMembers

#remove members in exclusion list
$remaining_members = $group_members | where {(!($exclusionlist -contains $_.samaccountname))}

cls

#summary of users in each domain's privaleged group
showdomaingroupcounts
#shows the breakdown of clean up activity.
showsummary
#runs through each account to clean up.
if($silentcleanup){
    silentCleanup -whatif
}else{
    if($(Read-Host -Prompt "Would you like to run through clean up on the accounts and create account exclusions. y for yes, n for no") -eq 'y' -or $cleanup -eq $true){
        startcleanup
    }
}










