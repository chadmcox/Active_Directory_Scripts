
<#PSScriptInfo

.VERSION 0.4

.GUID d96dbab2-8c25-4761-b7fc-ddaab5928472

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

.TAGS Active Directory Replication

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
#Requires -RunAsAdministrator
#Requires -Version 4

<# 

.DESCRIPTION 
 This script modifies and object in the configuration container and watches update on all domain controllers. 
 Then creaes a final report. 

#> 
Param($reportpath = "$env:userprofile\Documents")

$default_log = "$reportpath\report_active_directory_replication_convergence.csv"
If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}
$not_replicating_log = "$reportpath\report_domain_controller_failed_to_replicate.csv"
If ($(Try { Test-Path $not_replicating_log} Catch { $false })){Remove-Item $not_replicating_log -force}

[System.Collections.ArrayList]$domain_controllers_list = @();[System.Collections.ArrayList]$domain_controllers = @()

#gather list of all domain controllers in the forest with domain and site information
$domain_controllers_list = (get-adforest).domains | foreach{get-addomaincontroller -Filter * -server $_ | select domain,hostname,site}

#this is the object that gets changed, script watches this object on all DC's
$object_dn = "CN=Sites,$((get-adrootdse).configurationNamingContext)"
$ad_partition = (get-adrootdse).configurationNamingContext

#each loop will wait 5 seconds
$SleepTimer = 1

#random value that goes into the attribute
$value = 1..1000 | get-random

#this is the actual start time the script leverages to compare times
$start_time = get-date

#set value on current domains pdc
get-adobject $object_dn -Partition $ad_partition -properties wWWHomePage `
    -server (Get-ADDomain).PDCEmulator | set-adobject -Replace @{wWWHomePage=$value}

#used for progress bar
$count = ($domain_controllers_list).count; $i = 0
cls

Measure-Command {
    While (($domain_controllers_list | measure).count -ne 0){
        Write-Progress -Activity "Active Directory Replication Convergence"`
         -Status "Time Passed: $("{0:hh}:{0:mm}:{0:ss}" -f ($(get-date)-$start_time)), Domain Controllers Remaining: $($count - $i)"`
         -PercentComplete ($I/$count*100)
        [System.Collections.ArrayList]$domain_controllers = {$domain_controllers_list}.invoke()
        foreach($domain_controller in ($domain_controllers | sort site)){
            $query_time = get-date
            $replicated_value = (get-adobject $object_dn -Partition $ad_partition -properties wWWHomePage `
                                    -server $($domain_controller.hostname)).wWWHomePage
            if($value -eq $replicated_value){$i++
                $results = $domain_controller | select Domain,Hostname,Site,`
                    @{Name='TimeToReplicate';Expression ={$("{0:hh}:{0:mm}:{0:ss}" -f ($query_time-$start_time))}},`
                    @{Name='Value';Expression ={$value}}
                $domain_controllers_list.remove($domain_controller) 
                $results | export-csv $default_log -Append -NoTypeInformation
                $results | Out-Host
            }
        }
        Start-Sleep -seconds $SleepTimer;
        if((get-date) -gt $($start_time + (New-TimeSpan -hours 1))){
            #if time is greater than 1 hour stop script and report remaining domain controllers
            write-host "following Domain Controllers did not replicate within 1 hour:"
            $domain_controllers_list  | Out-Host
            $domain_controllers_list | export-csv $default_log -Append -NoTypeInformation
            #consider sending errors via email using send-mailmessage
            break
        }
    }
} | select @{name='Title';expression={"Total Convergence Time"}}, `
            @{name='Errors';expression={($domain_controllers_list | meassure).count}}, `
            @{name='Hours';expression={$_.hours}}, `
            @{name='Minutes';expression={$_.Minutes}}, `
            @{name='Seconds';expression={$_.Seconds}}

write-host "Report Can be found here $reportpath"
write-host "run to review the results: import-csv $default_log | Out-GridView"
Write-Progress -Activity "Active Directory Replication Convergence" -Status "End" -Completed 
