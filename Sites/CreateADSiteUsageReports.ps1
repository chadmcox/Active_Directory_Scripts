
<#PSScriptInfo

.VERSION 0.3

.GUID 8580e442-6a53-44cc-b821-2fe2d7fda178

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

.TAGS AD Computer Site SiteLink Subnet

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
    0.1 First go around of the script
    0.2 added several features provide instructions for clean up task

.PRIVATEDATA 

.EXAMPLE
    To specify a default path
    .\CreateADSiteUsageReports.ps1 -default_path "c:\temp"

   To store in the user's documents
   .\CreateADSiteUsageReports.ps1

   To skip generating the user report
   .\CreateADSiteUsageReports.ps1 -skipusers

   To skip generating the computer report
   .\CreateADSiteUsageReports.ps1 -skipcomputers

   To skip generating the user and computer report
   .\CreateADSiteUsageReports.ps1 -skipcomputers -skipusers
#>

#Requires -Module ActiveDirectory
#Requires -version 4.0

<# 

.DESCRIPTION 
 creates reports around sites, subnets, sitelinks, user locations and computer locations 
 This script will retrieve information related to sites and services. including computer object and 
   user objects.  Data is viewable via powerbi map

   Sorry about all the splatting
#> 
param($default_path = "$($env:userprofile)\Documents",[switch]$skipusers,[switch]$skipcomputers)

function Get-ipSite{
   param([string]$ip)
        $site = nltest /DSADDRESSTOSITE:$ip /dsgetsite 2>$null
        if ($LASTEXITCODE -eq 0) {
            $split = $site[3] -split "\s+"
            # validate result is for an IPv4 address before continuing
            if ($split[1] -match [regex]"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$") {
                "" | select @{l="ADSite";e={$split[2]}}, @{l="ADSubnet";e={$split[3]}}
        }
    }

}

function get-adobjectlocation{
    [cmdletbinding()]
    param()
    begin{
        $default_log = $default_path + '\report_ou.csv'
        If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}
        }
    process{
        write-Debug "Enumerating object Locations"
        $prog_count = ((get-adforest).domains).count; $i = 0
        Foreach($domain in (get-adforest).domains){$i++
            write-Debug "Enumerating OUs in $domain"
            Write-Progress -Activity "Enumerating Object Locations" -Status "Progress: $domain" -PercentComplete ($I/$prog_count*100)
            
            $splat_params = @{'ldapfilter' = "(|(objectclass=organizationalunit)(objectclass=domainDNS))";
                        'properties' = 'WhenChanged','whencreated','gPLink','gPOptions'
                        'server' = $domain}
            $splat_select_params = @{'property' = $hash_domain,'Name','DistinguishedName','objectclass','WhenChanged','whencreated',`
                'gPLink','gPOptions'}
            
            Get-ADObject @splat_params | `
                select-object @splat_select_params

            (get-addomain $domain).UsersContainer | `
                Get-ADObject -server $domain -properties WhenChanged,whencreated | `
                    select-object @splat_select_params

            (get-addomain $domain).ComputersContainer | `
                Get-ADObject -server $domain -properties WhenChanged,whencreated | `
                    select-object @splat_select_params
        }
    }
    end{
        
        Write-Progress -Activity "Enumerating Object Locations" -Status "End" -Completed 
    }
}

function get-addomaincontrollersites{
    [cmdletbinding()]
    param()
    begin{
        $default_log = $default_path + '\report_dc.csv'
        If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}
        }
    process{
        write-Debug "Enumerating Domain Controllers"
        $prog_count = ((get-adforest).domains).count; $i = 0
        Foreach($_domain in (get-adforest).domains){$i++
            write-Debug "Enumerating DCs in $_domain"
            Write-Progress -Activity "Enumerating Domain Controller" -Status "Progress: $_domain" -PercentComplete ($I/$prog_count*100)

            $splat_params = @{'filter' = '*';
                        'server' = $_domain}
            $splat_select_params = @{'property' = 'Domain','Name','HostName','IPv4Address','Enabled','IsGlobalCatalog',`
            'OperatingSystem','site'}
            
            Get-ADDomainController @splat_params | `
                select-object @splat_select_params | export-csv $default_log -append -NoTypeInformation
        }
    }
    end{
        Write-Progress -Activity "Enumerating Domain Controller" -Status "End" -Completed 
    }
}

function get-adsitedetails{
    [cmdletbinding()]
    param()
    begin{
        $default_log = $default_path + '\report_site.csv'
        If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}
        }
    process{
        write-Debug "Enumerating Sites"
        $prog_count = ((get-adforest).domains).count; $i = 0
        $splat_params = @{'filter' = 'objectClass -eq "site"';
                    'Searchbase' = $((Get-ADRootDSE).ConfigurationNamingContext);
                    'properties' = 'siteObjectBL','description','whencreated','whenchanged','interSiteTopologyGenerator','gpLink';
                    'PipelineVariable' = 'site'}
        $splat_select_params = @{'property' = 'name',`
                $(@{name='Subnet_Count';expression={$(([array]$site |`
                     Select-Object -ExpandProperty siteObjectBL).count)}}),`
                $(@{name='DC_Count';expression={(@(Get-ADObject -Filter 'objectClass -eq "server"'`
                     -searchbase $(($site).DistinguishedName))).count}}),`
                $(@{name='SiteLink_Count';expression={$sn = $(($site).name);`
                    (@(Get-ADReplicationSiteLink -Filter 'SitesIncluded -eq $sn')).count}}),`
                'description',`
                $(@{name='Address';expression={}}),
                $(@{name='City';expression={}}),`
                $(@{name='State';expression={}}),`
                $(@{name='Country';expression={}}),'distinguishedname'}
        
        $script:sites = Get-ADObject @splat_params | `
            select-object @splat_select_params | sort name
        $script:sites | export-csv $default_log -append -NoTypeInformation

        #get good details if commandlet exist
        if(get-command get-adreplicationsite){
            $default_log = $default_path + '\report_site_detailed.csv'
            If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}
            $splat_params = @{'filter' = '*';
                    'properties' = '*'}
            $splat_select_params = @{'property' = 'name','Description','AutomaticInterSiteTopologyGenerationEnabled','AutomaticTopologyGenerationEnabled',`
                    'RedundantServerTopologyEnabled','ScheduleHashingEnabled','TopologyCleanupEnabled','TopologyDetectStaleEnabled','TopologyMinimumHopsEnabled',`
                    'UniversalGroupCachingEnabled','UniversalGroupCachingRefreshSite','WindowsServer2000BridgeheadSelectionMethodEnabled',`
                    'WindowsServer2000KCCISTGSelectionBehaviorEnabled','WindowsServer2003KCCBehaviorEnabled',`
                    'WindowsServer2003KCCIgnoreScheduleEnabled','WindowsServer2003KCCSiteLinkBridgingEnabled',`
                    $(@{name='gpLink';expression={if($_.gplink){$true}else{$false}}}),`
                    $(@{name='istgOrphaned';expression={if($_.interSiteTopologyGenerator -like "*0ADEL*"){$true}else{$false}}}),`
                    'whencreated','whenchanged','DistinguishedName'}
            get-adreplicationsite @splat_params | select-object @splat_select_params | sort name |`
                 export-csv $default_log -NoTypeInformation
        }
    }
    end{
        
    }
}

function get-adsitelinkdetails{
    [cmdletbinding()]
    param()
    begin{
        $default_log = $default_path + '\report_sitelink.csv'
        If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}
        }
    process{
        #could also use Get-ADReplicationSiteLink to get the data
        write-Debug "Enumerating Site Links"
        $prog_count = ((get-adforest).domains).count; $i = 0
        
        $splat_params = @{'filter' = 'objectClass -eq "sitelink"';
                    'Searchbase' = $((Get-ADRootDSE).ConfigurationNamingContext)
                    'properties' = '*'
                    'PipelineVariable' = 'sitelink'}

        $splat_select_params = @{'property' = 'name',`
                                    $(@{name='Site';expression={$first_site.name}}),`
                                    $(@{name='LinkedSite';expression={$second_site.name}}),`
                                    'cost','replInterval','options','whencreated','whenchanged'}

        Get-ADObject @splat_params | foreach {
            $first_site = $null;$second_site = $null
            $splat_params = @{'filter' = {distinguishedname -eq $_};
                        'Searchbase' = $((Get-ADRootDSE).ConfigurationNamingContext)
                        'properties' = '*'}
            if($sitelink.sitelist){$sitelist2 = @()
                $sitelist1 = @()
                [System.Collections.ArrayList]$sitelist1 = $sitelink | select -expandproperty sitelist
                [System.Collections.ArrayList]$sitelist2 = $sitelink | select -expandproperty sitelist
                $sitelist1 | foreach {$_dn = $_
                    $sitelist2.remove($_)
                    $first_site = Get-ADObject @splat_params
                    $sitelist2 | foreach {
                        $second_site = Get-ADObject @splat_params
                        if($first_site.name -ne $second_site.name){
                            $sitelink | select @splat_select_params | export-csv $default_log -append -NoTypeInformation
                        }
                    }
                }
            }else{
            $sitelink | select @splat_select_params | export-csv $default_log -append -NoTypeInformation
            }
        }
    }
    end{
        
    }
}

function get-adsubnetdetails{
    [cmdletbinding()]
    param()
    begin{
        $default_log = $default_path + '\report_subnet.csv'
        If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}
        }
    process{
        write-Debug "Enumerating Subnets"
        $subnets = @()
        $splat_params = @{'filter' = 'objectClass -eq "subnet"';
                    'Searchbase' = $((Get-ADRootDSE).ConfigurationNamingContext;)
                    'properties' = 'siteobject','whencreated','whenchanged';
                    'PipelineVariable' = 'subnet'}
        $splat_select_params = @{'property' = 'name',`
                                        $(@{name='Site';expression={if($_.siteobject){($script:sites |`
                                             where distinguishedname -eq $subnet.siteObject).name}else{$false}}}),`
                                        'whencreated','whenchanged'}
                                        
        
        $subnets = Get-ADObject @splat_params | `
            select-object @splat_select_params
            $subnets | export-csv $default_log -append -NoTypeInformation
    }
    end{
        
    }
}

function get-addcrepconnections{
    [cmdletbinding()]
    param()
    begin{
        $default_log = $default_path + '\report_dc_replication_connections.csv'
        If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}
        }
    process{
        $splat_params = @{'filter' = '*';
                    'properties' = '*'}
        $splat_select_params = @{'property' = 'name','Description','AutoGenerated','enabledConnection',`
                'options',
                $(@{name='fromServer';expression={$(($_.fromServer.split(","))[1] -replace "CN=")}}),`
                $(@{name='ReplicateFromDirectoryServer';expression={$(($_.ReplicateFromDirectoryServer.split(","))[1] -replace "CN=")}}),`
                $(@{name='ReplicateToDirectoryServer';expression={$(($_.ReplicateToDirectoryServer.split(","))[0] -replace "CN=")}}),`
                $(@{name='Intersite';expression={if($(($_.ReplicateToDirectoryServer.split(","))[2] -replace "CN=")`
                     -ne $(($_.ReplicateFromDirectoryServer.split(","))[3] -replace "CN=")){$true}else{$false}}}),`
                'whencreated','whenchanged','DistinguishedName'}
        if(get-command get-adreplicationconnection){get-adreplicationconnection @splat_params |`
             select-object @splat_select_params | sort name |`
                export-csv $default_log -NoTypeInformation}
    }
    end{}
}

function get-adcomputerdetails{
    [cmdletbinding()]
    param()
    begin{
        $default_log = $default_path + '\report_computer.csv'
        If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}
        $stale_date = [DateTime]::Today.AddDays(-90)
        if(!($script:object_locations)){$script:object_locations = get-adobjectlocation}
        }
    process{
        write-Debug "Enumerating Computer"
        $prog_count = ($script:object_locations).count; $i = 0
        $script:object_locations | foreach {$domain = [string]$_.domain
            Write-Progress -Activity "Enumerating Computers" -Status "Progress: $($_.DistinguishedName)"`
                 -PercentComplete ($I/$prog_count*100);$i++
            $splat_params = @{'Filter' = {(isCriticalSystemObject -eq $False)};
                    'server' = $domain;
                    'Properties' = 'PwdLastSet','whencreated','SamAccountName','LastLogonTimeStamp',
                        'Enabled','IPv4Address','operatingsystem','serviceprincipalname';
                    'searchbase' = $($_.DistinguishedName);
                    'searchscope' = 'Onelevel'}

            $splat_select_params = @{'property' = $hash_domain,`
                                        'SamAccountName','enabled','operatingsystem','IPv4Address',`
                                        $hash_isComputerStale,$hash_pwdLastSet,$hash_lastLogonTimestamp,`
                                        $(@{Name="Site";Expression={if($_.IPv4Address){(get-ipsite $_.IPv4Address).ADSite}}}), `
                                        $(@{Name="Subnet";Expression={if($_.IPv4Address){(get-ipsite $_.IPv4Address).ADSubnet}}}),`
                                        'whencreated',`
                                         $(@{Name="ParentOU";Expression={$_.distinguishedname.Substring($_.samaccountname.Length + 3)}})}

            get-adcomputer @splat_params | select @splat_select_params | `
                export-csv $default_log -append -NoTypeInformation
        }
    }
    end{
        Write-Progress -Activity "Enumerating Computers" -Status "End" -Completed 
    }
}

function get-aduserdetails{
    [cmdletbinding()]
    param()
    begin{
        $default_log = $default_path + '\report_user.csv'
        If ($(Try { Test-Path $default_log} Catch { $false })){Remove-Item $default_log -force}
        $stale_date = [DateTime]::Today.AddDays(-90)
        if(!($script:object_locations)){$script:object_locations = get-adobjectlocation}
        }
    process{
        write-Debug "Enumerating User"
        $prog_count = ($script:object_locations).count; $i = 0
        $script:object_locations | foreach {$domain = [string]$_.domain
            Write-Progress -Activity "Enumerating Users" -Status "Progress: $($_.DistinguishedName)"`
                 -PercentComplete ($I/$prog_count*100);$i++
            $splat_params = @{'Filter' = '*';
                    'server' = $domain;
                    'Properties' = 'PwdLastSet','whencreated','WhenChanged','SamAccountName','LastLogonTimeStamp', `
                        'Enabled','c','co','countrycode','l','streetaddress','st';
                    'searchbase' = $($_.DistinguishedName);
                    'searchscope' = 'Onelevel'}

            $splat_select_params = @{'property' = $hash_domain,`
                                        'SamAccountName','enabled',`
                                        $(@{name='City';expression={$_.l}}), `
                                        $(@{name='State';expression={$_.st}}), `
                                        $(@{name='Country';expression={$_.c}}), `
                                        $(@{name='Country1';expression={$_.co}}), `
                                        $(@{name='Country2';expression={$_.countryCode}}), `
                                        $hash_isUserStale,$hash_pwdLastSet,$hash_pwdAge,$hash_lastLogonTimestamp,`
                                        'whencreated','whenchanged'}

            get-aduser @splat_params | select @splat_select_params | `
                export-csv $default_log -append -NoTypeInformation
        }
    }
    end{
        Write-Progress -Activity "Enumerating User" -Status "End" -Completed 
    }
}

#region quick reference hashtables for calculated properties
$hash_domain = @{name='Domain';expression={$domain}}
$hash_isComputerStale = @{Name="Stale";
    Expression={if(($_.LastLogonTimeStamp -lt $stale_date.ToFileTimeUTC() -or $_.LastLogonTimeStamp -notlike "*") `
        -and ($_.pwdlastset -lt $stale_date.ToFileTimeUTC() -or $_.pwdlastset -eq 0) `
        -and ($_.enabled -eq $true) -and ($_.whencreated -lt $stale_date) `
        -and ($_.IPv4Address -eq $null) -and ($_.OperatingSystem -like "Windows*") `
        -and (!($_.serviceprincipalname -like "*MSClusterVirtualServer*"))){$True}else{$False}}}
$hash_isUserStale = @{Name="Stale";
    Expression={if(($_.LastLogonTimeStamp -lt $stale_date.ToFileTimeUTC() -or $_.LastLogonTimeStamp -notlike "*") `
        -and ($_.pwdlastset -lt $stale_date.ToFileTimeUTC() -or $_.pwdlastset -eq 0) `
        -and ($_.enabled -eq $true) -and ($_.whencreated -lt $stale_date)){$True}else{$False}}}
$hash_pwdLastSet = @{Name="pwdLastSet";
    Expression={([datetime]::FromFileTime($_.pwdLastSet))}}
$hash_pwdAge = @{Name="PwdAge";
    Expression={if($_.PwdLastSet -ne 0){(new-TimeSpan([datetime]::FromFileTimeUTC($_.PwdLastSet)) $(Get-Date)).days}else{0}}}
$hash_lastLogonTimestamp = @{Name="LastLogonTimeStamp";
    Expression={([datetime]::FromFileTime($_.LastLogonTimeStamp))}}
#endregion

$script:object_locations = @()
$script:sites  = @()

cls
$runtime_log = $default_path + '\report_runtime.csv'

$splat_measure_Params = @{'property' = $(@{name='RunDate';expression={get-date -format d}}),
                                        $(@{name='Function';expression={$function_name}}), `
                                        $(@{name='Hours';expression={$_.hours}}), `
                                        $(@{name='Minutes';expression={$_.Minutes}}), `
                                        $(@{name='Seconds';expression={$_.Seconds}})}

write-host "Gathering Domain Controller Details"
Measure-Command {get-addomaincontrollersites; $function_name = "get-addomaincontrollersites"} | `
    select @splat_measure_Params | export-csv $runtime_log -append -NoTypeInformation

write-host "Gathering Site Details"
Measure-Command {get-adsitedetails; $function_name = "get-adsitedetails"} | `
    select @splat_measure_Params | export-csv $runtime_log -append -NoTypeInformation

write-host "Gathering Site Link Details"
Measure-Command {get-adsitelinkdetails; $function_name = "get-adsitelinkdetails"} | `
    select @splat_measure_Params | export-csv $runtime_log -append -NoTypeInformation

write-host "Gathering Subnet Details"
Measure-Command {get-adsubnetdetails; $function_name = "get-adsubnetdetails"} | `
    select @splat_measure_Params | export-csv $runtime_log -append -NoTypeInformation

write-host "Gathering Replication Connection Details"
Measure-Command {get-addcrepconnections; $function_name = "get-addcrepconnections"} | `
    select @splat_measure_Params | export-csv $runtime_log -append -NoTypeInformation

$script:object_locations | export-csv "$default_path\report_ou.csv" -append -NoTypeInformation

if(!($skipcomputers)){
write-host "Gathering Computer Site Details *this will take a while*"
Measure-Command {get-adcomputerdetails; $function_name = "get-adcomputerdetails"} | `
    select @splat_measure_Params | export-csv $runtime_log -append -NoTypeInformation}
if(!($skipusers)){
write-host "Gathering User Location Details *this will take a while*"
Measure-Command {get-aduserdetails; $function_name = "get-aduserdetails"} | `
    select @splat_measure_Params | export-csv $runtime_log -append -NoTypeInformation}

cd $default_path

write-host -foregroundcolor yellow "Reports can be found here: $default_path"
write-host "--------------------------------------------------------------------------------------"
write-host "
Open each report in Excel, create a filter based on Header.
* Review report_site.csv find sites with no Subnets and No DC assigned. Consider Deleting.
* * Can also run: import-csv .\report_site.csv | where {$_.Subnet_Count -eq 0 -and $_.DC_Count -eq 0} | select name"
write-host "
* Review report_site_detailed.csv if created.
* * Consider Removing any GPO assigned in gplink for a site.
* * Consider Removing any istgorphans that may exist.
* * Most settings in the report should be null, review is setting is desired."
write-host "
* Review report_subnet.csv consider deleting any subnet not assigned to a site."
write-host "
* Review report_sitelink.csv.
* * Best Practice is two sites per site link.
* * Delete or fix any site link with only one site.
* * Consider leveraging change notification on all site link with DCs in the site."
write-host "
* Review report_dc_replication_connections.csv
* * Consider removing any AutoGenerated = False.
* * At minimum every DC should have one to and one from connection."
write-host '
* Review report_computer.csv
* * Consider removing stale objects.
* * Find Computers with ip4address but no site defined, more than likely those are not in sites and services.
* * Pivot off of subnets that computers are mapped to consider removing unused subnets.
* * * Can also run: import-csv .\report_computer.csv | group subnet | Select name, count'
write-host "
* Review report_user.csv
* * Consider removing stale objects."
