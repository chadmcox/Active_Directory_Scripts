<#PSScriptInfo
.VERSION 0.1
.GUID dd9be3d5-52e5-4a1e-9d57-d99e01f1f312
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
.TAGS AD GPO
.LICENSEURI 
.PROJECTURI 
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
0.1 First go around of the script
.PRIVATEDATA 
#>

#Requires -Module ActiveDirectory
#Requires -Module GroupPolicy
#Requires -version 4

<# 
.DESCRIPTION 
 This script enumerates anything with gplink and searches for a unresolvable guid 
#> 
Param($defaultlog = "$env:userprofile\Documents\report_gpo_links.csv")
$results = @()
$hash_domain = @{Name="Domain";Expression={$domain}}
$hash_dn = @{Name="DistinguishedName";Expression={$location.distinguishedname}}
$hash_oc = @{Name="ObjectClass";Expression={$location.objectclass}}

Function resolve-gpoguid{
    param($guidtosearch)
    $found_gpo = $null
    (get-adforest).domains | foreach{
        $gpo = get-gpo -guid $matches[0] -Domain $_ -ErrorAction SilentlyContinue
        if($gpo){
            $found_gpo = $gpo
        }
    }
    [string]$gpo_state = (($_).split(";"))[1]
    $gpo_state =  $gpo_state.replace("]","")
    $location | select $hash_domain,$hash_dn,$hash_oc,`
        @{Name="GPOName";Expression={if($found_gpo){$found_gpo.displayname}else{$matches[0]}}},`
        @{Name="Resolved";Expression={if($found_gpo){$true}else{$false}}},`
        @{Name="GPOState";Expression={if($gpo_state){$gpo_state}else{99}}}
}

#gplinks from objects in each domain container
(get-adforest).domains | foreach{$domain = $_
    get-adobject -filter {gplink -like "*"} -properties gplink -server $domain -PipelineVariable location | foreach{
        [array]$array_gplink = $($location.gplink).split("`\[") 
        [array]$array_gplink | foreach{
            if($_){
                #$location.distinguishedname
                $guid = $_ -match "(([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12})"
                $results += resolve-gpoguid -guidtosearch $matches[0] 
            }
        }
    }
}
#gplinks from objects on Sites
get-adobject -filter {gplink -like "*"} -properties gplink -Searchbase $((Get-ADRootDSE).ConfigurationNamingContext) `
    -PipelineVariable location | foreach{
    $domain = (get-adforest).name
    [array]$array_gplink = $($location.gplink).split("`\[") 
    [array]$array_gplink | foreach{
        if($_){
            #$location.distinguishedname
            $guid = $_ -match "(([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12})"
            $results += resolve-gpoguid -guidtosearch $matches[0] 
        }
    }
}

cls
$results | export-csv $defaultlog -NoTypeInformation
write-host "Found $(($results | where resolved -eq $false | group resolved | select Count).count) GPLINKS with unresolvable GPO"
write-host "Found $(($results | where GPOState -eq 99| group GPOState | select Count).count) with Block Inheritance"
write-host "Found $(($results | where GPOState -eq 1 | group GPOState | select Count).count) with GPO Disabled"
write-host "Found $(($results | where GPOState -eq 2 | group GPOState | select Count).count) with GPO Enforced"
write-host "Found $(($results | where ObjectClass -eq "domainDNS" | group resolved | select Count).count) GPLINKS on the Root of the Domain"
write-host "Found $(($results | where ObjectClass -eq "Site" | group resolved | select Count).count) GPLINKS set on Sites"
write-host "Results can be found here $defaultlog"
write-host "--------------------------------------------------------------------------------------"
write-host -foreground yellow "Open the csv in excel and sort based on the column headers."
write-host -foreground yellow  "*remove any gpos on containers that are not resolvable"
write-host -foreground yellow  "*review containers that are Blocking Inheritance"
write-host -foreground yellow  "*review site linked gpos and consider removing the gpo"
