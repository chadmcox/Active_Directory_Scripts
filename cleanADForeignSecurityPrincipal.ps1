#Requires -Module ActiveDirectory
<#PSScriptInfo

.VERSION 0.1

.GUID bff8254c-d342-4d67-876e-378d5ca57447

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
 0.2 fixed to make sure it enumerates each domain
    does a trust domain sid check to make sure trust is still valid
    removes builtin sids from report

.DESCRIPTION 
 This script creates reports on foreign security principals. 

#> 
Param($reportpath = "$env:userprofile\Documents")

function CollectFSPGroupMembership{
    
    $results = @()
    #enumerate fsp members

    $trusted_domain_SIDs = @()
    foreach($domain in (get-adforest).domains){
        $trusted_domain_SIDs += get-adtrust -filter {intraforest -eq $false} -Properties securityIdentifier -server $domain | select securityIdentifier,target
    }

    Foreach($domain in (get-adforest).domains){
        #get trust of existing domain
        #$trusted_domain_SIDs = (get-adtrust -filter {intraforest -eq $false} -Properties securityIdentifier -server $domain).securityIdentifier.value

        Get-ADObject -Filter { objectClass -eq "foreignSecurityPrincipal" } -Properties memberof -server $domain -PipelineVariable fsp | select -ExpandProperty memberof | foreach{
            $group = $_
            if($fsp.Name -match "^S-\d-\d+-\d+-\d+-\d+-\d+"){$domain_sid = $matches[0]}else{$domain_sid = $null}
            $fsp_translate = try{([System.Security.Principal.SecurityIdentifier] $fsp.name).Translate([System.Security.Principal.NTAccount])}catch{"Orphan"}
            $results += $fsp | select $hash_domain,name, `
                @{name='Translate';expression={$fsp_translate}}, `
                @{name='TrustExist';expression={($trusted_domain_SIDs | where {$_.securityidentifier -eq $domain_sid}).target}}, `
                @{name='Memberof';expression={$group}},DistinguishedName | `
                where {$_.name -notmatch "^S-\d-\d+-(\d+)$"}
        }
    }
    write-host "Found $(($results | measure-object).count) references of FSP in Groups"
    write-host "Found $(($results | where {$_.translate -eq "Orphan"} | measure-object).count) references of Orphan FSP in Groups"
    $results | export-csv "$reportpath\reportForeignSecurityPricipalsGroupMembership-$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).csv" -NoTypeInformation
    $results
}

function RemoveFSPFromGroup{
    param($fsp,$adgroupdn,$adgroupdomain,$FSPDomain,$FSPObject)
    if($fspDomain){$fspdomain = $adgroupdomain} #have to set fspdomain of orphan
    $objtoremove = get-adobject -filter {name -eq $FSP} -server $FSPDomain
    $grp = get-adobject -Identity $adgroupdn -server $adgroupdomain
    $orphan = try{([System.Security.Principal.SecurityIdentifier] $fsp).Translate([System.Security.Principal.NTAccount])}catch{$true}
    if($orphan -eq $true){
        $status = "$(get-date) - Removing Orphaned $FSP from group $adgroupdn"; write-host $status
            add-content -value $status -path "$reportpath\logRemoveFSPfromGRP.txt"
            try{$grp | Set-ADObject -Remove @{'member'="$(($objtoremove).distinguishedname)"} -whatif}
                catch{
                $_.Exception
                $status = "$(get-date) - Error!!! Removing Orphan $FSP from group $adgroupdn"; write-host $status -ForegroundColor red
                add-content -value $status -path "$reportpath\logRemoveFSPfromGRP.txt"}
    }else{
        $fspobj = get-adobject -filter {samaccountname -eq $FSPObject} -server $FSPDomain
        if((validateTranslatedObjectinGroup -FSPDomain $fspdomain -FSPObjectdn ($fspobj).distinguishedname `
            -adgroupdn $adgroupdn -adgroupdomain $adgroupdomain)){
            $status = "$(get-date) - Removing Translated $FSP from group $adgroupdn"; write-host $status
            add-content -value $status -path "$reportpath\logRemoveFSPfromGRP.txt"
            try{$grp | Set-ADObject -Remove @{'member'="$(($objtoremove).distinguishedname)"} -whatif}
                catch{
                $status = "$(get-date) - Error!!! Removing $FSP from group $adgroupdn"; write-host $status -ForegroundColor red
                add-content -value $status -path "$reportpath\logRemoveFSPfromGRP.txt"}
        }else{
            $status = "$(get-date) - Translated Object not found!! Did Not Remove $FSP from group $adgroupdn"; write-host $status
            add-content -value $status -path "$reportpath\logRemoveFSPfromGRP.txt"
        }
    }
}

Function AddTranslatedObjecttoGroup{
    param($FSPDomain,$FSPObject,$adgroupdn,$adgroupdomain)
    $objtoadd = get-adobject -filter {samaccountname -eq $FSPObject} -server $FSPDomain

    #is object already a member of group
    if(!(validateTranslatedObjectinGroup -FSPDomain $fspdomain -FSPObjectdn ($objtoadd).distinguishedname `
        -adgroupdn $adgroupdn -adgroupdomain $adgroupdomain)){
        #get the group
        $grp = get-adobject -Identity $adgroupdn -server $adgroupdomain
        #add the direct object to the group
        $status = "$(get-date) - Adding $FSPObject to $adgroupdn"; write-host $status
        add-content -value $status -path "$reportpath\logAddFSPtoGRP.txt"
        try{Add-ADGroupMember -Identity $grp -Members $objtoadd -whatif}
            catch{
            $status = "$(get-date) - Error!!! Adding $FSPObject to $adgroupdn"; write-host $status -ForegroundColor red
            add-content -value $status -path "$reportpath\logAddFSPtoGRP.txt"}
    }else{
        $status = "$(get-date) - Already Added $FSPObject to $adgroupdn"
        Write-host $status
        add-content -value $status -path "$reportpath\logAddFSPtoGRP.txt"
    }
}

Function validateTranslatedObjectinGroup{
    param($FSPDomain,$FSPObjectdn,$adgroupdn,$adgroupdomain)
    
    if(Get-ADgroup -Filter {member -recursivematch $FSPObjectdn} `
        -searchbase $adgroupdn -server $adgroupdomain){
        $true
    }else{$false}
}

function CollectFSPwithNoGroupMembership{
$results = @()
#translate Sid
    Foreach($domain in (get-adforest).domains){
        $results += Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal" -and memberof -notlike "*"} -server $domain | ForEach-Object {$fsp_translate = $null
            $fsp_translate = try{([System.Security.Principal.SecurityIdentifier] $_.Name).Translate([System.Security.Principal.NTAccount])}catch{"Orphan"}
	        $_ | select $hash_domain,name, `
            @{name='Translate';expression={$fsp_translate}} | `
                where {$_.name -notmatch "^S-\d-\d+-(\d+)$"}
        }
    }
    write-host "Found $(($results | measure-object).count) FSP with no Group Membership"
    write-host "Found $(($results |  where {$_.translate -eq "Orphan"} | measure-object).count) Orphan FSP with no Group Membership"
    $results | export-csv "$reportpath\reportForeignSecurityPricipalsNoGroupMemberShips.csv" -NoTypeInformation
}
function startTranslatedObjectAdds{
    #resolvable fsp's actual object will get added to the group.
    $allFSP | where {$_.Translate -ne "Orphan"} | foreach{
        $tranobj = ($_).Translate
        $tranobj = $tranobj -split '\\'
        AddTranslatedObjecttoGroup -FSPDomain $tranobj[0] -FSPObject $tranobj[1] `
            -adgroupdn ($_).Memberof -adgroupdomain ($_).domain
    }
}
function startFSPRemovalfromGroups{
    $allfsp | foreach {
        $tranobj = ($_).Translate
        $tranobj = $tranobj -split '\\'
        RemoveFSPFromGroup -fsp ($_).name -adgroupdn ($_).Memberof -adgroupdomain ($_).domain -FSPDomain $tranobj[0] -FSPObject $tranobj[1]
    }
}
function deleteFSPforever{
    param($reportfile)
    import-csv $reportfile | foreach{
        $status = "$(get-date) - Deleting $(($_).name)"; write-host $status
        add-content -value $status -path "$reportpath\logdeleteFSP.txt"
        try{get-adobject -filter {name -eq $(($_).name)} -server $(($_).domain) | remove-object -whatif}
            catch{$status = "$(get-date) - Error Deleting $(($_).name)"; write-host $status -ForegroundColor red
                add-content -value $status -path "$reportpath\logdeleteFSP.txt.txt"}
    }
}
function recoverFSPGroupMembership{
    param($reportfile)
    import-csv $reportfile | foreach{
        get-adobject -Identity $_.Memberof -server $_.Domain | Set-ADObject -add @{'member'="$(($_).distinguishedname)"} -whatif
    }
}

#gather all the groups with FSP's
$allFSP = CollectFSPGroupMembership

#run this function to put correct object in group
#startTranslatedObjectAdds

#run this function to remove fsp from groups
#startFSPRemovalfromGroups

$unusedFSP = CollectFSPwithNoGroupMembership


#function for to fsp back into groups
#recoverFSPGroupMembership -reportfile $reportpath\reportForeignSecurityPricipalsGroupMembership-09-26-2018_04-36-40.csv

#function to remove unused fsp
#recoverFSPGroupMembership -reportfile $reportpath\reportForeignSecurityPricipalsNoGroupMemberShips.csv
