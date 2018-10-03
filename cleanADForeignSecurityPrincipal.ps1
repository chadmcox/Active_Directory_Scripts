#Requires -Module ActiveDirectory
#Requires -version 4.0
<#PSScriptInfo

.VERSION 0.6

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
Source: https://github.com/chadmcox/ADPoSh/blob/master/cleanADForeignSecurityPrincipal.ps1

!!!!!!
-whatif must be removed throughout if wanting to actually perform change, by doing so you acknowledge testing was done.
!!!!!

0.6
adding previous sid cache, it occured to me that I was hitting the domain controllers multiple times to resolve the same sidd as the previous
0.5 was leaving the connection open to the domain when i translated the fsp.  have all fsps writing to array now and work with array.
0.3 added menus
    fsp removal only happens if translated object is in the same domain
    Orphan fsp removal only happens if trust does not exist.
 0.2 fixed to make sure it enumerates each domain
    does a trust domain sid check to make sure trust is still valid
    removes builtin sids from report

.DESCRIPTION 
 This script creates reports on foreign security principals. Also allows admins to take action against them
 When the script is ran a menu will load.
 option 0 and 1 will run reports to determine scope of foreignsecurityprincipals 
 Option 2 will take the translated foreignsecurityprincipals and put its actual object into each group the fsp is a member of
 Option 3 removes only fsp's that are not from a trusted forest and the sid is not translatable and removes all of its group membership
 Option 4 removes all fsp out of groups, it only does so if the fsp is orphaned or the translated object is already added to group
 Option 5 Deletes fsp's from the list created from running option 1, this will display a list of the last 5 files generated and allow you to pick 1
 Option 6 restores fsp group membership based on reports generated from option 0, this will display a list of the last 5 files generated and allow you to pick 1
 Option 10 runs both option 0 and 1 reports.

#> 
Param($reportpath = "$env:userprofile\Documents")

$script:previousSid = @{}

function translateFSPSID{
    param($sid)
    $sidalreadyincache = $script:previousSid[$sid]
    if($sidalreadyincache){
        #Write-host "Already Resolved"
        $fsp_translate = $script:previousSid[$sid]
        return $fsp_translate
    }else{
        #Write-host "Resolving"
        $fsp_translate = try{(([System.Security.Principal.SecurityIdentifier] $fsp.name).Translate([System.Security.Principal.NTAccount])).value}catch{"Orphan"}
        $script:previousSid = @{$sid=$fsp_translate}
        return $fsp_translate
    }
}

function CollectFSPGroupMembership{
    write-host "Collecting Groups with ForeignSecurityPrincipals"
    $results = @()
    #enumerate fsp members
   
    $trusted_domain_SIDs = @()
    foreach($domain in (get-adforest).domains){
        $trusted_domain_SIDs += get-adtrust -filter {intraforest -eq $false} -Properties securityIdentifier -server $domain | select securityIdentifier,target
    }

    Foreach($domain in (get-adforest).domains){
        #get trust of existing domain
        #$trusted_domain_SIDs = (get-adtrust -filter {intraforest -eq $false} -Properties securityIdentifier -server $domain).securityIdentifier.value
        write-host "Searching $domain"
        $fsps = Get-ADObject -Filter { objectClass -eq "foreignSecurityPrincipal" } -Properties memberof -server $domain 
        $fsps | foreach{$fsp = $_
            $fsp | select -ExpandProperty memberof | foreach{
            $group = $_
            if($fsp.Name -match "^S-\d-\d+-\d+-\d+-\d+-\d+"){$domain_sid = $matches[0]}else{$domain_sid = $null}
            #this will do a check, if the sid has already been translated or will translate if not.
            $fsp_translate = translateFSPSID -sid ($fsp).Name
            $results += $fsp | select $hash_domain,name, `
                @{name='Translate';expression={$fsp_translate}}, `
                @{name='TrustExist';expression={($trusted_domain_SIDs | where {$_.securityidentifier -eq $domain_sid}).target}}, `
                @{name='Memberof';expression={$group}},DistinguishedName | `
                where {$_.name -notmatch "^S-\d-\d+-(\d+)$"}
        }}
    }
    write-host "Found $(($results | measure-object).count) references of FSP in Groups"
    write-host "Found $(($results | where {$_.translate -eq "Orphan"} | measure-object).count) references of Orphan FSP in Groups"
    write-host "Orphan FSP is usually caused when the sid of the name of the fsp is no longer found in the sidhistory of an object or the object is no longer found over a trust."
    write-host "Use the report located here: $reportpath and review the fsp's that are orphaned."
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
            $status = "$(get-date) - Translated Object not found in group!! Did Not Remove $FSP from group $adgroupdn"; write-host $status
            add-content -value $status -path "$reportpath\logRemoveFSPfromGRP.txt"
        }
    }
}
Function AddTranslatedObjecttoGroup{
    param($FSPDomain,$FSPObject,$adgroupdn,$adgroupdomain)

    #to simplify this I made it so that the new object needs to be in the same domain as the group.  
    #this will make it so that objects still over trust to not readd a new fsp
    try{$objtoadd = get-adobject -filter {samaccountname -eq $FSPObject} -server $adgroupdomain}
        catch{$status = "$(get-date) - Error!!!! Object $FSPObject not found in same domain as group: $adgroupdomain"
            Write-host $status
            add-content -value $status -path "$reportpath\logAddFSPtoGRP.txt"}
    if($objtoadd){
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
}
Function validateTranslatedObjectinGroup{
    param($FSPDomain,$FSPObjectdn,$adgroupdn,$adgroupdomain)
    
    if(Get-ADgroup -Filter {member -like $FSPObjectdn} `
        -searchbase $adgroupdn -server $adgroupdomain){
        $true
    }else{$false}
}
function CollectFSPwithNoGroupMembership{
write-host "Collecting ForeignSecurityPrincipals with no group memberships"
$results = @()
#translate Sid
    Foreach($domain in (get-adforest).domains){
        write-host "Searching $domain"
        $fsps = Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal" -and memberof -notlike "*"} -server $domain
        $results +=  $fsps | ForEach-Object {$fsp_translate = $null
            $fsp_translate = try{([System.Security.Principal.SecurityIdentifier] $_.Name).Translate([System.Security.Principal.NTAccount])}catch{"Orphan"}
	        $_ | select $hash_domain,name, `
            @{name='Translate';expression={$fsp_translate}} | `
                where {$_.name -notmatch "^S-\d-\d+-(\d+)$"}
        }
    }
    write-host "Found $(($results | measure-object).count) FSP with no Group Membership"
    write-host "Found $(($results |  where {$_.translate -eq "Orphan"} | measure-object).count) Orphan FSP with no Group Membership"
    write-host "Use the report located here: $reportpath and review the fsp's that are not members of any group, which means they are not used."
    $results | export-csv "$reportpath\reportForeignSecurityPricipalsNoGroupMemberShips-$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).csv" -NoTypeInformation
}
function startTranslatedObjectAdds{
    if(!($allFSP)){
        $allfsp = CollectFSPGroupMembership
    }
    #resolvable fsp's actual object will get added to the group.
    $allFSP | where {$_.Translate -ne "Orphan"} | foreach{
        $tranobj = ($_).Translate
        $tranobj = $tranobj -split '\\'
        AddTranslatedObjecttoGroup -FSPDomain $tranobj[0] -FSPObject $tranobj[1] `
            -adgroupdn ($_).Memberof -adgroupdomain ($_).domain
    }
}
function startFSPRemovalfromGroups{
    param([switch]$nottranslated)
    if(!($allFSP)){
        $script:allfsp = CollectFSPGroupMembership
    }
    if($nottranslated){
        write-host "Only Removing Orphans from Groups"
        #this filters the list to objects that do not translate and the trust exist property is null
        $allfsp = $allfsp | where {$_.translate -eq "Orphan" -and $_.trustexist -eq $null}
    }

    $allfsp | foreach {
        $tranobj = ($_).Translate
        $tranobj = $tranobj -split '\\'
        RemoveFSPFromGroup -fsp ($_).name -adgroupdn ($_).Memberof -adgroupdomain ($_).domain `
            -FSPDomain $tranobj[0] -FSPObject $tranobj[1]
    }
}
function deleteFSPforever{
    param($reportfile)
    if(!(Get-ADOptionalFeature -Filter {name -eq "Recycle Bin Feature"} | where {$_.enabledscopes -like "*"})){
        $continue = read-host "Recycle Bin is not enabled, press y then ENTER to proceed with deletion."
    }else{
        $continue = "y"
    }
    if($continue -eq "y"){
    import-csv $reportfile | foreach{
        $status = "$(get-date) - Deleting $(($_).name)"; write-host $status
        add-content -value $status -path "$reportpath\logdeleteFSP.txt"
        $fspname = ($_).name
        $fsddomain = ($_).domain
        try{get-adobject -filter {name -eq $fspname} -server $fsddomain | remove-adobject -whatif}
            catch{$_.Exception ;$status = "$(get-date) - Error Deleting $(($_).name)"; write-host $status -ForegroundColor red
                add-content -value $status -path "$reportpath\logdeleteFSP.txt.txt"}
    }}
}
function recoverFSPGroupMembership{
    param($reportfile)
    if($reportfile){
    import-csv $reportfile | foreach{
        get-adobject -Identity $_.Memberof -server $_.Domain | Set-ADObject -add @{'member'="$(($_).distinguishedname)"} -whatif
    }
    }else{
        write-host "No file specified"
    }
}
function launchMenu{
    cls
    Write-host -ForegroundColor yellow "Select the option you would like to run:"
    Write-host "   0 - Create Report of all FSP's Group Membership"
    Write-host "   1 - Create Report of all FSP without Group Membership"
    Write-host "   2 - Add Valid Translated Object to Group with associated FSP"
    Write-host "   3 - Remove Orphan FSPs from Groups (only if sid not from existing trusted domain)"
    Write-host "   4 - Remove ALL FSPs from Groups (validates translated object in group)"
    Write-host "   5 - Delete FSP from Active Directory (uses option 1 reports)"
    Write-host "   6 - Restore FSP's Group membership (uses Option 0 reports)"
    Write-host "   10 - Runs Option 1 & Option 0 to Create Both Reports"
    
    
    $xMenuChoiceA = read-host "Please enter an option 0 to 6 or 10..."

    switch($xMenuChoiceA){
        0{$script:allFSP = CollectFSPGroupMembership}
        1{$script:unusedFSP = CollectFSPwithNoGroupMembership}
        2{startTranslatedObjectAdds}
        3{startFSPRemovalfromGroups -nottranslated}
        4{startFSPRemovalfromGroups}
        5{$removefile = findlist -notamember;deleteFSPforever -reportfile $removefile}
        6{$restorefile = findlist -isamember;recoverFSPGroupMembership -reportfile $restorefile}
        10{CollectFSPwithNoGroupMembership;$script:allFSP = CollectFSPGroupMembership}
    }
}
function findlist{
    param([switch]$notamember,`
        [switch]$isamember)
    $i = 1
    if($isamember){
        #this will pull the possible list to remove fsp out of group membership
        $process = "restore fsp in group membership"
        $selection = Get-ChildItem -Path "$reportpath\*" -Include reportForeignSecurityPricipalsGroupMembership* | `
            sort LastWriteTime | select -last 5 | foreach{
            $_ | select fullname, `
            @{name='Option';expression={$i}}
            $i++
        }
    }elseif($notamember){
        #this will pull the list of fsp that are best to delete from AD
        $process = "removal of fsp from AD"
        $selection = Get-ChildItem -Path "$reportpath\*" -Include reportForeignSecurityPricipalsNoGroupMemberShips* | `
            sort LastWriteTime | select -last 5 | foreach{
            $_ | select fullname, `
            @{name='Option';expression={$i}}
            $i++
        }
    }
    if($selection){
    cls
    $selection | Select Option,fullname | out-host
    $xMenuChoiceA = read-host "Choose the option number of the file you would like to run the $process against?"
    return ($selection | where {$_.option -eq $xMenuChoiceA}).fullname
    }
}

$hash_domain = @{name='Domain';expression={$domain}}
$allFSP = @()
launchMenu
