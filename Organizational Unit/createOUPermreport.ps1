param($reportpath = "$env:userprofile\Documents")


function getOUPerms{
    $hash_domain = @{name='Domain';expression={$domain}}
    $hash_inheritance = @{name='InheritanceBroken';expression={$_.nTSecurityDescriptor.AreAccessRulesProtected}}
    foreach($domain in (get-adforest).domains){
        Write-host "Gathering OU's from $domain"
        Get-ADObject -ldapFilter "(objectclass=organizationalunit)"  -Properties "msds-approx-immed-subordinates",nTSecurityDescriptor | select DistinguishedName -ExpandProperty nTSecurityDescriptor | select distinguishedname -expandproperty access | where IsInherited -eq $false | select DistinguishedName, IdentityReference, AccessControlType, ActiveDirectoryRights
    }
}

getOUPerms | export-csv "$reportpath\OUpermissions.csv" -NoTypeInformation
write-host "Found reults here $reportpath"
