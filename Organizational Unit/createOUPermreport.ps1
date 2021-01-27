param($reportpath = "$env:userprofile\Documents")


function getOUPerms{
    $hash_domain = @{name='Domain';expression={$domain}}
    $hash_inheritance = @{name='InheritanceBroken';expression={$_.nTSecurityDescriptor.AreAccessRulesProtected}}
    foreach($domain in (get-adforest).domains){
        Write-host "Gathering OU's from $domain"
        Get-ADObject -ldapFilter "(objectclass=organizationalunit)"  -Properties "msds-approx-immed-subordinates",nTSecurityDescriptor -server $domain | `
            select DistinguishedName -ExpandProperty nTSecurityDescriptor | select distinguishedname -expandproperty access | `
                where IsInherited -ne $True | where {!($_.IdentityReference -like "NT AUTHORITY\*") -and !($_.IdentityReference -like "BUILTIN\*") -and !($_.IdentityReference -eq "S-1-5-32-548") -and !($_.IdentityReference -eq "Everyone")} | `
                    select DistinguishedName, IdentityReference, AccessControlType, ActiveDirectoryRights, IsInherited
    }
}

getOUPerms | export-csv "$reportpath\OUpermissions.csv" -NoTypeInformation
write-host "Found reults here $reportpath"
