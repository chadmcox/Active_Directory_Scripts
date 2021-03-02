param($reportpath = "$env:userprofile\Documents")
$schemaIDGUID = @{}
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID | `
    ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}

Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' `
    -Properties name, rightsGUID | `
    ForEach-Object {$schemaIDGUID.add([System.GUID]$_.rightsGUID,$_.name)}

function getOUPerms{
    $hash_domain = @{name='Domain';expression={$domain}}
    $hash_inheritance = @{name='InheritanceBroken';expression={$_.nTSecurityDescriptor.AreAccessRulesProtected}}
    foreach($domain in (get-adforest).domains){
        Write-host "Gathering OU's from $domain"
        Get-ADObject -ldapFilter "(objectclass=organizationalunit)"  -Properties "msds-approx-immed-subordinates",nTSecurityDescriptor,CanonicalName -server $domain | `
            select CanonicalName,DistinguishedName -ExpandProperty nTSecurityDescriptor | select CanonicalName,distinguishedname -expandproperty access | `
                where IsInherited -ne $True | where {!($_.IdentityReference -like "NT AUTHORITY\*") -and !($_.IdentityReference -like "BUILTIN\*") -and !($_.IdentityReference -eq "S-1-5-32-548") -and !($_.IdentityReference -eq "Everyone")} | `
                    select DistinguishedName, CanonicalName, IdentityReference, AccessControlType, ActiveDirectoryRights, IsInherited, `
                        @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaIDGUID.Item($_.objectType)}}}, `
                        @{name='inheritedObjectTypeName';expression={$schemaIDGUID.Item($_.inheritedObjectType)}}
    }
}

getOUPerms # | export-csv "$reportpath\OUpermissions.csv" -NoTypeInformation
write-host "Found reults here $reportpath"
