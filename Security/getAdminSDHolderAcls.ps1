param($reportpath = "$env:userprofile\Documents")
$schemaIDGUID = @{}
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID | `
    ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}

Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' `
    -Properties name, rightsGUID | `
    ForEach-Object {$schemaIDGUID.add([System.GUID]$_.rightsGUID,$_.name)}


get-adforest | select -ExpandProperty domains -pv domain | foreach {
    $hash_domain = @{name='Domain';expression={$domain}}
    Get-ADObject "CN=AdminSDHolder,$((get-addomain -Server $domain).SystemsContainer)" -Properties "msds-approx-immed-subordinates",nTSecurityDescriptor -server $domain | `
            select DistinguishedName -ExpandProperty nTSecurityDescriptor | select distinguishedname -expandproperty access | select $hash_domain,`
                DistinguishedName, CanonicalName, IdentityReference, AccessControlType, ActiveDirectoryRights, IsInherited, `
                @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaIDGUID.Item($_.objectType)}}}, `
                @{name='inheritedObjectTypeName';expression={$schemaIDGUID.Item($_.inheritedObjectType)}}

} | export-csv "$reportpath\sdadmins_perms.csv" -NoTypeInformation
