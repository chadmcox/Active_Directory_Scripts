$path = "$env:userprofile\Documents\domain_acls.csv"
$schemaIDGUID = @{}
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID |
    ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID |
    ForEach-Object {$schemaIDGUID.add([System.GUID]$_.rightsGUID,$_.name)}
Foreach($domain in (get-adforest).domains){
    try{get-PSDrive -Name ADROOT -ErrorAction SilentlyContinue | Remove-PSDrive -force}catch{}
    $ps_drive = New-PSDrive -Name ADROOT -PSProvider ActiveDirectory -Server $domain -Scope Global -root "//RootDSE/"
    $rootdn = "ADROOT:\" + ($domain | get-addomain).DistinguishedName
    (Get-ACL $rootdn).access | select ObjectType,IdentityReference,ActiveDirectoryRights,`
        accessControlType -unique | select `
        @{name='Domain';expression={$domain}}, `
        @{name='DistinguishedName';expression={$rootdn.Replace("ADROOT:\","")}}, `
        IdentityReference, `
        @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaIDGUID.Item($_.objectType)}}}, `
        @{name='ActiveDirectoryRights';expression={if($_.ActiveDirectoryRights -ne "ExtendedRight"){$_.ActiveDirectoryRights}else{$schemaIDGUID.Item($_.objectType)}}}, `
        AccessControlType
     try{Remove-PSDrive -Name ADROOT -Force}catch{}         
} | export-csv $path -notypeinformation
