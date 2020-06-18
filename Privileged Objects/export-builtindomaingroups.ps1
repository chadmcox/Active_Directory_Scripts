param($export_file = "$env:userprofile\documents\domain_builtin_group_export.csv")
#retrieve all of the critical and builtin groups
$privileged_groups = get-adforest | select -ExpandProperty domains -PipelineVariable domain | foreach{
    get-adgroup -filter 'admincount -eq 1 -and iscriticalsystemobject -notlike "*"' `
        -server $domain -Properties distinguishedname,SamAccountName,member  | select @{n='Domain';e={$domain}},distinguishedname,SamAccountName,member
    get-adgroup -filter '(admincount -eq 1 -and iscriticalsystemobject -like "*") -or samaccountname -eq "Cert Publishers"' `
        -server $domain -Properties distinguishedname,SamAccountName,member  | select @{n='Domain';e={$domain}},distinguishedname,SamAccountName,member
    get-adgroup -filter 'samaccountname -eq "Schema Admins" -or samaccountname -eq "Group Policy Creator Owners" -or samaccountname -eq "Key Admins" -or samaccountname -eq "Enterprise Key Admins" -or samaccountname -eq "Remote Desktop Users" -or samaccountname -eq "Cryptographic Operators"' `
        -server $domain -Properties distinguishedname,SamAccountName,member  | select @{n='Domain';e={$domain}},distinguishedname,SamAccountName,member
    get-adgroup -filter '(iscriticalsystemobject -like "*") -and (samaccountname -ne "Domain Users") -and (samaccountname -ne "Users") -and (samaccountname -ne "Domain Controllers") -and (samaccountname -ne "Domain Computers")' `
        -server $domain -Properties distinguishedname,SamAccountName,member  | select @{n='Domain';e={$domain}},distinguishedname,SamAccountName,member
} | select domain,distinguishedname,SamAccountName,member -Unique

#Im only using the Get-ADGroupMember because these groups should have low numbers of members.  wont use this for larger enumeration
#places a huge strain on domain controller and only returns a subset of members.
$results = $privileged_groups | foreach{$group = $_; Get-ADGroupMember -Identity $_.distinguishedname -Server $_.domain -Recursive | `
    select @{n='Domain';e={$group.Domain}},@{n='Group';e={$group.samaccountname}}, samaccountname, displayname, userprincipalname, company, objectclass} | `
        export-csv $export_file -NoTypeInformation

write-host "Results found here: $export_file"
