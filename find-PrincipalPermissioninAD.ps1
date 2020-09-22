cls
cd "$env:userprofile\Documents"

#find group or user, make sure to use the samaccount name.  you can also use an array of principals
#just remove the comment.

$PrincipalNames = @()
$PrincipalNames = "grp-contoso-general-132"
#$PrincipalNames = "Goup1","group2","user1"
$Pattern = "S-\d-(?:\d+-){1,14}\d+"

get-adforest | select -ExpandProperty domains -pv domain | foreach{
    Write-host "GPO Search: $domain"
    Get-GPO -all -domain $domain -pv gpo | select -ExpandProperty DisplayName | foreach{
        Get-GPPermissions -Name $_ -All -DomainName $domain | where {$_.Trustee.name -in $PrincipalNames -or $_.trustee.sidtype -eq "Unknown"} | select `
            @{n='Domain';e={$gpo.DomainName}},@{n='GPO';e={$gpo.DisplayName}},@{n='Trustee';e={$_.Trustee.name}},Permission,Inherited
    }
} | export-csv .\found_group_policies.csv -NoTypeInformation
Write-host "Finished GPO Report found_group_policies.csv"

get-adforest | select -ExpandProperty domains -pv domain | foreach{Write-host "Container Search: $domain"
    Get-ADObject -ldapFilter "(|(objectclass=organizationalunit)(objectclass=domainDNS)(objectclass=builtinDomain)(objectclass=Container))" -Properties nTSecurityDescriptor -server $domain -pv container | `
        select -ExpandProperty nTSecurityDescriptor | select -ExpandProperty Access | `           
            select @{n='Domain';e={$domain}},@{n='Location';e={$container.distinguishedname}},@{n='IdentityReference';e={[string]$_.IdentityReference}},IsInherited,@{n='ActiveDirectoryRights';e={[string]$_.ActiveDirectoryRights}},AccessControlType} | `
                where {($_.IdentityReference -split "\\")[1] -in $PrincipalNames -or $_.IdentityReference -match $Pattern} | export-csv .\found_containers.csv -NoTypeInformation
Write-host "Finished Container Report found_containers.csv"
