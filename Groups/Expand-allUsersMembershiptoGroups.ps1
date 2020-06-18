param($path = "$env:USERPROFILE\documents")
write-host "Export all OU's to search"
$ou_searchbase = get-adforest | select -ExpandProperty domains -PipelineVariable domain | foreach{Get-ADObject -ldapFilter "(|(objectclass=organizationalunit)(objectclass=domainDNS)(objectclass=builtinDomain))" `
        -Properties "msds-approx-immed-subordinates" -server $domain | where {$_."msds-approx-immed-subordinates" -ne 0} | select distinguishedname, @{Name="domain";Expression={$domain}}
        (get-addomain $domain).UsersContainer | Get-ADObject -server $domain | select distinguishedname, @{Name="domain";Expression={$domain}}}


Write-host "Export all AD Users and Groups"
$ou_searchbase | foreach{$domain = $_.domain
    get-adobject -LDAPFilter "(|(&(objectCategory=person)(objectClass=user))(objectClass=group))" -Properties distinguishedname, samaccountname, displayname, company,objectclass,userprincipalname,groupType -Server $_.domain -SearchBase $_.distinguishedname -SearchScope OneLevel
} | select @{n='Domain';e={$domain}},distinguishedname, samaccountname, displayname, company,objectclass,userprincipalname,groupType | export-csv "$path\object_extract.csv" -NoTypeInformation

write-host "Export all group members"
$ou_searchbase | foreach{$domain = $_.domain
     get-adgroup -LDAPFilter "(member=*)" -Server $_.domain -SearchBase $_.distinguishedname -SearchScope OneLevel -Properties member -pv group | select @{name='parent';expression={$group.distinguishedname}}, member
} -PipelineVariable gp | select -ExpandProperty member | select @{name='parent';expression={$gp.parent}}, @{name='member';expression={$_}} | export-csv "$path\group_member_extract.csv" -NoTypeInformation
#write-host "Building Group Lookup Table"
$hash_ad_groups = import-csv "$path\object_extract.csv" | where objectclass -eq "group" | group distinguishedname -AsHashTable -AsString
$hash_ad_group_member = import-csv "$path\group_member_extract.csv" | group member -AsHashTable -AsString

function expand-group{
    param($dn)
    if($dn){
    #write-host "expanding: $dn"
    if(!($hash_already_expanded.ContainsKey($dn))){
        $hash_already_expanded.add($dn,$null)
        $_ | select @{name='Group';expression={$hash_ad_groups["$dn"].samaccountname}},@{name='GroupDomain';expression={$hash_ad_groups["$dn"].domain}}
        $hash_ad_group_member[$dn].parent | foreach{
            
            expand-group -dn $_
            }
    }
    }
}
write-host "starting export"
import-csv "$path\object_extract.csv" -PipelineVariable object | where objectclass -eq "user" | foreach{
    $hash_already_expanded = @{}
    $hash_ad_group_member["$($object.distinguishedname)"].parent | foreach{
       expand-group -dn $_
    }
} | select @{name='Domain';expression={$object.domain}}, @{name='Samaccountname';expression={$object.samaccountname}},`
    @{name='DisplayName';expression={$object.displayname}},@{name='UserPrincipalName';expression={$object.UserPrincipalName}},`
    @{name='Company';expression={$object.company}},GroupDomain,Group | export-csv "$path\expanded_group_membership.csv" -NoTypeInformation
