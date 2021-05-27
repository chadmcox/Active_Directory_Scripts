get-adforest | select -expandproperty domains -PipelineVariable domain | `
    foreach {$_;(get-adtrust -filter * -Server $domain).name} | where {try{get-addomain -server $_}catch{$false}} | select -Unique -pv d | foreach{
        get-adgroup -filter '(admincount -eq 1 -and iscriticalsystemobject -like "*" -and samaccountname -ne "Domain Controllers") -or samaccountname -eq "Cert Publishers" -or samaccountname -eq "Group Policy Creator Owners"' -server $d -pv g | `
            Get-ADGroupMember -Server "$d" -Recursive  -pv m
    } | select @{name='Domain';expression={$d}}, @{name='Group';expression={$g.samaccountname}}, `
    @{name='Member';expression={$m.samaccountname}}, @{name='MemberDN';expression={$m.distinguishedname}} | export-csv .\privadmins.csv -NoTypeInformation
