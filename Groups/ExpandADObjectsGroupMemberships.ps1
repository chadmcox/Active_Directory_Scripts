function expandgpmem{
    [cmdletbinding()]
    param($dn)
    write-information "Expanding $dn" 
    if(!($script:alreadyexplored.containskey($dn))){
        write-information "Not Searched Yet: $dn" 
        if($hash_group_membership.containskey($dn)){
            write-information "Is a member: $dn" 
            $script:alreadyexplored.add($dn,$null)
            foreach($mem in $hash_group_membership[$dn].parent){
                $mem | select @{name='object';expression={$object}}, `
                @{name='memberof';expression={$mem}}
                if(!($script:alreadyexplored.ContainsKey($mem))){
                    expandgpmem -dn $mem
                }
            }
        }
    }

}


cd "$env:userprofile\Documents"
get-adforest | select -ExpandProperty domains -pv domain | foreach{
    write-host "Dumping Groups Members from $domain"
    get-adgroup -LDAPFilter "(|(member=*)(memberof=*))" -property member -server $domain -pv group -ErrorAction SilentlyContinue | select -ExpandProperty member -pv member | select `
        @{name='child';expression={$member}}, `
        @{name='parent';expression={$group.distinguishedname}}
} | export-csv .\gpmem.tmp -NoTypeInformation

Write-Host "Creating Hash Table for lookup"
$hash_group_membership = import-csv .\gpmem.tmp | group child -AsHashTable -AsString

remove-item .\expanded_membership.csv -force -ErrorAction SilentlyContinue

foreach($object in ($hash_group_membership).keys){
    write-host "Enumerating: $object"
    $script:alreadyexplored = @{}
    expandgpmem -dn $object | export-csv .\expanded_membership.csv -Append -NoTypeInformation
}

import-csv .\expanded_membership.csv | group object | select name, count | export-csv ".\adObjectMemberofCount.csv" -NoTypeInformation



