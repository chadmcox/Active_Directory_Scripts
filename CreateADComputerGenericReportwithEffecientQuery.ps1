#this is something thrown together very quick and easy

$hash_domain = @{name='Domain';expression={$domain}}
$hash_parentou = @{name='ParentOU';expression={`
    $($_.distinguishedname -split '(?<![\\]),')[1..$($($_.distinguishedname -split '(?<![\\]),').Count-1)] -join ','}}
foreach($domain in (get-adforest).domains){
    foreach($object_location in (Get-adobject -ldapFilter "(|(objectclass=organizationalunit)(objectclass=container))" -server $domain | where {$_.DistinguishedName -NotLike "*CN=System,DC*"}).DistinguishedName){
        get-adcomputer -Filter {(isCriticalSystemObject -eq $False)} -Properties ipv4address,dnshostname,operatingsystem,enabled -server $domain -searchbase $object_location -SearchScope OneLevel | `
        select $hash_domain,name,dnshostname,ipv4address,enabled,operatingsystem,$hash_parentou | `
        export-csv .\report_generic_ad_computer_info.csv -append -notypeinformation
    }
}
