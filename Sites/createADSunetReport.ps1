function collectADSubnets{
    Get-ADReplicationSubnet -Filter * -Properties * -server (get-adforest).name | select name, whencreated,whenchanged, site
}

collectADSubnets | export-csv ".\$((get-adforest).name)_adsubnets.csv" -NoTypeInformation
