function collectADDHCPServers{
    Get-ADObject -SearchBase Get-ADObject -SearchBase "cn=configuration,dc=iammred,dc=net" -Filter "objectclass -eq 'dhcpclass' -AND Name -ne 'dhcproot'" | select name
}

collectADDHCPServers | export-csv ".\$((get-adforest).name)_addhcpservers.csv" -NoTypeInformation
