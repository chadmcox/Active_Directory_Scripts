function collectExchangeServers{
    Get-ADObject -LDAPFilter "(objectClass=msExchExchangeServer)" –SearchBase (Get-ADRootDSE).configurationNamingContext | Select  name
}

collectExchangeServers | export-csv ".\$((get-adforest).name)_adexchangeservers.csv" -NoTypeInformation
