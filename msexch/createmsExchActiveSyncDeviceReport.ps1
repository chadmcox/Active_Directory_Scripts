get-adforest | select -ExpandProperty domains -pv domain | foreach{
    get-adobject -ldapfilter "(CN=ExchangeActiveSyncDevices*)" -server $domain | foreach{
        get-adobject -ldapfilter "(CN=ExchangeActiveSyncDevices*)" -server $domain -searchbase $_.distinguishedname -Properties * | select distinguishedname, msExch*, objectclass
    }
} | export-csv .\msExchDevice_export.csv -notypeinformation
