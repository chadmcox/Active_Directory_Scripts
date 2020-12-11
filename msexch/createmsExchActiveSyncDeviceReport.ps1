get-adforest | select -ExpandProperty domains -pv domain | foreach{
    get-adobject -filter {objectclass -eq "msExchActiveSyncDevices"} -server $domain | foreach{
        get-adobject -filter * -server $domain -searchbase $_.distinguishedname -Properties * | select distinguishedname, msExch*, objectclass
    }
} | export-csv .\msExchDevice_export.csv -notypeinformation -Encoding Unicode
