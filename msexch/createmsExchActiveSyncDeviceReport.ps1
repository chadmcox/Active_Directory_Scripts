get-adforest | select -ExpandProperty domains -pv domain | foreach{
    Get-ADObject -ldapFilter '(objectclass=msExchActiveSyncDevice)' -server $domain | select DistinguishedName, msExch* 
} | export-csv .\msExchDevice_export.csv -notypeinformation
