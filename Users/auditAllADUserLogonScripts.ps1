get-adforest | select -ExpandProperty domains -pv domain | foreach{
    Get-ADuser -LDAPFilter "(|(scriptpath=*)(homeDirectory=*))" -Properties scriptpath,homeDirectory -Server $domain | `
        select @{Name="Domain";Expression={$domain}},SamAccountName,scriptpath,homeDirectory} | `
            export-csv "$env:USERPROFILE\Documents\mapping.csv" -NoTypeInformation
