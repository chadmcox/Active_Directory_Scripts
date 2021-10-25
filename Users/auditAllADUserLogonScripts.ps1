get-adforest | select -ExpandProperty domains -pv domain | foreach{
    Get-ADuser -LDAPFilter "(|(scriptpath=*)(homeDirectory=*))" -Properties scriptpath,homeDirectory -Server $domain | `
        select @{Name="Domain";Expression={$domain}},SamAccountName,scriptpath,homeDirectory} | `
            export-csv "$env:USERPROFILE\Documents\mapping.csv" -NoTypeInformation
            
            
get-adforest | select -ExpandProperty domains -pv domain | foreach{
    Get-ADuser -LDAPFilter "(scriptpath=*)" -Properties scriptpath,homeDirectory -Server $domain | foreach{ 
        $file = $null;if($_.scriptpath  -like "\\*"){$file = get-item ($_.scriptpath -split " ")[0] -ErrorAction SilentlyContinue}
            else{$file = get-item "\\$domain\NETLOGON\$(($_.scriptpath -split " ")[0])" -ErrorAction SilentlyContinue}
        $_ | select @{Name="Domain";Expression={$domain}},SamAccountName,scriptpath,@{Name="LastModified";Expression={$file.LastWriteTimeUtc}},
            @{Name="LastAccessed";Expression={$file.LastAccessTimeUtc}}}} | `
                export-csv "$env:USERPROFILE\Documents\scriptDates.csv" -NoTypeInformation
