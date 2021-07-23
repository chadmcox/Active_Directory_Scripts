function CollectADSiteLinks{
    Get-ADReplicationSiteLink -Filter * -Properties * -server (get-adforest).name | select name, options, cost, InterSiteTransportProtocol, `
        ReplicationFrequencyInMinutes, ReplicationSchedule, replInterval, `
            @{Name="OperationMasterRoles";Expression={($_.siteList | foreach{Get-ADReplicationSite -Identity $_}).name -join(",")}}
}

CollectADSiteLinks | export-csv ".\$((get-adforest).name)_adsitelinks.csv" -NoTypeInformation
