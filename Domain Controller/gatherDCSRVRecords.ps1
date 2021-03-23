$dc = Get-ADForest | select -ExpandProperty domains -pv domain | foreach{(Get-ADDomainController -filter * -server $domain).hostname | foreach{"$($_)."}}
$dc += Get-ADForest | select -ExpandProperty domains -pv domain | foreach{(Get-ADDomainController -filter * -server $domain).IPv4Address}

Get-DnsServerZone | where IsReverseLookupZone -eq $false -pv zone | foreach{
    Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -RRType Srv |  `
        select hostname,RecordType, @{name='IPv4Address';expression={$_.RecordData.IPv4Address}}, `
         @{name='NameServer';expression={$_.RecordData.NameServer}}, @{name='DomainName';expression={$_.RecordData.DomainName}} 
} | export-csv .\report_dc_srv_records.csv -NoTypeInformation

Get-DnsServerZone | where IsReverseLookupZone -eq $false -pv zone | foreach{
    Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -RRType Srv | where {$_.RecordData.IPv4Address -notin $dc -and $_.RecordData.NameServer -notin $dc -and $_.RecordData.DomainName -notin $dc} | `
        select hostname,RecordType, @{name='IPv4Address';expression={$_.RecordData.IPv4Address}}, `
         @{name='NameServer';expression={$_.RecordData.NameServer}}, @{name='DomainName';expression={$_.RecordData.DomainName}} 
} | export-csv .\report_dc_invalid_srv_records.csv -NoTypeInformation
