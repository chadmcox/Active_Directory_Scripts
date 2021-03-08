Get-ADForest | select -ExpandProperty domains -pv domain | foreach{
    Get-ADDomainController -Filter * -Server $domain -pv dc | foreach{
    invoke-command -scriptblock {Get-DnsClientServerAddress | select -ExpandProperty ServerAddresses} -computername $dc.hostname
}} | select PSComputerName, @{name='DNS';expression={$_}}
