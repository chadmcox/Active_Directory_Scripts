get-adforest | select -ExpandProperty domains -pv domain | foreach {
    Get-ADDomainController -filter * -server $domain -pv dc | foreach{
        write-host "$($DC.hostname)"
        dfsrdiag.exe ReplicationState /member:"$($DC.hostname)"
    }
}
