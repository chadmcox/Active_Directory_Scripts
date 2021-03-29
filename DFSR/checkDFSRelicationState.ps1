get-adforest | select -ExpandProperty domains -pv domain | foreach {
    Get-ADDomainController -filter * -server $domain -pv dc | foreach{
        "--- $($DC.hostname) ----------------------------------"
        write-host "$($DC.hostname)"
        dfsrdiag.exe ReplicationState /member:"$($DC.hostname)" /all
    }
} | out-file "$env:TEMP\sysvolreplicationstate.txt"

write-host "Results found here $env:TEMP\sysvolreplicationstate.txt"
