#https://support.microsoft.com/en-us/topic/script-to-help-in-monitoring-event-ids-related-to-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-26434ae1-f9b9-90a0-cd0a-cfae9c5b2494
#https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e#bkmk_detectingnon_compliant

get-adforest | select -expandproperty domains -pv domain | foreach{
  Get-ADDomainController -Filter * -Server $domain -pv dc | foreach{
        write-host "Checking $($dc.hostname)"
        Get-WinEvent -FilterHashtable @{logname='system'; id=5827; StartTime=(Get-Date).date} -ComputerName $($dc.hostname) -pv ev | select  `
            @{name='DC';expression={$ev.MachineName}}, `
            @{name='Name';expression={$ev.Properties[0].value}}, `
            @{name='DomainName';expression={$ev.Properties[1].value}}, `
            @{name='AccountType';expression={$ev.Properties[2].value}}, `
            @{name='MachineOS';expression={$ev.Properties[3].value}}, `
            @{name='MachineOSBuild';expression={$ev.Properties[4].value}}
   } } | export-csv .\results.csv
