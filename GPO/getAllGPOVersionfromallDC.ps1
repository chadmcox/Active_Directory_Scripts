get-gpo -all -pv gpo | foreach{
    Get-ADDomainController -filter * -pv dc | foreach {
        Get-GPO -Guid $gpo.id -Server $dc.hostname | select `
            @{N="GPO";E={$gpo.DisplayName}}, `
            @{N="DomainController";E={$dc.hostname}}, `
            @{N="UserVersion";E={$_.User.DSVersion}}, `
            @{N="UserSysVolVersion";E={$_.User.SysvolVersion}}, `
            @{N="ComputerVersion";E={$_.Computer.DSVersion}}, `
            @{N="ComputerSysVolVersion";E={$_.Computer.SysvolVersion}}, `
            CreationTime, ModificationTime
    }
} | export-csv .\gpoexport.csv -NoTypeInformation
