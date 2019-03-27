#gathers computers in the computers container of every dommain
get-adforest | select -expandproperty domains -PipelineVariable domain |  foreach{
    get-adcomputer -filter * -Searchbase (get-addomain $domain).ComputersContainer `
    -properties * -server $domain | select `
    @{name='Domain';expression={$domain}},name,SamAccountName,distinguishedname,DNSHostName, `
    IPv4Address,enabled,OperatingSystem,whencreated,whenChanged,PasswordExpired,lastlogondate, `
    uSNChanged,uSNCreated,serviceprincipalname  
}

#----------

