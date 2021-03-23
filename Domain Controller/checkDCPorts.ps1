#https://learn-powershell.net/2011/02/21/querying-udp-ports-with-powershell/
#still working out the udp portion

$DCPorts = @{'TCP' = 135,137,139,445,389,636,3268,3269,88,53; 'UDP' = 135,137,138,445,389,88,53}

function testport{
    param($dc)
    #start with TCP Ports
    $DCPorts['TCP'] | foreach {
        Test-NetConnection -ComputerName $dc -Port $_
    } | select ComputerName, RemotePort, remoteAddress, @{name='TestSucceeded';expression={$_.TcpTestSucceeded}}
    #then UDP Ports
    $DCPorts['UDP'] | foreach {$port = $null; $port = $_
        $dc | select @{name='Computername';expression={$_}}, `
            @{name='RemotePort';expression={$port}}, `
            @{name='remoteAddress';expression={}}, `
            @{name='TestSucceeded';expression={}}  
    }
}

Get-ADForest | select -ExpandProperty domains -pv domain | foreach{
    Get-ADDomainController -filter * -server $domain | foreach{
        testport -dc $_.HostName
    } 
}
