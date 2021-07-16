#Requires -modules ActiveDirectory
Param($reportpath = "$env:userprofile\Documents")

function getEmptyGroups {
    get-adforest | select -ExpandProperty domains -PipelineVariable domain | foreach {
        write-host "Looking in Domains: $domain"
        get-adgroup -LDAPFilter "(&(!(member=*))(!(IsCriticalSystemObject=TRUE)))" -server $domain `
                 -properties samaccountname,Name,groupscope,groupcategory,admincount,iscriticalsystemobject, `
                    whencreated,whenchanged,objectSid
    } | where {$_.distinguishedname -notlike "*OU=Microsoft Exchange Security Groups*"}

}

write-host "Gathering Empty Groups"
getEmptyGroups | export-csv "$reportpath\EmptyADGroups.csv" -NoTypeInformation
write-host "Results found here: $reportpath\EmptyADGroups.csv"
