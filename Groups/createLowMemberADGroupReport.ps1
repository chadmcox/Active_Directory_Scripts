Param($reportpath = "$env:userprofile\Documents")

function retrieveADContainers{
    get-adforest | select -ExpandProperty domains -PipelineVariable domain | foreach{
        Get-ADOrganizationalUnit -filter * -properties "msds-approx-immed-subordinates" -server $domain -PipelineVariable ou | `
            where {$_."msds-approx-immed-subordinates" -ne 0} | select distinguishedname, `
                @{Name="domain";Expression={$domain}}
            get-adobject -ldapfilter "(objectclass=Container)" -SearchScope OneLevel -server $domain | select distinguishedname, `
                @{Name="domain";Expression={$domain}}} | where {$_.distinguishedname -notlike "*OU=Microsoft Exchange Security Groups*"}
}

function getPopulatedADGroups {
    foreach($ou in $searchbase) {
        write-host "Gathering from $($ou.domain) in $($ou.distinguishedname)"
        get-adgroup -LDAPFilter "(&(member=*)(!(IsCriticalSystemObject=TRUE)))" -server $ou.domain -SearchBase $ou.distinguishedname -SearchScope OneLevel `
                 -properties samaccountname,Name,groupscope,groupcategory,admincount,iscriticalsystemobject, `
                    whencreated,whenchanged,objectSid,member | where {$_.member.count -lt 2} | `
                        select @{name='Domain';expression={$ou.domain}}, samaccountname,Name,groupscope, `
                        groupcategory,admincount,iscriticalsystemobject,whencreated,whenchanged,objectSid
    }  
}
function GetADGroupLowMembership{
    $searchbase = retrieveADContainers
    $groups = getPopulatedADGroups
    foreach($grp in $groups){
        write-host "Enumerating Membership on $($grp.domain) \ $($grp.samaccountname)"
        $grp | where {(Get-ADGroupMember -Identity $grp.samaccountname -Recursive -server $grp.domain | measure-object ).count -lt 2}

    }
}

write-host "Gathering Groups with low member number"
GetADGroupLowMembership | export-csv "$reportpath\LowMemberADGroups.csv" -NoTypeInformation
write-host "Results found here: $reportpath\LowMemberADGroups.csv"
