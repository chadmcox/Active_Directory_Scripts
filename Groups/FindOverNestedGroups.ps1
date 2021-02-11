Param($reportpath = "$env:userprofile\Documents")

function retrieveADContainers{
    get-adforest | select -ExpandProperty domains -PipelineVariable domain | foreach{
        Get-ADOrganizationalUnit -filter * -properties "msds-approx-immed-subordinates" -server $domain -PipelineVariable ou | `
            where {$_."msds-approx-immed-subordinates" -ne 0} | select distinguishedname, `
                @{Name="domain";Expression={$domain}}
            get-adobject -ldapfilter "(objectclass=Container)" -SearchScope OneLevel -server $domain | select distinguishedname, `
                @{Name="domain";Expression={$domain}}}
}


function retrieveGroupMembers{
    foreach($sb in $searchbase){
        get-adgroup -ldapfilter "(memberof=*)" -Properties memberof -searchbase $sb.DistinguishedName -SearchScope OneLevel -server $sb.domain `
            -ResultPageSize 256 -ResultSetSize $null -PipelineVariable grp | select -ExpandProperty memberof | select @{Name="group";Expression={$grp.DistinguishedName}},@{Name="memberof";Expression={$_}}
    }  
}

function expandGroupMembers{
    param($dn)
    if($dn){
        if(!($alreadysearched.containskey($dn))){
            $script:alreadysearched.add($dn,$null)
            $hash_groupmembership[$dn].memberof | foreach {
                if($_){
                    if(!($alreadysearched.containskey($_))){
                    $_
                    expandGroupMembers -dn $_
                    }
                }
            }

        }
    }
}

function retrieveGroupStatus{
    foreach($group in $hash_groupmembership.Keys){
        $script:alreadysearched = @{}
        expandGroupMembers -dn $group | select @{Name="Group";Expression={$group}}, @{Name="Nestedin";Expression={$_}}

    }
}

function buildGroupSummary{
    $expandedgroups | export-csv "$reportpath\expandedGroups.csv" -NoTypeInformation
    $expandedgroups | group group | foreach {
    $prob = $(100 - [math]::Round((($_.count - ($hash_groupmembership["$($_.name)"] | measure-object).count) / $_.count) * 100))
    write-host "$($_.name) $prob"
    $_ | select name, `
    @{Name="DirectCount";Expression={($hash_groupmembership["$($_.name)"] | measure-object).count}},`
    @{Name="ExpandedCount";Expression={$_.count}}, `
    @{name='LikelyProblem';expression={
        if(([convert]::ToInt32($_.count) -gt 500 -and  [convert]::ToInt32($prob) -gt 75) -or [convert]::ToInt32($_.count) -gt 9000){
            "Critical"
        }Elseif([convert]::ToInt32($_.count) -gt 250 -and  [convert]::ToInt32($prob) -gt 50){
            "High"
        }elseif([convert]::ToInt32($_.count) -gt 100 -and  [convert]::ToInt32($prob) -gt 35){
            "Medium"
        }else{
            "Low"
        }}}}

}


$searchbase = retrieveADContainers
$groups = retrieveGroupMembers
$groups | export-csv "$reportpath\directGroups.csv" -NoTypeInformation
$hash_groupmembership = $groups | group group -AsHashTable -AsString
$expandedgroups = retrieveGroupStatus
$results = buildGroupSummary
$results  | export-csv "$reportpath\reportADGroupMemStats.csv" -NoTypeInformation
write-host "-----------------------------------" -ForegroundColor Yellow
write-host "Groups Likely To Cause a Token Issue Due to Over Nesting" -ForegroundColor Yellow
$results | sort ExpandedCount -Descending | where {$_.LikelyProblem -ne "low"} | select -first 25 | Out-Host
write-host "-----------------------------------" -ForegroundColor Yellow
write-host "-----------------------------------" -ForegroundColor Yellow
write-host "Groups Over Nesting" -ForegroundColor Yellow
$results | sort ExpandedCount -Descending | where {$_.ExpandedCount -gt "500"} | select -first 25 | Out-Host
write-host "-----------------------------------" -ForegroundColor Yellow

write-host "results can be found here: $reportpath"
