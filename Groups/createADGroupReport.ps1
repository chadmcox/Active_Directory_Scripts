function collectADContainers{
    get-adforest | select -ExpandProperty domains -PipelineVariable domain | foreach{
        Get-ADOrganizationalUnit -filter * -properties "msds-approx-immed-subordinates" -server $domain -PipelineVariable ou | `
            where {$_."msds-approx-immed-subordinates" -ne 0} | select distinguishedname, `
                @{Name="domain";Expression={$domain}}
            get-adobject -ldapfilter "(objectclass=Container)" -SearchScope OneLevel -server $domain | select distinguishedname, `
                @{Name="domain";Expression={$domain}}}
}
function collectADGroups {
    $properties = "distinguishedname","SID","samaccountname","DisplayName","groupscope","groupcategory","admincount", `
        "iscriticalsystemobject","sidhistory", "whencreated","description","managedby","mail","objectSid", `
        "ProtectedFromAccidentalDeletion", "msDS-ReplValueMetaData", `
        "msExchRecipientTypeDetails","whenchanged","CanonicalName"
    $selectproperties = $properties + @{Name="domain";Expression={$sb.domain}}
    foreach($sb in $searchbases){
        get-adgroup -filter * -Properties $properties -searchbase $sb.DistinguishedName -SearchScope OneLevel -server $sb.domain `
            -ResultPageSize 256 -ResultSetSize $null | select $selectproperties
    }
}

function collectEmptyADGroups{
    foreach($sb in $searchbases){
        get-adgroup -ldapfilter "(!(member=*))" -searchbase $sb.DistinguishedName -SearchScope OneLevel -server $sb.domain `
            -ResultPageSize 256 -ResultSetSize $null
    }
}

function reportADGroup{
    $emptygroups = @{}
    collectEmptyADGroups | foreach{
        $emptygroups.add($_.distinguishedname,$true)
    }
    $MembershipLastChanged = @{name='MembershipLastChanged';expression={[string]($_ | Select-Object -ExpandProperty "msDS-ReplValueMetaData" | foreach {([XML]$_.Replace("`0","")).DS_REPL_VALUE_META_DATA | where { $_.pszAttributeName -eq "member" }}| select -first 1).ftimeLastOriginatingChange | get-date -Format MM/dd/yyyy}}
    $sidhistory = @{N="sidHistory";e={if($_.sidhistory){$True}else{$False}}}
    $OU = @{n='OU';e={($_.CanonicalName -split '/')[0..(($_.CanonicalName -split '/').Count – 2)] -join '/'}}
    $Description = @{n='Description';e={($_).description -replace '[^a-zA-Z0-9\s]', ''}}
    $WhenCreated = @{n='WhenCreated';e={(Get-Date($_.WhenCreated)).ToString('MM/dd/yyyy')}}
    $WhenChanged = @{n='WhenChanged';e={(Get-Date($_.WhenChanged)).ToString('MM/dd/yyyy')}}
    $Member = @{n='containsMembers';e={!($emptygroups.containskey($_.DistinguishedName))}}
    $rid = @{n='rid';e={[int]($_.objectSid.value -split("-"))[-1]}}

    collectADGroups | select domain, "distinguishedname","SID","samaccountname","DisplayName","groupscope","groupcategory","admincount", `
    "iscriticalsystemobject",$sidhistory, $WhenCreated,$Description,"managedby","mail",$rid, "ProtectedFromAccidentalDeletion", `
    $MembershipLastChanged,$Member, $WhenChanged,$OU, extensionAttribute*, msExch*

}
$searchbases = collectADContainers
reportADGroup | export-csv ".\$((get-adforest).name)_adgroups.csv" -NoTypeInformation
