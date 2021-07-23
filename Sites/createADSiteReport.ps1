function collectADSitesServices{
    $splat_params = @{'filter' = '*';
                    'properties' = '*'}
    $splat_select_params = @{'property' = 'name','Description','AutomaticInterSiteTopologyGenerationEnabled','AutomaticTopologyGenerationEnabled',`
                    'RedundantServerTopologyEnabled','ScheduleHashingEnabled','TopologyCleanupEnabled','TopologyDetectStaleEnabled','TopologyMinimumHopsEnabled',`
                    'UniversalGroupCachingEnabled','UniversalGroupCachingRefreshSite','WindowsServer2000BridgeheadSelectionMethodEnabled',`
                    'WindowsServer2000KCCISTGSelectionBehaviorEnabled','WindowsServer2003KCCBehaviorEnabled',`
                    'WindowsServer2003KCCIgnoreScheduleEnabled','WindowsServer2003KCCSiteLinkBridgingEnabled',`
                    $(@{name='gpLink';expression={if($_.gplink){$true}else{$false}}}),`
                    $(@{name='istgOrphaned';expression={if($_.interSiteTopologyGenerator -like "*0ADEL*"){$true}else{$false}}}),`
                    'whencreated','whenchanged','DistinguishedName'}

    get-adreplicationsite @splat_params | select-object @splat_select_params

}

collectADSitesServices  | export-csv ".\$((get-adforest).name)_adsites.csv" -NoTypeInformation
