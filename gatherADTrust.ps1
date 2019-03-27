<#
using Get-ADReplicationAttributeMetadata to get last time anything has replicated with the trust.
#>

get-adforest | select -expandproperty domains -PipelineVariable domain | foreach{
get-adtrust -filter * -Properties * -server $domain -PipelineVariable trust | select `
    @{name='Domain';expression={$domain}},name,securityIdentifier,Created, `
    Direction,trustType,DisallowTransivity,SelectiveAuthentication,TGTDelegation, `
    UsesAESKeys,UsesRC4Encryption,whenCreated,whenchanged,`
    @{name='trustAuthOutgoing';expression={(Get-ADReplicationAttributeMetadata `
        -filter {attributename -eq "trustAuthOutgoing"} -Server (get-addomain $domain).PDCEmulator `
        -Object ($trust).DistinguishedName).LastOriginatingChangeTime}}, `
    @{name='trustAuthIncoming';expression={(Get-ADReplicationAttributeMetadata `
        -filter {attributename -eq "trustAuthIncoming"} -Server (get-addomain $domain).PDCEmulator `
        -Object ($trust).DistinguishedName).LastOriginatingChangeTime}}}
