#Requires –Modules ActiveDirectory
#Requires -version 4.0

<#-----------------------------------------------------------------------------
Example code for

Chad Cox, Microsoft Premier Field Engineer
https://blogs.technet.microsoft.com/chadcox/

LEGAL DISCLAIMER
This Sample Code is provided for the purpose of illustration only and is not
intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
nonexclusive, royalty-free right to use and modify the Sample Code and to
reproduce and distribute the object code form of the Sample Code, provided
that You agree: (i) to not use Our name, logo, or trademarks to market Your
software product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneys’ fees, that arise or result
from the use or distribution of the Sample Code.
-----------------------------------------------------------------------------#>



import-module activedirectory
set-variable -name "user" -value $(read-host "SamAccount Name?") 
(get-adforest).domains | foreach-object {$domain=$_ ;Get-ADDomainController -filter * -server $_ | select name,hostname,site,OperationMasterRoles | foreach-object {
    $dc = $_.name;$dcsite=$_.site;$pdc=if($_.OperationMasterRoles -like "*PDCEmulator*"){$True}
    try{get-aduser $user -server $_.hostname -properties badPwdCount,badPasswordTime,lockedout,PwdLastSet,LastLogonTimeStamp | select `
    @{name='Domain';expression={$Domain}}, `
    @{name='DC Name';expression={$DC}}, `
    @{name='DC Site';expression={$dcsite}}, `
    @{name='PDC';expression={$pdc}}, `
    @{name='User';expression={$_.samaccountname}}, `
    @{name='User State';expression={$_.lockedout}}, `
    @{name='Bad Pwd Count';expression={$_.badPwdCount}}, `
    @{name='Last Bad Pwd';expression={([datetime]::FromFileTime($_.badPasswordTime)).ToString('u')}}, `
    @{Name="Pwd Last Sets";Expression={([datetime]::FromFileTime($_.PwdLastSet)).ToString('u')}}, `
    @{Name="Pwd Age in Days";Expression={if($_.PwdLastSet -ne 0){(new-TimeSpan([datetime]::FromFileTimeUTC($_.PwdLastSet)) $(Get-Date)).days}else{"NA"}}}, `
    @{Name="Last Logon";Expression={([datetime]::FromFileTime($_.LastLogonTimeStamp)).ToString('u')}}}catch{}}} | Out-GridView -title "LockoutStatus"


