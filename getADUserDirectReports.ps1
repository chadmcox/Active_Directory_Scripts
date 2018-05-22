
#Requires -Module activedirectory
<#PSScriptInfo

.VERSION 0.1

.GUID 99537558-e989-463e-ba22-b955289e364c

.AUTHOR Chad.Cox@microsoft.com
    https://blogs.technet.microsoft.com/chadcox/
    https://github.com/chadmcox

.COMPANYNAME 

.COPYRIGHT This Sample Code is provided for the purpose of illustration only and is not
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
against any claims or lawsuits, including attorneys` fees, that arise or result
from the use or distribution of the Sample Code..

.TAGS get-aduser get-adobject get-adgroups

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES



.DESCRIPTION 
 this will populate all of the directs for an individual. 

#> 
param($samaccountname = $(read-host -Prompt "Enter samaccountname"))

function getADUserDirectReports{
    param($dn,$place,$previous)
    $place = $place + 1
    $sam = get-aduser $dn -server "$((get-addomain).DNSRoot):3268" -Properties displayname
    $sam | select `
        @{name='Level';expression={$place}}, `
        @{name='ReportsSAM';expression={$_.samaccountname}}, `
        @{name='ReportsDisplayname';expression={$_.displayname}}, `
        @{name='ReportsTo';expression={$previous.displayname}} | out-host

    #write-host "$place $($sam.samaccountname) - $($sam.displayname)"
    #does this DN have results
    $results = foreach($domain in (get-adforest).domains){try{get-aduser $dn -Properties directreports `
         -server $domain -ErrorAction SilentlyContinue | select -ExpandProperty directreports}catch{}}
    if($results){
          $results | foreach{
                $directsupn = $_
                
                getADUserDirectReports -dn $directsupn -place $place -previous $sam

        }
    }
}

cls

#$samaccountname = read-host -Prompt "Enter samaccountname"
foreach($domain in (get-adforest).domains){
    try{get-aduser $samaccountname -Properties directreports -server $domain `
        -ErrorAction SilentlyContinue | select -ExpandProperty directreports | `
            foreach{
        $upn = $_
        getADUserDirectReports -dn $upn 

    }}catch{}
}
