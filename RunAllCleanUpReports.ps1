
<#PSScriptInfo

.VERSION 0.1

.GUID 0c0e5f1e-bb81-41bf-9650-9748289e663f

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

.TAGS msonline PowerShell

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


.PRIVATEDATA 

#>

#Requires -Module ActiveDirectory

<# 

.DESCRIPTION 
 This script downloads all the clean up scripts and runs them in seperate threads. 

#> 
Param($reportpath = "$env:userprofile\Documents",[switch]$DontUpdateScripts)

$reportpath = "$reportpath\ADCleanUpReports"
If (!($(Try { Test-Path $reportpath } Catch { $true }))){
    new-Item $reportpath -ItemType "directory"  -force
}

cls
Function DownloadNewestScripts{
cd $reportpath

    #AD Computer Clean up Report
    (Invoke-WebRequest "https://raw.githubusercontent.com/chadmcox/ADPoSh/master/CreateADComputerCleanUpReports.ps1").content | `
        out-file .\CreateADComputerCleanUpReports.ps1
    
    #AD User Clean up Report
    (Invoke-WebRequest "https://raw.githubusercontent.com/chadmcox/ADPoSh/master/CreateADUserCleanUpReports.ps1").content | `
        out-file .\CreateADUserCleanUpReports.ps1
   
    #AD Group Clean up Report
    (Invoke-WebRequest "https://raw.githubusercontent.com/chadmcox/ADPoSh/master/CreateADGroupCleanUpReports.ps1").content | `
        out-file .\CreateADGroupCleanUpReports.ps1
    
    #AD OU Clean Up Report
    (Invoke-WebRequest "https://raw.githubusercontent.com/chadmcox/ADPoSh/master/CreateADOUCleanUpReports.ps1").content | `
            out-file .\CreateADOUCleanUpReports.ps1

    #AD GPO Clean Up Report
    (Invoke-WebRequest "https://raw.githubusercontent.com/chadmcox/GPOPoSh/master/CreateADGPOCleanUpReports.ps1").content | `
            out-file .\CreateADGPOCleanUpReports.ps1
    #AD Forest Clean Up Report
    (Invoke-WebRequest "https://raw.githubusercontent.com/chadmcox/ADPoSh/master/CreateADForestCleanUpReports.ps1").content | `
            out-file .\CreateADForestCleanUpReports.ps1
}

if(!($DontUpdateScripts)){
    DownloadNewestScripts
}
$SleepTimer = 1000
$scripts = @()
$scripts = Get-ChildItem $reportpath | where {$_.Extension -eq ".ps1" -and $_.Name -like "CreateAD*"}
get-job | remove-job
if($scripts){
    $scripts | foreach{
        $scripttorun = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe $($_.fullname)"
        start-job -ScriptBlock {Invoke-Expression -command $using:scripttorun} -name $_.name
    }
}else{
    write-host "Scripts are not found in the directory $reportpath"
    write-host "if this computer does not have internet access go to https://github.com/chadmcox/ADPoSh"
    write-host "Download the user, computers, groups and forest scripts that create ad Clean up reports"
}


While (@(Get-Job -State Running).count -gt 0){
    Start-Sleep -Milliseconds $SleepTimer
}


get-job | receive-job | out-file .\results.txt
get-job | Remove-Job -Force

write-host "Report Can be found here $reportpath"





