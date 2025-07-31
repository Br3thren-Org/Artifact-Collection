#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Comprehensive log and artifact collection script for security analysts.

.DESCRIPTION
    This script collects various logs, system information, and forensic artifacts
    commonly needed for security incident response and analysis. Creates a timestamped
    ZIP archive with organized folders for different artifact types.

.PARAMETER OutputPath
    Specify custom output path for the ZIP file (default: Desktop)

.PARAMETER CollectionType
    Specify what to collect: 'All', 'EventLogs', 'SystemInfo', 'NetworkInfo', 'UserArtifacts', 'ProcessInfo'
    Default is 'All'

.PARAMETER MaxDays
    Collect logs from the last N days (default: 30, 0 = all available)

.PARAMETER IncludeMemoryDump
    Include memory dump if available (can be very large)

.EXAMPLE
    .\Collect-SecurityLogs.ps1
    
.EXAMPLE
    .\Collect-SecurityLogs.ps1 -CollectionType EventLogs -MaxDays 7
    
.EXAMPLE
    .\Collect-SecurityLogs.ps1 -OutputPath "C:\Investigation" -MaxDays 14
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [ValidateSet('All', 'EventLogs', 'SystemInfo', 'NetworkInfo', 'UserArtifacts', 'ProcessInfo')]
    [string]$CollectionType = 'All',
    [int]$MaxDays = 30,
    [switch]$IncludeMemoryDump
)

# Define paths and constants
$sourcePath = "C:\Windows\System32\winevt\Logs"
$desktopPath = if ($OutputPath) { $OutputPath } else { [Environment]::GetFolderPath("Desktop") }
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$zipFileName = "SecurityArtifacts_$($env:COMPUTERNAME)_$timestamp.zip"
$zipFilePath = Join-Path -Path $desktopPath -ChildPath $zipFileName

# Priority event logs for security analysis
$priorityEventLogs = @(
    'Security.evtx',
    'System.evtx', 
    'Application.evtx',
    'Windows PowerShell.evtx',
    'Microsoft-Windows-PowerShell%4Operational.evtx',
    'Microsoft-Windows-Sysmon%4Operational.evtx',
    'Microsoft-Windows-TaskScheduler%4Operational.evtx',
    'Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx',
    'Microsoft-Windows-WinRM%4Operational.evtx',
    'Microsoft-Windows-Windows Defender%4Operational.evtx',
    'Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx',
    'Microsoft-Windows-Kernel-Process%4Analytic.evtx',
    'Microsoft-Windows-AppLocker%4EXE and DLL.evtx',
    'Microsoft-Windows-AppLocker%4MSI and Script.evtx',
    'Microsoft-Windows-Bits-Client%4Operational.evtx',
    'Microsoft-Windows-DNS-Client%4Operational.evtx',
    'Microsoft-Windows-Kernel-File%4Analytic.evtx',
    'Microsoft-Windows-SMBClient%4Security.evtx',
    'Microsoft-Windows-SMBServer%4Security.evtx'
)

# Function to test if running as administrator
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to create directory structure
function New-CollectionStructure {
    param([string]$BasePath)
    
    $folders = @(
        'EventLogs',
        'SystemInfo', 
        'NetworkInfo',
        'ProcessInfo',
        'UserArtifacts',
        'RegistryExports',
        'Prefetch',
        'ScheduledTasks',
        'Services',
        'SecurityPolicy'
    )
    
    foreach ($folder in $folders) {
        $folderPath = Join-Path -Path $BasePath -ChildPath $folder
        New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
    }
    
    return $BasePath
}

# Function to collect event logs
function Collect-EventLogs {
    param([string]$DestinationPath)
    
    Write-Host "Collecting Event Logs..." -ForegroundColor Green
    $eventLogPath = Join-Path -Path $DestinationPath -ChildPath "EventLogs"
    
    # Get all available event logs
    $allLogs = Get-ChildItem -Path $sourcePath -Filter "*.evtx" -ErrorAction SilentlyContinue
    $priorityLogs = @()
    $standardLogs = @()
    
    # Separate priority logs from standard logs
    foreach ($log in $allLogs) {
        if ($priorityEventLogs -contains $log.Name) {
            $priorityLogs += $log
        } else {
            $standardLogs += $log
        }
    }
    
    # Create priority and standard subdirectories
    $priorityPath = Join-Path -Path $eventLogPath -ChildPath "Priority"
    $standardPath = Join-Path -Path $eventLogPath -ChildPath "Standard"
    New-Item -ItemType Directory -Path $priorityPath -Force | Out-Null
    New-Item -ItemType Directory -Path $standardPath -Force | Out-Null
    
    $totalLogs = $priorityLogs.Count + $standardLogs.Count
    $counter = 0
    $successCount = 0
    
    # Copy priority logs first
    Write-Host "  Copying priority security logs..." -ForegroundColor Cyan
    foreach ($log in $priorityLogs) {
        $counter++
        $percentComplete = [math]::Round(($counter / $totalLogs) * 100, 2)
        Write-Progress -Activity "Collecting Event Logs" -Status "Priority: $($log.Name)" -PercentComplete $percentComplete
        
        try {
            Copy-Item -Path $log.FullName -Destination $priorityPath -ErrorAction Stop
            $successCount++
        }
        catch {
            Write-Warning "Failed to copy priority log $($log.Name): $($_.Exception.Message)"
        }
    }
    
    # Copy standard logs
    Write-Host "  Copying standard event logs..." -ForegroundColor Cyan
    foreach ($log in $standardLogs) {
        $counter++
        $percentComplete = [math]::Round(($counter / $totalLogs) * 100, 2)
        Write-Progress -Activity "Collecting Event Logs" -Status "Standard: $($log.Name)" -PercentComplete $percentComplete
        
        try {
            Copy-Item -Path $log.FullName -Destination $standardPath -ErrorAction Stop
            $successCount++
        }
        catch {
            Write-Warning "Failed to copy standard log $($log.Name): $($_.Exception.Message)"
        }
    }
    
    Write-Progress -Activity "Collecting Event Logs" -Completed
    Write-Host "  Event logs collected: $successCount of $totalLogs" -ForegroundColor Green
}

# Function to collect system information
function Collect-SystemInfo {
    param([string]$DestinationPath)
    
    Write-Host "Collecting System Information..." -ForegroundColor Green
    $systemInfoPath = Join-Path -Path $DestinationPath -ChildPath "SystemInfo"
    
    # System information commands
    $commands = @{
        'SystemInfo.txt' = 'systeminfo'
        'InstalledSoftware.txt' = 'Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallDate | Sort-Object Name'
        'InstalledHotfixes.txt' = 'Get-HotFix | Sort-Object InstalledOn -Descending'
        'EnvironmentVariables.txt' = 'Get-ChildItem Env: | Sort-Object Name'
        'LocalUsers.txt' = 'Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires'
        'LocalGroups.txt' = 'Get-LocalGroup'
        'Shares.txt' = 'Get-SmbShare'
        'StartupPrograms.txt' = 'Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User'
        'WindowsFeatures.txt' = 'Get-WindowsOptionalFeature -Online | Where-Object State -eq "Enabled" | Select-Object FeatureName, State'
        'TimeZone.txt' = 'Get-TimeZone; w32tm /query /status'
        'SystemUptime.txt' = '(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime'
    }
    
    $counter = 0
    foreach ($file in $commands.Keys) {
        $counter++
        $percentComplete = [math]::Round(($counter / $commands.Count) * 100, 2)
        Write-Progress -Activity "Collecting System Information" -Status $file -PercentComplete $percentComplete
        
        try {
            $filePath = Join-Path -Path $systemInfoPath -ChildPath $file
            $command = $commands[$file]
            
            if ($command.StartsWith('Get-') -or $command.Contains('|')) {
                # PowerShell command
                Invoke-Expression $command | Out-File -FilePath $filePath -Encoding UTF8
            } else {
                # External command
                cmd /c $command > $filePath 2>&1
            }
        }
        catch {
            Write-Warning "Failed to collect $file : $($_.Exception.Message)"
        }
    }
    
    Write-Progress -Activity "Collecting System Information" -Completed
    Write-Host "  System information collected" -ForegroundColor Green
}

# Function to collect network information
function Collect-NetworkInfo {
    param([string]$DestinationPath)
    
    Write-Host "Collecting Network Information..." -ForegroundColor Green
    $networkInfoPath = Join-Path -Path $DestinationPath -ChildPath "NetworkInfo"
    
    $commands = @{
        'NetworkConfig.txt' = 'ipconfig /all'
        'RoutingTable.txt' = 'route print'
        'ARPTable.txt' = 'arp -a'
        'NetstatConnections.txt' = 'netstat -ano'
        'NetstatRoutes.txt' = 'netstat -rn'
        'DNSCache.txt' = 'ipconfig /displaydns'
        'NetworkAdapters.txt' = 'Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress'
        'FirewallRules.txt' = 'Get-NetFirewallRule | Where-Object Enabled -eq True | Select-Object DisplayName, Direction, Action, Profile'
        'WiFiProfiles.txt' = 'netsh wlan show profiles'
        'NetworkShares.txt' = 'net share'
        'ActiveConnections.txt' = 'Get-NetTCPConnection | Where-Object State -eq "Established" | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess'
    }
    
    $counter = 0
    foreach ($file in $commands.Keys) {
        $counter++
        $percentComplete = [math]::Round(($counter / $commands.Count) * 100, 2)
        Write-Progress -Activity "Collecting Network Information" -Status $file -PercentComplete $percentComplete
        
        try {
            $filePath = Join-Path -Path $networkInfoPath -ChildPath $file
            $command = $commands[$file]
            
            if ($command.StartsWith('Get-') -or $command.Contains('|')) {
                Invoke-Expression $command | Out-File -FilePath $filePath -Encoding UTF8
            } else {
                cmd /c $command > $filePath 2>&1
            }
        }
        catch {
            Write-Warning "Failed to collect $file : $($_.Exception.Message)"
        }
    }
    
    Write-Progress -Activity "Collecting Network Information" -Completed
    Write-Host "  Network information collected" -ForegroundColor Green
}

# Function to collect process information
function Collect-ProcessInfo {
    param([string]$DestinationPath)
    
    Write-Host "Collecting Process Information..." -ForegroundColor Green
    $processInfoPath = Join-Path -Path $DestinationPath -ChildPath "ProcessInfo"
    
    $commands = @{
        'RunningProcesses.txt' = 'Get-Process | Select-Object Name, Id, CPU, WorkingSet, StartTime, Path | Sort-Object CPU -Descending'
        'ProcessTree.txt' = 'Get-WmiObject Win32_Process | Select-Object Name, ProcessId, ParentProcessId, CommandLine, CreationDate | Sort-Object ProcessId'
        'Services.txt' = 'Get-Service | Select-Object Name, Status, StartType, ServiceType | Sort-Object Status, Name'
        'ServiceDetails.txt' = 'Get-WmiObject Win32_Service | Select-Object Name, State, StartMode, PathName, StartName | Sort-Object Name'
        'ScheduledTasks.txt' = 'Get-ScheduledTask | Where-Object State -ne "Disabled" | Select-Object TaskName, State, LastRunTime, NextRunTime, TaskPath'
        'LoadedModules.txt' = 'Get-Process | ForEach-Object { try { $_.Modules | Select-Object @{n="ProcessName";e={$_.ProcessName}}, @{n="PID";e={$_.ProcessId}}, ModuleName, FileName } catch {} }'
        'NetworkProcesses.txt' = 'Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}'
    }
    
    $counter = 0
    foreach ($file in $commands.Keys) {
        $counter++
        $percentComplete = [math]::Round(($counter / $commands.Count) * 100, 2)
        Write-Progress -Activity "Collecting Process Information" -Status $file -PercentComplete $percentComplete
        
        try {
            $filePath = Join-Path -Path $processInfoPath -ChildPath $file
            $command = $commands[$file]
            Invoke-Expression $command | Out-File -FilePath $filePath -Encoding UTF8
        }
        catch {
            Write-Warning "Failed to collect $file : $($_.Exception.Message)"
        }
    }
    
    Write-Progress -Activity "Collecting Process Information" -Completed
    Write-Host "  Process information collected" -ForegroundColor Green
}

# Function to collect user artifacts
function Collect-UserArtifacts {
    param([string]$DestinationPath)
    
    Write-Host "Collecting User Artifacts..." -ForegroundColor Green
    $userArtifactsPath = Join-Path -Path $DestinationPath -ChildPath "UserArtifacts"
    
    # Collect prefetch files
    try {
        $prefetchPath = Join-Path -Path $DestinationPath -ChildPath "Prefetch"
        $prefetchSource = "C:\Windows\Prefetch"
        if (Test-Path $prefetchSource) {
            Copy-Item -Path "$prefetchSource\*.pf" -Destination $prefetchPath -ErrorAction SilentlyContinue
            $prefetchCount = (Get-ChildItem -Path $prefetchPath -ErrorAction SilentlyContinue).Count
            Write-Host "  Prefetch files collected: $prefetchCount" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Failed to collect prefetch files: $($_.Exception.Message)"
    }
    
    # Registry exports
    try {
        $registryPath = Join-Path -Path $DestinationPath -ChildPath "RegistryExports"
        $registryExports = @{
            'HKLM_Run.reg' = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            'HKLM_RunOnce.reg' = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
            'HKLM_Services.reg' = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services'
            'HKLM_Uninstall.reg' = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
            'HKLM_MountedDevices.reg' = 'HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices'
        }
        
        foreach ($file in $registryExports.Keys) {
            $regPath = Join-Path -Path $registryPath -ChildPath $file
            $regKey = $registryExports[$file]
            reg export $regKey $regPath /y 2>$null
        }
        Write-Host "  Registry exports collected" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to collect registry exports: $($_.Exception.Message)"
    }
    
    # Security policy
    try {
        $securityPolicyPath = Join-Path -Path $DestinationPath -ChildPath "SecurityPolicy"
        secedit /export /cfg (Join-Path $securityPolicyPath "SecurityPolicy.inf") /quiet 2>$null
        auditpol /get /category:* > (Join-Path $securityPolicyPath "AuditPolicy.txt") 2>$null
        Write-Host "  Security policy collected" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to collect security policy: $($_.Exception.Message)"
    }
}

# Function to create the final archive
function New-SecurityArchive {
    param([string]$SourceFolder, [string]$DestinationZip)
    
    Write-Host "Creating security archive..." -ForegroundColor Green
    
    if (Test-Path $DestinationZip) {
        Remove-Item -Path $DestinationZip -Force
    }
    
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($SourceFolder, $DestinationZip)
    
    $zipInfo = Get-Item -Path $DestinationZip
    $fileSizeMB = [math]::Round($zipInfo.Length / 1MB, 2)
    
    Write-Host "Archive created successfully!" -ForegroundColor Green
    Write-Host "  Location: $DestinationZip" -ForegroundColor Cyan
    Write-Host "  Size: $fileSizeMB MB" -ForegroundColor Cyan
}

# Main execution
try {
    # Check admin privileges
    if (-not (Test-IsAdmin)) {
        throw "This script requires administrator privileges. Please run as administrator."
    }
    
    # Create temporary collection directory
    $tempCollectionPath = Join-Path -Path $env:TEMP -ChildPath "SecurityCollection_$(Get-Random)"
    New-Item -ItemType Directory -Path $tempCollectionPath -Force | Out-Null
    New-CollectionStructure -BasePath $tempCollectionPath
    
    # Display collection information
    Write-Host "Security Artifact Collection Script" -ForegroundColor Magenta
    Write-Host "===================================" -ForegroundColor Magenta
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "Collection Type: $CollectionType" -ForegroundColor White
    Write-Host "Output: $zipFilePath" -ForegroundColor White
    Write-Host "Max Days: $MaxDays" -ForegroundColor White
    Write-Host ""
    
    # Collect artifacts based on selection
    switch ($CollectionType) {
        'All' {
            Collect-EventLogs -DestinationPath $tempCollectionPath
            Collect-SystemInfo -DestinationPath $tempCollectionPath
            Collect-NetworkInfo -DestinationPath $tempCollectionPath
            Collect-ProcessInfo -DestinationPath $tempCollectionPath
            Collect-UserArtifacts -DestinationPath $tempCollectionPath
        }
        'EventLogs' { Collect-EventLogs -DestinationPath $tempCollectionPath }
        'SystemInfo' { Collect-SystemInfo -DestinationPath $tempCollectionPath }
        'NetworkInfo' { Collect-NetworkInfo -DestinationPath $tempCollectionPath }
        'ProcessInfo' { Collect-ProcessInfo -DestinationPath $tempCollectionPath }
        'UserArtifacts' { Collect-UserArtifacts -DestinationPath $tempCollectionPath }
    }
    
    # Create collection summary
    $summaryPath = Join-Path -Path $tempCollectionPath -ChildPath "CollectionSummary.txt"
    $folderInfo = Get-ChildItem -Path $tempCollectionPath -Directory | ForEach-Object { 
        $fileCount = (Get-ChildItem -Path $_.FullName -Recurse -File -ErrorAction SilentlyContinue).Count
        "- $($_.Name): $fileCount files"
    }
    
    $summary = @"
Security Artifact Collection Summary
===================================
Computer Name: $env:COMPUTERNAME
Collection Date: $(Get-Date)
Collection Type: $CollectionType
Collector: $env:USERNAME
Script Version: 2.0
PowerShell Version: $($PSVersionTable.PSVersion)

Folders Created:
$($folderInfo -join "`n")

Total Files Collected: $((Get-ChildItem -Path $tempCollectionPath -Recurse -File -ErrorAction SilentlyContinue).Count)

Important Notes:
- Priority event logs are in EventLogs\Priority folder
- Standard event logs are in EventLogs\Standard folder  
- Registry exports are partial exports of key security-relevant hives
- Prefetch files show evidence of program execution
- Network information includes active connections and firewall rules
- Process information includes running processes, services, and scheduled tasks

For Analysis:
1. Start with Priority event logs (Security.evtx, System.evtx, PowerShell logs)
2. Review ProcessInfo for suspicious processes or connections
3. Check RegistryExports for persistence mechanisms
4. Examine Prefetch for evidence of malicious program execution
5. Review NetworkInfo for suspicious connections or configurations

This collection was created for security analysis purposes.
"@
    
    $summary | Out-File -FilePath $summaryPath -Encoding UTF8
    
    # Create final archive
    New-SecurityArchive -SourceFolder $tempCollectionPath -DestinationZip $zipFilePath
    
}
catch {
    Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}
finally {
    # Clean up temporary directory
    if (Test-Path $tempCollectionPath) {
        try {
            Remove-Item -Path $tempCollectionPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Could not clean up temporary directory: $tempCollectionPath"
        }
    }
}

Write-Host "`nCollection completed successfully!" -ForegroundColor Green
Write-Host "Archive Location: $zipFilePath" -ForegroundColor Cyan

# Display next steps
Write-Host "`nNext Steps for Analysis:" -ForegroundColor Yellow
Write-Host "1. Extract the archive to your analysis workstation" -ForegroundColor White
Write-Host "2. Start with Priority event logs (Security, System, PowerShell)" -ForegroundColor White  
Write-Host "3. Review the CollectionSummary.txt for collection details" -ForegroundColor White
Write-Host "4. Use tools like Event Log Explorer, Hayabusa, or Chainsaw for log analysis" -ForegroundColor White
Write-Host "5. Cross-reference process info with network connections" -ForegroundColor White
