# Artifact Collection

## Overview

Artifact Collection is a comprehensive PowerShell tool designed for security analysts, incident responders, and forensic investigators. It systematically collects critical logs, system information, and forensic artifacts from Windows systems to support security analysis and incident response activities.

## Key Features

- **Comprehensive Collection**: Gathers event logs, system information, network data, process details, and user artifacts
- **Prioritized Event Logs**: Separates high-priority security logs from standard logs for efficient analysis
- **Organized Output Structure**: Creates structured ZIP archives with logical folder organization
- **Flexible Collection Types**: Allows selective collection of specific artifact categories
- **Progress Tracking**: Provides real-time progress indicators during collection
- **Error Resilience**: Continues collection even if individual files are locked or inaccessible
- **Timestamped Archives**: Prevents overwrites with automatic timestamp inclusion
- **Analysis Guidance**: Includes collection summary with analysis recommendations

## System Requirements

- **Operating System**: Windows 10/11, Windows Server 2016/2019/2022
- **PowerShell**: Version 5.1 or higher
- **Privileges**: Administrator privileges required
- **Disk Space**: Minimum 500MB free space (more recommended for large environments)
- **.NET Framework**: 4.5 or higher (for ZIP compression)

## Installation

1. Download the Artifact Collection script (`Collect-SecurityLogs.ps1`)
2. Place the script in a directory accessible to administrators
3. Ensure PowerShell execution policy allows script execution:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## Usage

### Basic Usage

Run Artifact Collection with administrator privileges to collect all available artifacts:

```powershell
.\Collect-SecurityLogs.ps1
```

### Advanced Usage

#### Collect Specific Categories
```powershell
# Collect only event logs
.\Collect-SecurityLogs.ps1 -CollectionType EventLogs

# Collect only system information
.\Collect-SecurityLogs.ps1 -CollectionType SystemInfo

# Collect only network information
.\Collect-SecurityLogs.ps1 -CollectionType NetworkInfo
```

#### Custom Output Location
```powershell
# Specify custom output directory
.\Collect-SecurityLogs.ps1 -OutputPath "C:\Investigation\Case-2024-001"
```

#### Time-Bounded Collection
```powershell
# Collect artifacts from last 7 days
.\Collect-SecurityLogs.ps1 -MaxDays 7

# Collect all available artifacts (no time limit)
.\Collect-SecurityLogs.ps1 -MaxDays 0
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `OutputPath` | String | Desktop | Custom output directory for ZIP archive |
| `CollectionType` | String | All | Specific collection type (All, EventLogs, SystemInfo, NetworkInfo, UserArtifacts, ProcessInfo) |
| `MaxDays` | Integer | 30 | Number of days to collect logs (0 = no limit) |
| `IncludeMemoryDump` | Switch | False | Include memory dump files if available |

## Output Structure

The script creates a timestamped ZIP archive with the following structure:

```
SecurityArtifacts_COMPUTERNAME_YYYYMMDD_HHMMSS.zip
├── CollectionSummary.txt          # Collection metadata and analysis guidance
├── EventLogs/
│   ├── Priority/                  # Critical security event logs
│   │   ├── Security.evtx
│   │   ├── System.evtx
│   │   ├── Application.evtx
│   │   ├── Windows PowerShell.evtx
│   │   └── [Other priority logs]
│   └── Standard/                  # All other event logs
├── SystemInfo/
│   ├── SystemInfo.txt             # Detailed system information
│   ├── InstalledSoftware.txt      # Installed applications
│   ├── LocalUsers.txt             # Local user accounts
│   ├── StartupPrograms.txt        # Startup applications
│   └── [Other system data]
├── NetworkInfo/
│   ├── NetworkConfig.txt          # Network configuration
│   ├── NetstatConnections.txt     # Active network connections
│   ├── FirewallRules.txt          # Windows Firewall rules
│   └── [Other network data]
├── ProcessInfo/
│   ├── RunningProcesses.txt       # Currently running processes
│   ├── Services.txt               # Windows services
│   ├── ScheduledTasks.txt         # Scheduled tasks
│   └── [Other process data]
├── UserArtifacts/                 # User activity evidence
├── RegistryExports/               # Critical registry hive exports
│   ├── HKLM_Run.reg
│   ├── HKLM_Services.reg
│   └── [Other registry exports]
├── Prefetch/                      # Program execution evidence
└── SecurityPolicy/                # Security policy configuration
```

## Priority Event Logs

The script prioritizes collection of these critical security logs:

**Authentication and Access**
- Security.evtx (Windows Security log)
- Microsoft-Windows-TerminalServices-LocalSessionManager
- Microsoft-Windows-TerminalServices-RemoteConnectionManager

**System Activity**
- System.evtx (Windows System log)
- Application.evtx (Windows Application log)

**PowerShell Activity**
- Windows PowerShell.evtx
- Microsoft-Windows-PowerShell/Operational

**Security Tools**
- Microsoft-Windows-Sysmon/Operational (if available)
- Microsoft-Windows-Windows Defender/Operational
- Microsoft-Windows-Windows Firewall With Advanced Security

**Network and File Activity**
- Microsoft-Windows-DNS-Client/Operational
- Microsoft-Windows-SMBClient/Security
- Microsoft-Windows-SMBServer/Security

## Security Considerations

### Data Sensitivity
- Collected artifacts may contain sensitive information including:
  - User credentials and authentication data
  - Network configuration details
  - System configuration information
  - Process and service details

### Access Controls
- Artifact Collection requires administrator privileges to access system logs and files
- Some files may be locked by active processes (handled gracefully)
- Certain logs may not be available depending on system configuration

### Data Handling
- Store collected archives in secure locations
- Follow organizational data handling policies
- Consider encryption for archives containing sensitive data
- Maintain chain of custody documentation for forensic investigations

## Troubleshooting

### Common Issues

**Artifact Collection Won't Run**
- Verify administrator privileges
- Check PowerShell execution policy
- Ensure .NET Framework 4.5+ is installed

**Some Files Not Collected**
- Normal behavior for locked files
- Check Windows Event Viewer for access denied errors
- Verify source paths exist on target system

**Large Archive Sizes**
- Use `-MaxDays` parameter to limit collection timeframe
- Consider selective collection types for specific investigations
- Monitor available disk space during collection

**Memory or Performance Issues**
- Run during low-activity periods
- Consider collecting in phases using different CollectionType values
- Increase virtual memory if needed

### Log Analysis

Review the `CollectionSummary.txt` file first for:
- Collection statistics
- Failed collection attempts
- Recommended analysis starting points

## Analysis Workflow

### Initial Triage
1. Extract archive to analysis workstation
2. Review `CollectionSummary.txt` for collection overview
3. Start with Priority event logs in EventLogs/Priority/
4. Focus on Security.evtx, System.evtx, and PowerShell logs

### Detailed Analysis
1. **Timeline Creation**: Correlate events across different log sources
2. **Process Analysis**: Review ProcessInfo for suspicious processes
3. **Network Analysis**: Examine NetworkInfo for unusual connections
4. **Persistence Analysis**: Check RegistryExports and StartupPrograms
5. **Execution Evidence**: Analyze Prefetch files for program execution

### Recommended Tools
- **Event Log Analysis**: Event Log Explorer, Hayabusa, Chainsaw, EvtxECmd
- **Timeline Analysis**: Plaso, Volatility, TimeSketch
- **Registry Analysis**: Registry Explorer, RegRipper
- **Network Analysis**: Wireshark, NetworkMiner
- **General Analysis**: AXIOM, EnCase, X-Ways Forensics

## Legal and Compliance

### Authorization Requirements
- Ensure proper authorization before running on any system
- Follow organizational incident response procedures
- Maintain documentation of collection activities

### Privacy Considerations
- Collection may include personally identifiable information (PII)
- Follow applicable privacy laws and regulations
- Implement appropriate data protection measures

### Chain of Custody
- Document who collected the data and when
- Maintain integrity of collected artifacts
- Use cryptographic hashing to verify data integrity

## Version History

### Version 2.0
- Added comprehensive security artifact collection
- Implemented priority event log categorization
- Added network and process information collection
- Improved error handling and progress reporting
- Added analysis guidance and documentation

### Version 1.0
- Basic event log collection functionality
- Simple ZIP archive creation
- Administrator privilege checking

## Support and Contributions

Artifact Collection is provided as-is for security analysis purposes. Users are responsible for:
- Testing in their environment before production use
- Ensuring compliance with organizational policies
- Validating collected data for their specific use cases

For questions or improvements, consult with your security team or forensic analysts.

## Disclaimer

Artifact Collection is designed for legitimate security analysis and incident response activities. Users must ensure they have proper authorization before collecting data from any system. The authors are not responsible for misuse of this tool or any data collected using it.
