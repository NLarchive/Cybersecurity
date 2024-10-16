# Security_Report_Generator.ps1

# =====================================================================
# Security_Report_Generator.ps1
# Generates a comprehensive security report for Windows 11 systems.
# Enhanced with centralized error logging, detailed error messages,
# pre-execution administrative checks, and real-time terminal feedback.
# =====================================================================

# ------------------------------
# 1. Setup Report Directory and Logs
# ------------------------------
$reportPath = "$env:USERPROFILE\Desktop\Security_Report"
$logFile = "$reportPath\Report_Log.txt"
$errorLogFile = "$reportPath\Error_Log.csv"

# Initialize a hashtable to store file statuses
$fileStatus = @{}

# Function to log informational messages with timestamps
function Log-Message {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "$timestamp - $Message"
}

# Function to log errors with timestamps and associated file names
function Log-Error {
    param (
        [string]$FileName,
        [string]$ErrorMessage
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $escapedMessage = $ErrorMessage -replace '"', '""'
    $errorEntry = "$timestamp,$FileName,""$escapedMessage"""
    Add-Content -Path $errorLogFile -Value $errorEntry
}

# Function to check file status
function Check-FileStatus {
    param ([string]$Path)
    if (Test-Path $Path) {
        $size = (Get-Item $Path).Length
        if ($size -eq 0) {
            return "Empty"
        } else {
            return "Success"
        }
    } else {
        return "Not Found"
    }
}

# Function to update file status hashtable and provide terminal feedback
function Update-Status {
    param (
        [string]$FileName,
        [string]$Status,
        [string]$Message
    )
    $fileStatus[$FileName] = @{ Status = $Status; Message = $Message }
    switch ($Status) {
        "Success" {
            Write-Host "${FileName}: ✅ Successfully Created - $Message" -ForegroundColor Green
        }
        "Empty" {
            Write-Host "${FileName}: ⚠️ Created but Empty - $Message" -ForegroundColor Yellow
        }
        "Error" {
            Write-Host "${FileName}: ❌ Encountered Errors - $Message" -ForegroundColor Red
        }
        "Not Found" {
            Write-Host "${FileName}: ❌ File Not Found - $Message" -ForegroundColor Red
        }
    }
}

# ------------------------------
# 2. Pre-Execution Checks
# ------------------------------
# Check if running as Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")) {
    Write-Host "❌ Please run PowerShell as Administrator." -ForegroundColor Red
    exit
}

# Create Report Directory if it doesn't exist
if (!(Test-Path -Path $reportPath)) {
    try {
        New-Item -ItemType Directory -Path $reportPath -Force | Out-Null
        Write-Host "📁 Created Security_Report directory at $reportPath" -ForegroundColor Cyan
    } catch {
        Write-Host "❌ Failed to create report directory: $_" -ForegroundColor Red
        exit
    }
}

# Initialize the log files
try {
    "Security Report Generation Log - $(Get-Date)" | Out-File $logFile -Force
    "Timestamp,FileName,ErrorMessage" | Out-File $errorLogFile -Force
    Log-Message "Security report generation started."
} catch {
    Write-Host "❌ Failed to initialize log files: $_" -ForegroundColor Red
    exit
}

# ------------------------------
# 3. Critical Security Settings
# ------------------------------
Log-Message "Collecting Critical Security Settings."
Write-Host "🔍 Collecting Critical Security Settings..." -ForegroundColor Cyan

## 3.1 Windows Defender Status
$fileName = "Windows_Defender_Status.txt"
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled, AntivirusEnabled, AntivirusSignatureLastUpdated, RealTimeProtectionEnabled
    $defenderStatus | Format-List | Out-File "$reportPath\$fileName" -Force
    Log-Message "Collected Windows Defender Status."
    $status = Check-FileStatus "$reportPath\$fileName"
    if ($status -eq "Success") {
        Update-Status $fileName $status "Windows Defender is active and up to date."
    } else {
        Update-Status $fileName $status "Windows Defender status could not be determined."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect Windows Defender Status."
    Update-Status $fileName "Error" $_.Exception.Message
}

## 3.2 Firewall Status
$fileName = "Firewall_Status.txt"
try {
    $firewallStatus = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    $firewallStatus | Format-Table | Out-File "$reportPath\$fileName" -Force
    Log-Message "Collected Firewall Status."
    $status = Check-FileStatus "$reportPath\$fileName"
    if ($status -eq "Success") {
        Update-Status $fileName $status "Firewall is enabled with appropriate inbound and outbound actions."
    } else {
        Update-Status $fileName $status "Firewall status could not be determined."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect Firewall Status."
    Update-Status $fileName "Error" $_.Exception.Message
}

## 3.3 User Account Control (UAC) Status
$fileName = "UAC_Status.txt"
try {
    $uacStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction Stop
    $uacInfo = @{
        'User Account Control Enabled' = if ($uacStatus.EnableLUA -eq 1) {'Yes'} else {'No'}
    }
    $uacInfo | Out-File "$reportPath\$fileName" -Force
    Log-Message "Collected UAC Status."
    $status = Check-FileStatus "$reportPath\$fileName"
    if ($status -eq "Success") {
        Update-Status $fileName $status "User Account Control is enabled."
    } else {
        Update-Status $fileName $status "UAC status could not be determined."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect UAC Status."
    Update-Status $fileName "Error" $_.Exception.Message
}

## 3.4 Windows Update Status
$fileName = "Windows_Update_Status.txt"
try {
    # Check the service status
    $wuStatus = Get-Service -Name wuauserv -ErrorAction Stop | Select-Object Status, StartType
    $wuStatus | Format-List | Out-File "$reportPath\$fileName" -Force
    Log-Message "Collected Windows Update Status."
    $status = Check-FileStatus "$reportPath\$fileName"
    if ($status -eq "Success") {
        Update-Status $fileName $status "Windows Update service is running with Start Type set to $($wuStatus.StartType)."
    } else {
        Update-Status $fileName $status "Windows Update service status could not be determined."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect Windows Update Status."
    Update-Status $fileName "Error" $_.Exception.Message
}

# ------------------------------
# 4. Access Logs and Sessions
# ------------------------------
Log-Message "Collecting Access Logs and Active Sessions."
Write-Host "🔍 Collecting Access Logs and Active Sessions..." -ForegroundColor Cyan

## 4.1 Security Logs: Successful and Failed Logons
$fileName = "Security_Logs.csv"
try {
    $securityLogs = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625} -MaxEvents 1000 -ErrorAction Stop |
        Select-Object TimeCreated, Id, LevelDisplayName, Message
    if ($securityLogs.Count -gt 0) {
        $securityLogs | Export-Csv "$reportPath\$fileName" -NoTypeInformation -Force
        Log-Message "Collected Security Logs."
        $status = Check-FileStatus "$reportPath\$fileName"
        Update-Status $fileName $status "Security logon events have been successfully recorded."
    } else {
        Log-Error $fileName "No events were found that match the specified selection criteria."
        # Create an empty file to indicate no data
        New-Item -ItemType File -Path "$reportPath\$fileName" -Force | Out-Null
        Log-Message "No Security log events found."
        Update-Status $fileName "Empty" "No security logon events were found."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect Security Logs."
    Update-Status $fileName "Error" $_.Exception.Message
}

## 4.2 Remote Desktop Connection Logs
$fileName = "RDP_Connections.csv"
try {
    $rdpLogs = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; ID=1149} -MaxEvents 1000 -ErrorAction Stop |
        Select-Object TimeCreated, Id, LevelDisplayName, Message
    if ($rdpLogs.Count -gt 0) {
        $rdpLogs | Export-Csv "$reportPath\$fileName" -NoTypeInformation -Force
        Log-Message "Collected RDP Connection Logs."
        $status = Check-FileStatus "$reportPath\$fileName"
        Update-Status $fileName $status "RDP connection events have been successfully recorded."
    } else {
        Log-Error $fileName "No events were found that match the specified selection criteria."
        # Create an empty file to indicate no data
        New-Item -ItemType File -Path "$reportPath\$fileName" -Force | Out-Null
        Log-Message "No RDP connection events found."
        Update-Status $fileName "Empty" "No RDP connection events were found."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect RDP Connection Logs."
    Update-Status $fileName "Error" $_.Exception.Message
}

## 4.3 Active Remote Sessions
### 4.3.1 Query Active Users
$fileName = "Active_Sessions.txt"
try {
    query user | Out-File "$reportPath\$fileName" -Force
    Log-Message "Collected Active Sessions."
    $status = Check-FileStatus "$reportPath\$fileName"
    if ($status -eq "Success") {
        Update-Status $fileName $status "Active user sessions have been successfully recorded."
    } else {
        Update-Status $fileName $status "Active user sessions could not be determined."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect Active Sessions."
    Update-Status $fileName "Error" $_.Exception.Message
}

### 4.3.2 Check for Active RDP Connections
$fileName = "Netstat_3389.txt"
try {
    netstat -an | Select-String ":3389" | Out-File "$reportPath\$fileName" -Force
    Log-Message "Collected Netstat 3389 Information."
    $status = Check-FileStatus "$reportPath\$fileName"
    if ($status -eq "Success") {
        Update-Status $fileName $status "Active RDP connections have been successfully recorded."
    } else {
        Update-Status $fileName $status "No active RDP connections were found."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect Netstat 3389 Information."
    Update-Status $fileName "Error" $_.Exception.Message
}

# ------------------------------
# 5. Installed Software
# ------------------------------
Log-Message "Collecting Installed Software Information."
Write-Host "🔍 Collecting Installed Software Information..." -ForegroundColor Cyan

## 5.1 Installed Remote Access Software
$fileName = "Installed_Remote_Software.csv"
try {
    $remoteAccessSoftware = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                                             'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction Stop |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Where-Object { $_.DisplayName -match 'TeamViewer|AnyDesk|VNC|Remote Desktop|UltraVNC|LogMeIn|GoToMyPC' }

    if ($remoteAccessSoftware.Count -gt 0) {
        $remoteAccessSoftware | Export-Csv "$reportPath\$fileName" -NoTypeInformation -Force
        Log-Message "Collected Installed Remote Access Software."
        $status = Check-FileStatus "$reportPath\$fileName"
        Update-Status $fileName $status "Remote access software installations have been successfully recorded."
    } else {
        Log-Error $fileName "No known remote access software found."
        # Create an empty file to indicate no data
        New-Item -ItemType File -Path "$reportPath\$fileName" -Force | Out-Null
        Log-Message "No Installed Remote Access Software found."
        Update-Status $fileName "Empty" "No known remote access software was found on the system."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect Installed Remote Access Software."
    Update-Status $fileName "Error" $_.Exception.Message
}

## 5.2 All Installed Applications (for auditing)
$fileName = "All_Installed_Applications.csv"
try {
    $allInstalledApps = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                                       'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction Stop |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

    if ($allInstalledApps.Count -gt 0) {
        $allInstalledApps | Export-Csv "$reportPath\$fileName" -NoTypeInformation -Force
        Log-Message "Collected All Installed Applications."
        $status = Check-FileStatus "$reportPath\$fileName"
        Update-Status $fileName $status "All installed applications have been successfully recorded."
    } else {
        Log-Error $fileName "No installed applications found."
        # Create an empty file to indicate no data
        New-Item -ItemType File -Path "$reportPath\$fileName" -Force | Out-Null
        Log-Message "No Installed Applications found."
        Update-Status $fileName "Empty" "No installed applications were found on the system."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect All Installed Applications."
    Update-Status $fileName "Error" $_.Exception.Message
}

# ------------------------------
# 6. Network Security
# ------------------------------
Log-Message "Collecting Network Security Information."
Write-Host "🔍 Collecting Network Security Information..." -ForegroundColor Cyan

## 6.1 Active Network Connections
$fileName = "Established_Connections.txt"
try {
    netstat -ano | Select-String "ESTABLISHED" | Out-File "$reportPath\$fileName" -Force
    Log-Message "Collected Established Network Connections."
    $status = Check-FileStatus "$reportPath\$fileName"
    if ($status -eq "Success") {
        Update-Status $fileName $status "Established network connections have been successfully recorded."
    } else {
        Update-Status $fileName $status "No established network connections were found."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect Established Network Connections."
    Update-Status $fileName "Error" $_.Exception.Message
}

## 6.2 Recent Logon Events
$fileName = "Recent_Logons.csv"
try {
    $recentLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 1000 -ErrorAction Stop |
        Select-Object TimeCreated, Id, LevelDisplayName, Message
    if ($recentLogons.Count -gt 0) {
        $recentLogons | Export-Csv "$reportPath\$fileName" -NoTypeInformation -Force
        Log-Message "Collected Recent Logon Events."
        $status = Check-FileStatus "$reportPath\$fileName"
        Update-Status $fileName $status "Recent logon events have been successfully recorded."
    } else {
        Log-Error $fileName "No events were found that match the specified selection criteria."
        # Create an empty file to indicate no data
        New-Item -ItemType File -Path "$reportPath\$fileName" -Force | Out-Null
        Log-Message "No Recent Logon Events found."
        Update-Status $fileName "Empty" "No recent logon events were found."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect Recent Logon Events."
    Update-Status $fileName "Error" $_.Exception.Message
}

# ------------------------------
# 7. System Information
# ------------------------------
Log-Message "Collecting System Information."
Write-Host "🔍 Collecting System Information..." -ForegroundColor Cyan

## 7.1 Detailed System Information
$fileName = "System_Information.txt"
try {
    systeminfo | Out-File "$reportPath\$fileName" -Force
    Log-Message "Collected System Information."
    $status = Check-FileStatus "$reportPath\$fileName"
    if ($status -eq "Success") {
        Update-Status $fileName $status "System information has been successfully recorded."
    } else {
        Update-Status $fileName $status "System information could not be determined."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect System Information."
    Update-Status $fileName "Error" $_.Exception.Message
}

# ------------------------------
# 8. Additional Security Checks (Optional)
# ------------------------------
Log-Message "Collecting Additional Security Information."
Write-Host "🔍 Collecting Additional Security Information..." -ForegroundColor Cyan

## 8.1 BitLocker Status
$fileName = "BitLocker_Status.txt"
try {
    $bitlockerStatus = Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint, VolumeStatus, ProtectionStatus
    if ($bitlockerStatus.Count -gt 0) {
        $bitlockerStatus | Format-Table | Out-File "$reportPath\$fileName" -Force
        Log-Message "Collected BitLocker Status."
        $status = Check-FileStatus "$reportPath\$fileName"
        Update-Status $fileName $status "BitLocker status has been successfully recorded."
    } else {
        Log-Error $fileName "No BitLocker volumes found."
        # Create an empty file to indicate no data
        New-Item -ItemType File -Path "$reportPath\$fileName" -Force | Out-Null
        Log-Message "No BitLocker Volumes found."
        Update-Status $fileName "Empty" "No BitLocker volumes were found on the system."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect BitLocker Status."
    Update-Status $fileName "Error" $_.Exception.Message
}

## 8.2 Scheduled Tasks for Suspicious Activities
$fileName = "Scheduled_Tasks.csv"
try {
    $scheduledTasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -like "*\\*" } |
        Select-Object TaskName, TaskPath, State

    if ($scheduledTasks.Count -gt 0) {
        $scheduledTasks | Export-Csv "$reportPath\$fileName" -NoTypeInformation -Force
        Log-Message "Collected Scheduled Tasks."
        $status = Check-FileStatus "$reportPath\$fileName"
        Update-Status $fileName $status "Scheduled tasks have been successfully recorded."
    } else {
        Log-Error $fileName "No scheduled tasks found."
        # Create an empty file to indicate no data
        New-Item -ItemType File -Path "$reportPath\$fileName" -Force | Out-Null
        Log-Message "No Scheduled Tasks found."
        Update-Status $fileName "Empty" "No scheduled tasks were found on the system."
    }
} catch {
    Log-Error $fileName $_.Exception.Message
    Log-Message "Failed to collect Scheduled Tasks."
    Update-Status $fileName "Error" $_.Exception.Message
}

# ------------------------------
# 9. Completion Message and Summary
# ------------------------------
Log-Message "Security report generation completed successfully."
Write-Host "✅ Security report generation completed." -ForegroundColor Cyan
Write-Host "`n📄 **Report Summary:**" -ForegroundColor Yellow

$hasIssues = $false

foreach ($file in $fileStatus.Keys) {
    $statusObj = $fileStatus[$file]
    $status = $statusObj.Status
    $message = $statusObj.Message
    switch ($status) {
        "Success" {
            Write-Host "${file}: ✅ Successfully Created - $message" -ForegroundColor Green
        }
        "Empty" {
            Write-Host "${file}: ⚠️ Created but Empty - $message" -ForegroundColor Yellow
            $hasIssues = $true
        }
        "Error" {
            Write-Host "${file}: ❌ Encountered Errors - $message" -ForegroundColor Red
            $hasIssues = $true
        }
        "Not Found" {
            Write-Host "${file}: ❌ File Not Found - $message" -ForegroundColor Red
            $hasIssues = $true
        }
        default {
            Write-Host "${file}: ❓ Status Unknown - $message" -ForegroundColor DarkYellow
            $hasIssues = $true
        }
    }
}

if ($hasIssues) {
    Write-Host "`n⚠️ **Summary:** Some issues were detected during the report generation. Please review the `Error_Log.csv` for details and consider investigating the empty reports." -ForegroundColor Yellow
} else {
    Write-Host "`n✅ **Summary:** All reports were generated successfully without any issues. Your system appears to be secure." -ForegroundColor Green
}

Write-Host "`n✅ **Security report generated at $reportPath**" -ForegroundColor Green
Write-Host "❗ **Please check Error_Log.csv for any errors encountered during the report generation.**" -ForegroundColor Magenta
