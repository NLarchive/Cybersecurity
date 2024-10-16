# Cybersecurity
# README.md

# Security Report Generator

## Overview

The **Security Report Generator** is a PowerShell script designed to create a comprehensive security report for Windows 11 systems. The report includes critical security settings, access logs, installed software, network security information, system details, and additional security checks. All errors encountered during the report generation are logged in a centralized error log for easy troubleshooting.

## Features

- **Critical Security Settings:** Windows Defender status, Firewall status, User Account Control (UAC) status, Windows Update status.
- **Access Logs and Sessions:** Security logs, Remote Desktop Protocol (RDP) connections, active user sessions, active RDP connections.
- **Installed Software:** Lists of installed remote access software and all installed applications for auditing.
- **Network Security:** Active network connections and recent logon events.
- **System Information:** Detailed system configuration.
- **Additional Security Checks:** BitLocker status and scheduled tasks for suspicious activities.
- **Centralized Error Logging:** All errors are recorded in a single `Error_Log.txt` file.

## Prerequisites

- **Operating System:** Windows 11
- **PowerShell Version:** 5.1 or later (PowerShell 7 recommended)
- **Administrative Privileges:** The script must be run with administrative rights to access certain system logs and settings.

## Setup Instructions

1. **Download the Script:**
   
   - Save the `Security_Report_Generator.ps1` script to a desired location on your computer, e.g., `C:\Scripts\Security_Report_Generator.ps1`.

2. **Set Execution Policy:**
   
   PowerShell may restrict script execution by default. To allow the script to run:
   
   - Open **PowerShell as Administrator**:
     - Press `Win + X` and select **Windows Terminal (Admin)** or **Windows PowerShell (Admin)**.
   - Execute the following command:
     ```powershell
     Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
     ```
   - When prompted, type **`Y`** and press **Enter**.

3. **Run the Script:**
   
   - Navigate to the directory where the script is saved:
     ```powershell
     cd "C:\Scripts"
     ```
   - Execute the script:
     ```powershell
     .\Security_Report_Generator.ps1
     ```
   
   - **Note:** Ensure that PowerShell is running with administrative privileges.

4. **Review the Reports:**
   
   - Upon successful execution, a folder named `Security_Report` will be created on your **Desktop**.
   - Navigate to `C:\Users\YourUsername\Desktop\Security_Report` to access the generated report files.
   - **Report Files Include:**
     - **Critical Security Settings:** `Windows_Defender_Status.txt`, `Firewall_Status.txt`, `UAC_Status.txt`, `Windows_Update_Status.txt`
     - **Access Logs and Sessions:** `Security_Logs.csv`, `RDP_Connections.csv`, `Active_Sessions.txt`, `Netstat_3389.txt`
     - **Installed Software:** `Installed_Remote_Software.csv`, `All_Installed_Applications.csv`
     - **Network Security:** `Established_Connections.txt`, `Recent_Logons.csv`
     - **System Information:** `System_Information.txt`
     - **Additional Security Checks:** `BitLocker_Status.txt`, `Scheduled_Tasks.csv`
     - **Logs:** `Report_Log.txt`, `Error_Log.txt`

5. **Check Error Log:**
   
   - Open `Error_Log.txt` within the `Security_Report` folder to review any errors encountered during the report generation.
   - Each error entry includes a timestamp, the associated file name, and a descriptive error message.

## Scheduling Regular Audits (Optional)

To automate the execution of the script at regular intervals:

1. **Open Task Scheduler:**
   
   - Press `Win + R`, type `taskschd.msc`, and press **Enter**.

2. **Create a New Task:**
   
   - Click on **"Create Task..."** in the **Actions** pane.
   
3. **Configure the Task:**
   
   - **General Tab:**
     - **Name:** Security Report Generation
     - **Description:** Automatically generates a security report for Windows 11 systems.
     - **Security Options:** Select **"Run with highest privileges"**.
   
   - **Triggers Tab:**
     - Click **"New..."** and set the schedule (e.g., weekly on Mondays at 2 AM).
   
   - **Actions Tab:**
     - Click **"New..."** and configure:
       - **Action:** Start a program
       - **Program/script:** `powershell.exe`
       - **Add arguments:** `-ExecutionPolicy Bypass -File "C:\Scripts\Security_Report_Generator.ps1"`
   
   - **Conditions and Settings Tabs:**
     - Adjust as needed (e.g., run only if connected to AC power).
   
4. **Save the Task:**
   
   - Click **"OK"** and provide administrative credentials if prompted.

## Security Considerations

- **Data Privacy:** The generated reports contain sensitive system information. Ensure that the `Security_Report` folder is secured and accessible only to authorized personnel.
  
- **Script Security:** Only run scripts from trusted sources. Review and understand the script's contents before execution.

- **Regular Updates:** Keep the script updated to adapt to evolving security requirements and system changes.

## Support

For any issues or questions regarding the Security Report Generator, please contact the project maintainer.

