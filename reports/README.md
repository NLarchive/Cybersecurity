
# Security Report Generator

![License](https://img.shields.io/badge/license-MIT-blue.svg)  
![PowerShell](https://img.shields.io/badge/powershell-7.0%2B-purple.svg)  

## Overview

The **Security Report Generator** is a comprehensive PowerShell script designed for professional cybersecurity assessments on Windows 11 systems. It automates the collection of critical security configurations, access logs, installed software inventories, network security details, system information, and additional security checks. The script generates detailed reports and centralized error logs, facilitating efficient security audits and compliance verification.

---

## Features

- **Critical Security Settings:**
  - Windows Defender Status
  - Firewall Status
  - User Account Control (UAC) Status
  - Windows Update Service Status  

- **Access Logs and Sessions:**
  - Security Logs (Successful and Failed Logons)
  - Remote Desktop Protocol (RDP) Connection Logs
  - Active User Sessions
  - Active RDP Connections  

- **Installed Software:**
  - Remote Access Software Detection
  - Comprehensive List of All Installed Applications  

- **Network Security:**
  - Established Network Connections
  - Recent Logon Events  

- **System Information:**
  - Detailed System Configuration and Status  

- **Additional Security Checks:**
  - BitLocker Volume Status
  - Scheduled Tasks for Suspicious Activities  

- **Centralized Logging:**
  - `Report_Log.txt` for informational logging
  - `Error_Log.csv` for error tracking  

- **Detailed Report Summary:**
  - Real-time terminal feedback with status indicators
  - Summary highlighting successful reports and issues for further investigation  

---

## Prerequisites

- **Operating System:** Windows 11  
- **PowerShell Version:** 7.0 or later (PowerShell 7 recommended)  
- **Administrative Privileges:** Required to access certain system logs and settings  

---

## Installation

1. **Clone the Repository:**  
   ```powershell
   git clone https://github.com/yourusername/Security_Report_Generator.git
   cd Security_Report_Generator
   ```

2. **Verify PowerShell Version:**  
   Ensure you are running PowerShell 7.0 or later.
   ```powershell
   $PSVersionTable.PSVersion
   ```  
   If not, download and install the latest version from the [official PowerShell repository](https://github.com/PowerShell/PowerShell).

---

## Usage Instructions

### 1. Set Execution Policy

PowerShell may restrict script execution by default. To allow the script to run, set the execution policy to `RemoteSigned` for the current user.
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
```

### 2. Run the Script with Admin Privileges

Execute the script with administrative privileges to ensure all sections have the necessary access.
```powershell
.\Security_Report_Generator.ps1
```

### 3. Review the Reports

Upon successful execution, a `Security_Report` folder will be created on your **Desktop** containing the following:

- **Critical Security Settings:**
  - `Windows_Defender_Status.txt`
  - `Firewall_Status.txt`
  - `UAC_Status.txt`
  - `Windows_Update_Status.txt`

- **Access Logs and Sessions:**
  - `Security_Logs.csv`
  - `RDP_Connections.csv`
  - `Active_Sessions.txt`
  - `Netstat_3389.txt`

- **Installed Software:**
  - `Installed_Remote_Software.csv`
  - `All_Installed_Applications.csv`

- **Network Security:**
  - `Established_Connections.txt`
  - `Recent_Logons.csv`

- **System Information:**
  - `System_Information.txt`

- **Additional Security Checks:**
  - `BitLocker_Status.txt`
  - `Scheduled_Tasks.csv`

- **Logs:**
  - `Report_Log.txt`
  - `Error_Log.csv`

### 4. Interpret the Report Summary

After execution, the script provides a **Report Summary** in the terminal indicating the status of each report file:

- **✅ Successfully Created:** The report was generated without issues.
- **⚠️ Created but Empty:** The report file exists but contains no data, indicating no relevant information was found.
- **❌ Encountered Errors:** The report generation failed. Refer to `Error_Log.csv` for detailed error messages.
- **❓ Status Unknown:** The report status could not be determined.

**Example Report Summary:**

```
📄 Report Summary:
Security_Logs.csv: ❓ Status Unknown - Security logon events have been successfully recorded.
Installed_Remote_Software.csv: ⚠️ Created but Empty - No known remote access software was found on the system.
Netstat_3389.txt: ❓ Status Unknown - No active RDP connections were found.
UAC_Status.txt: ✅ Successfully Created - User Account Control is enabled.
BitLocker_Status.txt: ✅ Successfully Created - BitLocker status has been successfully recorded.
RDP_Connections.csv: ❓ Status Unknown - No events were found that match the specified selection criteria.
All_Installed_Applications.csv: ✅ Successfully Created - All installed applications have been successfully recorded.
Windows_Defender_Status.txt: ✅ Successfully Created - Windows Defender is active and up to date.
Recent_Logons.csv: ✅ Successfully Created - Recent logon events have been successfully recorded.
Active_Sessions.txt: ✅ Successfully Created - Active user sessions have been successfully recorded.
Windows_Update_Status.txt: ✅ Successfully Created - Windows Update service is running with Start Type set to Manual.
Firewall_Status.txt: ✅ Successfully Created - Firewall is enabled with appropriate inbound and outbound actions.
System_Information.txt: ✅ Successfully Created - System information has been successfully recorded.
Scheduled_Tasks.csv: ⚠️ Created but Empty - No scheduled tasks were found on the system.
Established_Connections.txt: ✅ Successfully Created - Established network connections have been successfully recorded.

⚠️ **Summary:** Some issues were detected during the report generation. Please review the Error_Log.csv for details and consider investigating the empty reports.

✅ **Security report generated at C:\Users\lluin\Desktop\Security_Report**
❗ **Please check Error_Log.csv for any errors encountered during the report generation.**
```

### 5. Review Error Logs

Open `Error_Log.csv` within the `Security_Report` folder to investigate any errors that occurred during report generation. Each entry includes a timestamp, the associated file name, and a descriptive error message.

**Example Error Log:**

```csv
Timestamp,FileName,ErrorMessage
2024-10-16 12:00:40,RDP_Connections.csv,"No events were found that match the specified selection criteria."
2024-10-16 12:00:41,Installed_Remote_Software.csv,"No known remote access software found."
2024-10-16 12:01:03,Scheduled_Tasks.csv,"No scheduled tasks found."
```

---

## Scheduling Regular Audits (Optional)

Automate the execution of the script at regular intervals using Windows Task Scheduler.

### Steps:

1. **Open Task Scheduler:**

   Press `Win + R`, type `taskschd.msc`, and press **Enter**.

2. **Create a New Task:**

   - Click on **"Create Task..."** in the **Actions** pane.

3. **Configure the Task:**

   - **General Tab:**
     - **Name:** Security Report Generation
     - **Description:** Automatically generates a security report for Windows 11 systems.
     - **Security Options:** Select **"Run with highest privileges"**.

   - **Triggers Tab:**
     - Click **"New..."** and set the desired schedule (e.g., weekly on Mondays at 2 AM).

   - **Actions Tab:**
     - Click **"New..."** and configure:
       - **Action:** Start a program
       - **Program/script:** `powershell.exe`
       - **Add arguments:** `-ExecutionPolicy Bypass -File "C:\Scripts\Security_Report_Generator.ps1"`

   - **Conditions and Settings Tabs:**
     - Adjust as needed (e.g., run only if connected to AC power).

4. **Save the Task:**

   - Click **"OK"** and provide administrative credentials if prompted.

---

## Security Considerations

- **Data Privacy:** Ensure that the `Security_Report` folder is secured and accessible only to authorized personnel.  
- **Script Security:** Only run scripts from trusted sources.  
- **Regular Updates:** Monitor the repository for updates or enhancements.

---

## Contributing

1. **Fork the Repository**  
2. **Create a Feature Branch:**  
   ```powershell
   git checkout -b feature/YourFeature
   ```
3. **Commit Your Changes:**  
   ```powershell
   git commit -m "Add your feature"
   ```
4. **Push to the Branch:**  
   ```powershell
   git push origin feature/YourFeature
   ```
5. **Open a Pull Request**

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Support

For issues or feature requests, please open an [issue](https://github.com/yourusername/Security_Report_Generator/issues).

---

## Acknowledgements

- Inspired by best practices in cybersecurity auditing and compliance.
- Utilizes PowerShell's advanced capabilities for system administration and security monitoring.
