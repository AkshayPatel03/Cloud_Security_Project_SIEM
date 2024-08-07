# Cloud Security Project: Monitoring and Responding to Failed Logon Attempts with Azure Sentinel (SIEM) 

## Overview

This project demonstrates how to use Microsoft Azure to create a secure cloud environment, monitor failed logon attempts, and respond to potential security incidents. It leverages Azure Virtual Machines, Azure Log Analytics, Microsoft Defender for Cloud, and Azure Sentinel. Additionally, this project involves adding custom log files, using an IP Geolocation API to get the exact location of IP addresses, and visualizing these locations in maps in Azure Sentinel. This comprehensive approach showcases my skills in using SIEM technology.

## Objectives

- Provision and configure a Windows 10 virtual machine in Azure.
- Expose the virtual machine to the internet and monitor it for security events.
- Use PowerShell to scan the Event Viewer for failed logon attempts (EventID 4625).
- Send log data to Azure Log Analytics and visualize it in Azure Sentinel.
- Use IPgeolocation.io API to map the origin of logon attempts.
- Implement incident response and remediation procedures.

## Features

- [**Microsoft Azure**](https://azure.microsoft.com/en-us/free/): Cloud platform for creating and managing virtual machines.
- [**Azure Log Analytics Workspace**](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-workspace-overview): Collects and analyzes log data.
- [**Microsoft Defender for Cloud**](https://learn.microsoft.com/en-us/azure/defender-for-cloud/managing-and-responding-alerts): Provides security management and threat protection.
- [**Azure Sentinel**](https://learn.microsoft.com/en-us/azure/sentinel/overview?tabs=azure-portal): Cloud-native SIEM tool for monitoring and analyzing security data.
- [**PowerShell**](https://learn.microsoft.com/en-us/powershell/azure/get-started-azureps?view=azps-12.0.0): Script to scan Event Viewer and send log data to an external API.
- [**IPgeolocation.io API**](https://ipgeolocation.io/): Retrieves geolocation information for IP addresses.

## Step 1: Deploy Azure Virtual Machines

### Setting Up Virtual Machines

To begin, I deployed several Azure Virtual Machines (VMs) to create a baseline infrastructure. These VMs were configured with Windows Server and enabled for Remote Desktop Protocol (RDP). The VMs acted as honeypots to attract unauthorized access attempts.

1. **Creating VMs**: Using the Azure Portal, I created VMs by selecting the appropriate VM size, OS image, and configuring network settings.
2. **Enabling RDP**: Ensuring RDP was enabled on these VMs allowed for remote access, which was crucial for monitoring failed logon attempts.

### Screenshots

- **Screenshot 1.1**: VM creation process in Azure Portal.

![Azure portal Google](Project_screenshots/Azure_VM_Creation.png)

![Azure Free Portal](Project_screenshots/Azure_VM_Creation_2.png)

![VM creation](Project_screenshots/Azure_VM_Creation_11.png)

![Resource Creation](Project_screenshots/Azure_VM_Creation_3.png)

- **Screenshot 1.2**: Network settings configuration for the VM.

![NSG network configuration](Project_screenshots/NSG_Setup1.png)

![NSG inbound rule setup](Project_screenshots/NSG_Setup2.jpg)

![NSG inbound rule configuration](Project_screenshots/NSG_Setup3.png)

![NSG inbound rule configuration 2](Project_screenshots/NSG_Setup4.png)

## Step 2: Implementing Microsoft Defender for Cloud

### Enabling Microsoft Defender for Cloud

To enhance the security of my Azure environment, I enabled Microsoft Defender for Cloud. This service provides advanced threat protection for Azure resources.

1. **Security Center Configuration**: Configured the Azure Security Center to monitor the VMs and provide security recommendations.
2. **Policy Assignment**: Applied security policies to ensure that the VMs adhered to best practices.

### Monitoring Security Alerts

Microsoft Defender for Cloud continuously monitored the environment and generated alerts for suspicious activities, such as repeated failed logon attempts.

### Screenshots

- **Screenshot 2.1**: Microsoft Defender for Cloud dashboard showing security posture.

![Microsoft Defender for Cloud Dashboard](Project_screenshots/Microsoft-Defender-for-cloud1.png)

![Microsoft Defender for Cloud Alerts](Project_screenshots/Microsoft-Defender-for-cloud3.png)

## Step 3: Configuring Log Collection with Azure Log Analytics

### Creating a Log Analytics Workspace

I created an Azure Log Analytics Workspace to collect and analyze log data from the VMs. This workspace served as the central hub for all log-related activities.

1. **Workspace Creation**: I set up a new Log Analytics Workspace using the Azure Portal.
2. **Agent Installation**: Installed the Log Analytics agent on each VM to forward log data to the workspace.

### Configuring Data Collection

I configured the workspace to collect specific logs, such as Windows Event logs, which include details about failed RDP attempts. This setup ensured that all relevant security events were captured.

### 3. Monitoring with PowerShell

1. **PowerShell Script**:

   - Open PowerShell on the VM and create a script to scan Event Viewer for EventID 4625.
   - Use the IPgeolocation.io API to log the IP addresses and their geolocations.

[Powershell script for Locations](../Scrips/geo_location_logs.ps1)

### Screenshots

- **Screenshot 3.1**: Log Analytics Workspace creation.

![Log Analytics Workspace Creation](Project_screenshots/Log_Analytics_Workspace1.png)

![Log Analytics Workspace Setup](Project_screenshots/Log_Analytics_Workspace2.png)

![Log Analytics Workspace Configuration](Project_screenshots/Log_Analytics_Workspace4.png)

![Log Analytics Workspace Connection](Project_screenshots/Log_Analytics-Connection2.png)

![Log Analytics Workspace Connection 2](Project_screenshots/Log_Analytics-Connection3.png)

- **Screenshot 3.2**: VM Access remotely, Check Security logs

![VM Access Remotely](Project_screenshots/Azure_VM_Creation_Step1.png)

![RDP Agent](Project_screenshots/RDP-agent.png)

![RDP VM Agent Connection](Project_screenshots/RDP-VM-agent-connect.png)

![RDP VM OS Setup](Project_screenshots/RDP-VM-OsSetup.png)

- **Screenshot 3.3**:Turn off Firewall to allow the traffic in.

![Firewall Off](Project_screenshots/RDP-VM-Firewall-off.png)

![VM Connection](Project_screenshots/RDP-VM-connection.png)

- **Screenshot 3.4**:Configuration of data collection rules in Log Analytics.

![Failed Logon Attempts Event Viewer](Project_screenshots/RDP-VM-FailedLogonAttempts-EventViewer.png)

```kql
SecurityEvent
| where EventID == 4625
```

![Log Analytics Query](Project_screenshots/LAWFailed_Logon_Analytics_Query-1.png)

### Integrating IP Geolocation API

To enhance the analysis of failed logon attempts, I integrated an IP Geolocation API. This API converted IP addresses from the logs into geographical locations.

1. **API Integration**: Used an IP Geolocation API (such as MaxMind or IPstack) in an Azure Function to look up the geographical locations of IP addresses.
2. **Data Enrichment**: The Azure Function enriched the log data with latitude and longitude coordinates for each IP address.

- **Screenshot 3.5**: Geo Location API setup, get API key

![Geo Location API Setup](Project_screenshots/Geo-location-api2.png)

![Geo Location API Explanation](Project_screenshots/Geo-location-api-explaination.png)

- **Screenshot 3.6**: Powershell script to create custom log and extract location using IPs.

![PowerShell Script Custom Log](Project_screenshots/RDP-VM-Powershel-script-Custom-log-file-create.png)

![PowerShell Failed Logon Attempts](Project_screenshots/RDP-VM-Powershel-Failed_Logon_Attempts.png)

- **Screenshot 3.7**: Example of a Custom log schema creation in Log Analytics.

![Custom Log Schema Creation Step 1](Project_screenshots/LAW_Custom_logSchema_create-1.png)

![Custom Log Schema Creation Step 2](Project_screenshots/LAW_Custom_logSchema_create2.png)

![Custom Log Schema Creation Step 3](Project_screenshots/LAW_Custom_logSchema_create3.png)

![Custom Log Schema Creation Step 4](Project_screenshots/LAW_Custom_logSchema_create4.png)

![Custom Log Schema Creation Step 5](Project_screenshots/LAW_Custom_logSchema_create5.png)

![Custom Log Schema Creation Step 6](Project_screenshots/LAW_Custom_logSchema_create6.png)

- **Screenshot 3.8**: Example of KQL query to fetch the Custom logs in the Log Analytics from honeypot VM.

This is the log data we get from powershell scrip, GeoLocation API and custom log file. We need to modify it to visualise this data in the Microsoft Sentinel.

```kql
GEO_Data_failedRDP_CL
```

![KQL Query for Custom Logs](Project_screenshots/LAWFailed_Logon_Analytics_Query-2.png)

This is KQL is to extract the field from the raw data.

```kql
GEO_Data_failedRDP_CL
| extend
  latitude = extract("latitude:([^,]+)", 1, RawData),
  longitude = extract("longitude:([^,]+)", 1, RawData),
  destinationhost = extract("destinationhost:([^,]+)", 1, RawData),
  username = extract("username:([^,]+)", 1, RawData),
  sourcehost = extract("sourcehost:([^,]+)", 1, RawData),
  state = extract("state:([^,]+)", 1, RawData),
  country = extract("country:([^,]+)", 1, RawData),
  label = extract("label:([^,]+)", 1, RawData),
  timestamp = extract("timestamp:([^,]+)", 1, RawData)
| project latitude, longitude, destinationhost, username, sourcehost, state, country, label, timestamp
```

![Log Analytics Query After 3 Days](Project_screenshots/LAWFailed_Logon_AnalyticsALLafter3days.png)

## Step 4: Setting Up Azure Sentinel

### Deploying Azure Sentinel

To centralize security monitoring and incident response, I deployed Azure Sentinel. This cloud-native SIEM (Security Information and Event Management) system allowed for advanced threat detection and response.

1. **Connecting Data Sources**: Connected Azure Sentinel to the Log Analytics Workspace, enabling it to ingest log data from the VMs.
2. **Creating Analytics Rules**: Created custom analytics rules to detect failed logon attempts and other potential security incidents.

### Visualizing Data in Azure Sentinel

Azure Sentinel provided a rich set of tools for visualizing security data and responding to incidents. I created dashboards to display real-time data on failed logon attempts, including geographical distribution and trends.

1. **Map Visualization**: Used Azure Sentinel’s built-in map visualizations to display the geographical locations of failed logon attempts on a world map.
2. **Incident Response**: Configured playbooks in Azure Sentinel to automate responses to detected incidents, enhancing the overall security posture.

### Screenshots

- **Screenshot 4.1**: Azure Sentinel dashboard showing connected data sources.

![Azure Sentinel Create Step 1](Project_screenshots/MicrosoftSentinelCreate1.png)

![Azure Sentinel Create Step 2](Project_screenshots/MicrosoftSentinelCreate2.png)

![Azure Sentinel Create Step 3](Project_screenshots/MicrosoftSentinelCreate3.png)

![Azure Sentinel Create Step 4](Project_screenshots/MicrosoftSentinelCreate4.png)

- **Screenshot 4.2**: Visualization of failed logon attempt locations on a map in Sentinel.

  ```kql
  GEO_Data_failedRDP_CL
  | extend
    latitude = todouble(extract("latitude:([^,]+)", 1, RawData)),
    longitude = todouble(extract("longitude:([^,]+)", 1, RawData)),
    destinationhost = extract("destinationhost:([^,]+)", 1, RawData),
    username = extract("username:([^,]+)", 1, RawData),
    sourcehost = extract("sourcehost:([^,]+)", 1, RawData),
    state = extract("state:([^,]+)", 1, RawData),
    country = extract("country:([^,]+)", 1, RawData),
    label = extract("label:([^,]+)", 1, RawData),
    timestamp = extract("timestamp:([^,]+)", 1, RawData)
  | project latitude, longitude, destinationhost, username, sourcehost, state, country, label, timestamp
  | where isnotempty(latitude) and isnotempty(longitude)
  | summarize event_count=count() by sourcehost, latitude, longitude, country, state, label, destinationhost
  | where destinationhost != "samplehost"
  | where sourcehost != ""

  ```

![Azure Sentinel SIEM Grid](Project_screenshots/Azure-Sentenial-SIEM-grid.png)

![Azure Sentinel SIEM Map](Project_screenshots/Azure-Sentenial-SIEM-map-2.png)

![Azure Sentinel SIEM Map](Project_screenshots/Azure-Sentenial-SIEM-map-3.png)

![Geo Location API Limit](Project_screenshots/Geo-location-api-limit.png)

![Azure Sentinel SIEM Map After 3 Days](Project_screenshots/Azure-Sentenial-SIEM-map-4After3days.png)

### 6. Incident Response and Remediation

1. **Incident Detection**:

   - Set up alert rules in Azure Sentinel to detect suspicious activities, such as multiple failed logon attempts from the same IP.
   - Example KQL query to detect failed logon attempts:

   ```kql
   GEO_Data_failedRDP_CL
   | extend
    latitude = todouble(extract("latitude:([^,]+)", 1, RawData)),
    longitude = todouble(extract("longitude:([^,]+)", 1, RawData)),
    destinationhost = extract("destinationhost:([^,]+)", 1, RawData),
    username = extract("username:([^,]+)", 1, RawData),
    sourcehost = extract("sourcehost:([^,]+)", 1, RawData),
    state = extract("state:([^,]+)", 1, RawData),
    country = extract("country:([^,]+)", 1, RawData),
    label = extract("label:([^,]+)", 1, RawData),
    timestamp = extract("timestamp:([^,]+)", 1, RawData)
   | project latitude, longitude, destinationhost, username, sourcehost, state, country, label, timestamp
   | where isnotempty(latitude) and isnotempty(longitude)
   | where destinationhost != "samplehost" and sourcehost != ""
   | summarize event_count=count() by sourcehost, latitude, longitude, country, state, label, destinationhost
   | where event_count > 10
   | project sourcehost, event_count, latitude, longitude, country, state, label, destinationhost
   ```

2. **Response Actions**:

   - Automate responses using Azure Logic Apps to notify the SOC team.
   - Block malicious IP addresses using Azure Firewall or NSG rules.

3. **Reporting**:

   - Generate reports summarizing the incidents detected and actions taken.
   - Example report template:

   ```markdown
   ## Incident Report

   ### Incident Summary

   - **Date/Time**: 31/05/2024 7:50 PM
   - **Description**: Multiple failed logon attempts detected from IP .

   ### Affected Resources

   - **Resource**: My honeypot Windows 10 machine
   - **Public IP**: 20.80.222.3

   ### Actions Taken

   - **Action 1**: Blocked IP address using NSG rule. Blocked IP 182.75.135.46 in the NSG inbound rule.
   - **Action 2**: Notified SOC team via email.

   ### Recommendations

   - **Recommendation 1**: Implement multi-factor authentication (MFA).
   - **Recommendation 2**: Regularly review and update firewall rules.
   ```

## Conclusion

Through this project, I successfully demonstrated how to create a secure cloud environment using Microsoft Azure. By leveraging Azure Virtual Machines, Azure Log Analytics, Microsoft Defender for Cloud, and Azure Sentinel, I was able to monitor failed logon attempts and respond to potential security incidents effectively. The integration of custom log files and an IP Geolocation API allowed for precise location tracking and visualization of attack origins. This project showcases my ability to implement and manage advanced security solutions, utilizing SIEM technology to enhance threat detection and response.
