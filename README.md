# Cloud Security Project: Monitoring and Responding to Failed Logon Attempts with Azure

## Overview

This project demonstrates how to use Microsoft Azure to create a secure cloud environment, monitor failed logon attempts, and respond to potential security incidents. It leverages Azure Virtual Machines, Azure Log Analytics, Microsoft Defender for Cloud, and Azure Sentinel to provide a comprehensive security monitoring and incident response solution. 

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

## Architecture

![Architecture Diagram](https://github.com/yourusername/yourrepository/raw/main/images/architecture_diagram.png)

## Step-by-Step Guide

### 1. Provisioning the Virtual Machine

1. **Create a Virtual Machine**:
    - Go to the Azure portal and create a new VM with the following configuration:
        - **Image**: Windows 10
        - **Size**: Standard B2s (2 vcpus, 4 GiB memory)
        - **Inbound Port Rules**: Allow RDP (3389)
    - Ensure the VM has a static public IP address.

### 2. Configuring Network Security

1. **Network Security Group**:
    - Configure the NSG to allow inbound traffic on RDP (port 3389) for remote access.
    - Implement rules to restrict access to only trusted IP addresses.

### 3. Setting Up Log Collection

1. **Azure Log Analytics Workspace**:
    - Create a Log Analytics Workspace in Azure.
    - Install the Log Analytics agent on the VM and link it to the workspace.

### 4. Monitoring with PowerShell

1. **PowerShell Script**:
    - Open PowerShell on the VM and create a script to scan Event Viewer for EventID 4625.
    - Use the IPgeolocation.io API to log the IP addresses and their geolocations.

    ```powershell
    $logPath = "C:\path\to\logfile.txt"
    $apiKey = "your_api_key"
    
    Get-EventLog -LogName Security -InstanceId 4625 | ForEach-Object {
        $ip = $_.ReplacementStrings[-2]
        $response = Invoke-RestMethod -Uri "https://api.ipgeolocation.io/ipgeo?apiKey=$apiKey&ip=$ip"
        $location = $response | Select-Object -ExpandProperty geo
        Add-Content -Path $logPath -Value "$($ip) - $($location.country_name)"
    }
    ```

### 5. Integrating with Azure Sentinel

1. **Azure Sentinel**:
    - Enable Azure Sentinel on your Log Analytics Workspace.
    - Create data connectors to ingest log data from the VM.
    - Configure workbooks and dashboards to visualize the data.

### 6. Incident Response and Remediation

1. **Incident Detection**:
    - Set up alert rules in Azure Sentinel to detect suspicious activities, such as multiple failed logon attempts from the same IP.
    - Example KQL query to detect failed logon attempts:
    ```kql
    SecurityEvent
    | where EventID == 4625
    | summarize count() by IPAddress, bin(TimeGenerated, 1h)
    | where count_ > 5
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
    - **Date/Time**: 
    - **Description**: Multiple failed logon attempts detected from IP .

    ### Affected Resources
    - **Resource**: 
    - **Public IP**: 

    ### Actions Taken
    - **Action 1**: Blocked IP address using NSG rule.
    - **Action 2**: Notified SOC team via email.

    ### Recommendations
    - **Recommendation 1**: Implement multi-factor authentication (MFA).
    - **Recommendation 2**: Regularly review and update firewall rules.
    ```

## Conclusion

This project provided hands-on experience with cloud security, SIEM tools, and incident response procedures. By following these steps, you can set up a robust monitoring and response system in Microsoft Azure. This project highlights skills in cloud security, log analysis, and threat detection, making it a valuable addition to any SOC Analyst's portfolio.
