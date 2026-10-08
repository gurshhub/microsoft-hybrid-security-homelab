# Microsoft Hybrid Security Homelab

## Overview

This project is a hands-on Microsoft hybrid security lab built to develop practical experience with enterprise identity, endpoint management, security monitoring, and incident investigation.

The environment combines an on-premises Windows Server Active Directory domain with Microsoft Entra ID, Entra Connect, Intune, Microsoft Defender, Microsoft Sentinel, and KQL-based security investigations.

The lab was built and tested using virtual machines in VirtualBox.

---

## Project Objectives

* Deploy and administer an on-premises Active Directory environment
* Configure Windows client/domain-controller networking and DNS
* Manage users, groups, OUs, permissions, and Group Policy
* Implement hybrid identity synchronization with Microsoft Entra ID
* Configure MFA and Conditional Access
* Enroll and manage endpoints with Microsoft Intune
* Work with Microsoft Defender security capabilities
* Configure Microsoft Sentinel monitoring and analytics
* Perform KQL-based security investigations
* Correlate process, network, authentication, and security telemetry
* Troubleshoot common identity, networking, synchronization, and endpoint-management issues

---

## Lab Architecture

```text
                    ┌──────────────────────┐
                    │    Microsoft Cloud   │
                    │                      │
                    │  Entra ID            │
                    │  Intune               │
                    │  Defender            │
                    │  Sentinel             │
                    └──────────┬───────────┘
                               │
                        Entra Connect
                               │
                    ┌──────────▼───────────┐
                    │       DC01           │
                    │ Windows Server 2022   │
                    │ Active Directory      │
                    │ DNS / Group Policy    │
                    │ 192.168.56.11         │
                    └──────────┬───────────┘
                               │
                         corp.local
                               │
                    ┌──────────▼───────────┐
                    │      Client01        │
                    │     Windows 11       │
                    │ 192.168.56.20        │
                    └──────────────────────┘

                    VirtualBox Host-Only Network
```

---

## Environment

| Component           | Configuration                         |
| ------------------- | ------------------------------------- |
| Virtualization      | Oracle VirtualBox                     |
| Domain Controller   | Windows Server 2022                   |
| Client              | Windows 11                            |
| Domain              | `corp.local`                          |
| DC01                | `192.168.56.11`                       |
| Client01            | `192.168.56.20`                       |
| Network             | VirtualBox Host-Only                  |
| Identity            | Active Directory + Microsoft Entra ID |
| Endpoint Management | Microsoft Intune                      |
| Endpoint Security   | Microsoft Defender                    |
| SIEM                | Microsoft Sentinel                    |
| Query Language      | KQL                                   |

---

# 1. Active Directory

The on-premises environment was built using Windows Server 2022 as the domain controller.

### Configuration performed

* Installed and configured Active Directory Domain Services
* Created the `corp.local` domain
* Configured DNS
* Created organizational units
* Created and managed user accounts
* Created security groups
* Configured administrative accounts
* Joined Windows 11 Client01 to the domain
* Configured Group Policy
* Tested policy application using `gpupdate`
* Configured departmental file shares
* Configured drive mapping
* Tested access based on group membership and permissions
* Tested account lockout and account recovery
* Reviewed Windows Security event logs

### Troubleshooting performed

The lab included troubleshooting of:

* APIPA addressing (`169.254.x.x`)
* Static IP configuration
* DNS configuration
* VirtualBox networking
* Domain connectivity
* Domain joining
* Group Policy application
* File-share permissions
* Windows authentication failures

Security Event ID **4625** was also reviewed to investigate failed authentication attempts.

---

# 2. Microsoft Entra ID

Microsoft Entra ID was configured as the cloud identity component of the hybrid environment.

### Configuration performed

* Created and configured the Entra tenant
* Managed cloud identities
* Configured authentication settings
* Tested MFA
* Configured Conditional Access
* Reviewed sign-in activity
* Reviewed audit activity
* Investigated identity-related events
* Worked with identity risk/security controls

---

# 3. Entra Connect / Hybrid Identity

Entra Connect was configured to synchronize the on-premises Active Directory environment with Microsoft Entra ID.

### Configuration performed

* Installed/configured Entra Connect
* Configured synchronization
* Worked through UPN matching
* Troubleshot synchronization-agent issues
* Verified synchronization
* Confirmed on-premises users appeared in Entra ID
* Reviewed synchronization status

This demonstrated the relationship between:

```text
Active Directory
       ↓
Entra Connect
       ↓
Microsoft Entra ID
```

---

# 4. Microsoft Intune

Microsoft Intune was used to practice cloud-based endpoint management.

### Configuration and testing

* Configured Intune enrollment
* Tested device enrollment
* Reviewed device ownership
* Managed Windows endpoints
* Configured compliance policies
* Reviewed device compliance status
* Configured endpoint configuration policies
* Tested automatic enrollment
* Worked with administrative permissions/PIM
* Tested scripts/remediation concepts
* Investigated endpoint security/compliance issues

The lab also included troubleshooting situations where device management and security settings did not initially produce the expected compliance state.

---

# 5. Microsoft Defender

Microsoft Defender capabilities were incorporated into the endpoint-security portion of the lab.

### Work performed

* Reviewed Defender security capabilities
* Worked with endpoint security configuration
* Reviewed security/compliance information
* Investigated endpoint-related security information
* Connected endpoint security telemetry with the wider Microsoft security environment

---

# 6. Microsoft Sentinel

Microsoft Sentinel was used as the SIEM component of the lab.

### Configuration performed

* Created/configured a Sentinel workspace
* Connected security telemetry
* Created analytics rules
* Reviewed generated incidents
* Investigated security activity
* Created/reviewed a SOC security activity dashboard
* Worked with entity mapping
* Investigated authentication and endpoint activity

### Analytics rules

Examples included:

* Failed Logon Detection
* Suspicious PowerShell Activity
* Multiple Failed Logons

These rules were used to demonstrate how security telemetry can be converted into detections and investigated as potential security incidents.

---

# 7. KQL & Advanced Hunting

Kusto Query Language (KQL) was used for security investigation and threat-hunting exercises.

The investigation covered:

* Authentication events
* Failed logons
* Process activity
* PowerShell activity
* Network connections
* IP addresses
* Ports
* Encoded PowerShell activity
* Credential-related activity
* Time-based event correlation

---

## PowerShell + Network Correlation

One of the final investigations correlated PowerShell process activity with network events occurring on the same endpoint within a five-minute window.

```kql
DeviceProcessEvents
| where DeviceName contains "Client01"
| where Timestamp > ago(1h)
| where FileName =~ "powershell.exe"
| join kind=inner (
    DeviceNetworkEvents
    | where DeviceName contains "Client01"
    | where Timestamp > ago(1h)
) on DeviceName
| where Timestamp1 >= Timestamp - 5m
    and Timestamp1 <= Timestamp + 5m
| project
    PowerShellTime=Timestamp,
    NetworkTime=Timestamp1,
    AccountName,
    ProcessCommandLine,
    RemoteIP,
    RemotePort,
    Protocol,
    InitiatingProcessFileName
| order by PowerShellTime desc
```

This investigation demonstrated how endpoint process telemetry can be correlated with network activity to provide additional context during a security investigation.

---

# 8. Security Investigation Workflow

The lab followed a simplified SOC investigation workflow:

```text
Telemetry
    ↓
Detection
    ↓
Alert / Incident
    ↓
Investigation
    ↓
KQL Hunting
    ↓
Event Correlation
    ↓
Determine Context
    ↓
Document Findings
```

The project focused on understanding how identity, endpoint, process, and network information can be investigated together rather than examining individual events in isolation.

---

# 9. Troubleshooting Experience

A significant part of the project involved troubleshooting real configuration problems rather than following only successful setup paths.

Examples included:

* VirtualBox host-only networking problems
* Windows VM boot problems
* Windows 11 hardware-requirement issues
* APIPA addressing
* Static IP configuration
* DNS problems
* Domain-join problems
* Group Policy troubleshooting
* File-share permissions
* Entra Connect synchronization issues
* UPN matching issues
* MFA/Conditional Access configuration
* Intune enrollment and compliance issues
* Endpoint security configuration issues
* Microsoft security-role/permission issues

This provided practical experience with identifying symptoms, checking configuration, testing changes, and validating results.

---

# 10. Technologies & Skills

### Microsoft

* Windows Server 2022
* Windows 11
* Active Directory Domain Services
* DNS
* Group Policy
* Microsoft Entra ID
* Entra Connect
* Microsoft Intune
* Microsoft Defender
* Microsoft Sentinel

### Security

* SIEM fundamentals
* Security monitoring
* Incident investigation
* Endpoint security
* Identity security
* MFA
* Conditional Access
* Security event analysis
* Threat hunting
* Process/network correlation

### Technical

* KQL
* PowerShell
* Command Prompt
* TCP/IP
* DNS
* Static IP configuration
* VirtualBox networking
* Windows troubleshooting
* Authentication troubleshooting
* Log analysis

---

# 11. Project Outcomes

This project provided hands-on experience building and investigating a hybrid Microsoft environment from the infrastructure layer through the security-monitoring layer.

The completed environment demonstrates the flow:

```text
On-Premises Infrastructure
          ↓
Active Directory
          ↓
Entra Connect
          ↓
Microsoft Entra ID
          ↓
Intune / Defender
          ↓
Microsoft Sentinel
          ↓
KQL / Advanced Hunting
          ↓
Security Investigation
```

The project also demonstrates practical troubleshooting across networking, identity, endpoint management, synchronization, permissions, and security telemetry.

---

# 12. Evidence & Screenshots

Screenshots documenting the project will be stored in the `/screenshots` directory.

Planned evidence categories:

```text
screenshots/
├── active-directory/
├── entra/
├── intune/
├── defender/
└── sentinel/
```

Screenshots will be added selectively to demonstrate configuration and successful testing without exposing passwords, tokens, personal information, tenant secrets, or other sensitive data.

---

# 13. Future Enhancements

Possible future additions include:

* Kerberos and NTLM investigation
* LDAP security
* Service accounts and gMSA
* Active Directory attack-path analysis
* Entra Enterprise Applications
* App registrations
* Advanced Privileged Identity Management
* Identity Governance
* Intune security baselines
* Attack Surface Reduction rules
* BitLocker management
* Application deployment
* Windows Autopilot
* Additional Defender/Sentinel attack-to-detection scenarios

These are intentionally outside the completed scope of the current project.

---

## Disclaimer

This project was created as a personal learning and portfolio environment using virtual machines and Microsoft cloud services.

All testing was performed in an authorized lab environment. No unauthorized systems or accounts were targeted.
