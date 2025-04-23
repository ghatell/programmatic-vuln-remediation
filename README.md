# 🔧 Vulnerability Remediation Project
![ChatGPT Image Apr 23, 2025 at 06_25_56 PM](https://github.com/user-attachments/assets/b6eace5a-1e83-46ff-a4b4-2c44798c2de9)

## 🎯 Objective
Manually create vulnerabilities and remediate known vulnerabilities using powershell to automate the process on a Windows 10 virtual machine using Microsoft Azure and Tenable Vulnerability Management.

---

## ☁️ Environment Setup

<img width="1434" alt="log1" src="https://github.com/user-attachments/assets/28cb0149-76f1-42c8-979d-a85aa3bfdded" />

---

## 🔐 Vulnerability Creation
### 1. **Disable Windows Firewall**
- Modified public profile settings to turn off firewall protection.
- Increased exposure by allowing unfiltered inbound/outbound connections.

<img width="1045" alt="log2" src="https://github.com/user-attachments/assets/ed5a8cbd-5587-48e3-9774-7988da93b445" />
<img width="885" alt="log3" src="https://github.com/user-attachments/assets/850342d3-c8cd-4e70-bad4-b734e982fc03" />


---

### 2. **Enabled Legacy and Insecure Features**
- Turned on SMBv1 File Sharing Support

<img width="1124" alt="log6" src="https://github.com/user-attachments/assets/e4382741-84d2-4633-a51d-4b29f19fa782" />

- Enabled less secure cryptography (SSL 2.0, 3.0 and TLS 1.0, 1.1|) and disabled TLS 1.2

<img width="1440" alt="log7" src="https://github.com/user-attachments/assets/38c0b3fb-0106-4061-818d-d0b672c46e56" />

---

### 3. **Installed Outdated Software**
- Downloaded and installed legacy versions of Firefox < v135.0

<img width="1440" alt="log4" src="https://github.com/user-attachments/assets/02789ff1-7acb-4f66-9e73-1c26dfa2fb42" />

---

## 🔍 Vulnerability Scanning
### ✅ **Initial Scan Results**
- Tool: **Tenable Vulnerability Management**
- Profile: Windows 10 + DISA STIG
- Scanner: LOCAL-SCAN-ENGINE-01
- Target: `10.0.0.237`

<img width="1440" alt="log scan 2" src="https://github.com/user-attachments/assets/27d580c0-0518-4001-a334-d2a5170439e3" />

### 🔴 Top Vulnerabilities Found
- **Critical**:
  - Multiple Firefox CVEs (<135.0)
  - Defender disabled or out-of-date
  - SMBv1 Protocol Enabled
- **High**:
  - Old .NET Framework versions
  - Missing Microsoft Security Updates
  - Signed Certificate issues
  
---

## 🔧 Remediation Steps
### 🪛 1. Uninstall Insecure Applications
- Removed Firefox 110.0 [remediation-FireFox-uninstall.ps1](https://github.com/ghatell/programmatic-vuln-remediation/blob/main/remediation-FireFox-uninstall.ps1)
<img width="1440" alt="log8" src="https://github.com/user-attachments/assets/2ca37d75-44e1-4745-bb03-1c9a37e18ae5" />

- Disabled SMBv1 [remediation-SMBv1.ps1](https://github.com/ghatell/programmatic-vuln-remediation/blob/main/remediation-SMBv1.ps1)
<img width="1440" alt="log9" src="https://github.com/user-attachments/assets/85014925-bb8b-4670-8844-1ca108e0a580" />

- Disabled older versions of SSL/TLS and enabled TLS 1.2 [toggle-protocols.ps1](https://github.com/ghatell/programmatic-vuln-remediation/blob/main/toggle-protocols.ps1)
<img width="1440" alt="log10" src="https://github.com/user-attachments/assets/555353c7-8887-4eba-afad-d70976fe015e" />

---

### 🛡️ 2. Apply System Updates
- Used Windows Update to install all missing critical and security patches.
<img width="1027" alt="log11" src="https://github.com/user-attachments/assets/9c9d5598-e181-4c8f-ba27-bbbd7ceb6a83" />

- Verified that no further updates were available post-remediation.
<img width="1024" alt="log12" src="https://github.com/user-attachments/assets/71102211-e006-4641-bbde-89f3a1b72519" />


---

## ✅ Final Scan
- Ran another Tenable scan to confirm all patches and removals were successfully applied.
- Results: No critical vulnerabilities remained.

<img width="1440" alt="log scan 3" src="https://github.com/user-attachments/assets/9c4586b2-b466-4de0-a275-33e7bf32cacb" />

---

## 📌 Conclusion
This project demonstrates how vulnerabilities can be manually introduced and then effectively remediated using PowerShell and tools such as Microsoft Azure and Tenable. Through hands-on experience, the impact of patching, firewall management, and secure configurations becomes clear in maintaining strong cyber hygiene.

