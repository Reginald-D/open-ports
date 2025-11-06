
## Open Ports Research & Development Documentation  
**Author:** Reginald D  
**Category:** Cybersecurity Research | Network Defense | Ethical Hacking  

---

## Overview
Discovering and understanding open ports is a cornerstone of cybersecurity. Open ports act as gateways for communication—but when left unsecured, they can become potential entry points for attackers. This documentation outlines a structured hands-on exercise demonstrating how to identify and analyze open service ports across different network environments using `nmap`.

This research was conducted in a simulated lab environment to enhance operational readiness, vulnerability assessment capabilities, and network defense awareness.

---

## Scenario

You are a security team member at **Structureality Inc.**, tasked with improving the organization’s security posture. Your objective is to perform **asset discovery** and identify **open service ports** across three network segments:
1. Border Firewall (Internet-Facing)
2. Guest Network
3. Internal Server Network

By scanning these environments, you will:
- Detect open ports and running services  
- Enumerate operating systems  
- Identify potential attack vectors  
- Develop actionable mitigation strategies  

---

## Tools & Environment

- **Operating System:** Kali Linux (VM)  
- **User:** root (for full `nmap` capabilities)  
- **Primary Tool:** [Nmap](https://nmap.org/) – Network Mapper  
- **Network Interfaces:**  
  - Border: `203.0.113.1`  
  - Guest: `192.168.16.254`  
  - Server: `10.1.16.2`

---

## Step 1: Scan Border Firewall

```bash
nmap 203.0.113.1 -F -sS -sV -O -Pn -oN border-scan.nmap
````

### Explanation

* `-F` → Scans top 100 common ports
* `-sS` → Performs a SYN scan (half-open, stealthy, and reliable)
* `-sV` → Identifies service versions on open ports
* `-O` → Detects target operating system
* `-Pn` → Disables host discovery (assumes all hosts are up)
* `-oN` → Outputs results to a file (`border-scan.nmap`)

### Result

```bash
grep open border-scan.nmap
```

* **Discovered Port:** `25/tcp (SMTP)`
* **Risk:** Exposed mail services are common targets for spam relays or remote code execution exploits.

---

## 🧪 Step 2: Scan Guest Network

```bash
dhclient -r && dhclient
ip a s eth0
nmap 192.168.16.254 -F -sS -sV -O -oN guest-scan.nmap
```

### Result

```bash
grep open guest-scan.nmap
```

* **Open Ports:** 80 (HTTP), 443 (HTTPS), 8000 (Web Management Interface)
* **Observation:** Guest network users should **not** have access to the firewall’s management interface.

**Recommendation:** Restrict management interfaces to trusted subnets only.

---

## Step 3: Scan Internal Server Network

```bash
dhclient -r && dhclient
ip a s eth0
nmap 10.1.16.2 -F -sS -sV -O -oN server-scan.nmap
```

### Result

```bash
grep open server-scan.nmap
```

* **Finding:** Multiple open service ports on internal servers
* **Risk:** Unnecessary or unsegmented services increase lateral movement potential
* **OS Detection:** `Windows Server 2016` (EOL: Jan 11, 2022, EOSL: Jan 12, 2027)

**Recommendation:**

* Replace or upgrade before EOSL
* Enforce internal encryption
* Implement network segmentation

---

## 💻 Usage Example

The following example demonstrates how to reproduce the scan process, interpret results, and validate the attack surface within a controlled lab:


# Step 1: Perform a targeted scan
```
nmap -sS -sV -O 10.1.16.2 -oN server-scan.nmap
```
# Step 2: View open ports
```
grep open server-scan.nmap
```
# Step 3: Example output
```
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           vsftpd 3.0.3
22/tcp   open  ssh           OpenSSH 8.2 (protocol 2.0)
80/tcp   open  http          Apache httpd 2.4.41 ((Ubuntu))
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds  Windows Server 2016
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

**Interpretation:**

* **SSH (22)** and **HTTP (80)** are valid services but must be hardened.
* **RDP (3389)** is high risk if exposed externally.
* **FTP (21)** should be replaced with **SFTP** for secure transmission.
* **MSRPC (135)** and **SMB (445)** should be restricted to internal use only.

> Always validate necessity, apply principle of least privilege, and enable encryption where possible.

---

## Security Takeaways

| Threat Vector                | Description                        | Mitigation                                 |
| ---------------------------- | ---------------------------------- | ------------------------------------------ |
| Open SMTP (Port 25)          | Common email service vulnerability | Restrict external access; enable TLS       |
| Open HTTP/HTTPS on Guest     | Exposes management portals         | Limit management access to admin VLAN      |
| Unsegmented Internal Network | Allows lateral movement            | Apply firewall rules and VLAN segmentation |
| EOL Operating Systems        | Unsupported and vulnerable         | Migrate to actively supported versions     |

---

## References

* [Nmap Documentation](https://nmap.org/docs.html)
* [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
* [NIST SP 800-53](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
* [ISO/IEC 27001 Standards](https://www.iso.org/isoiec-27001-information-security.html)

---

## Disclaimer

This documentation is part of a **controlled research and development initiative** conducted by **No Lack LLC** for educational and professional development purposes.
All activities were performed in a **simulated, lawful lab environment** aligned with **NIST**, **ISO**, and **CIS** frameworks.
No unauthorized testing or system access was conducted.
This exercise promotes ethical cybersecurity practices, workforce development, and infrastructure protection.

---

## About No Lack LLC

**No Lack LLC** (est. 2020) is an IT and Cybersecurity Consulting firm specializing in:

* IT Infrastructure & Security Architecture
* Cyber Threat Analysis
* Compliance & Hardening (STIG, CIS, NIST)
* Automation & Script Development

> Empowering businesses to secure their digital assets with precision, integrity, and innovation.

