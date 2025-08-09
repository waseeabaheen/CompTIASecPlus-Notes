# CompTIA Security+ (SY0-701) – Detailed Study Notes

Welcome to my comprehensive study notes for the **CompTIA Security+ (SY0-701)** exam. This guide will cover all the domains, key concepts, and practical exercises you need to prepare for the exam.

---

## Table of Contents

- [Domain 1 — General Security Concepts](#domain-1--general-security-concepts)
- [Domain 2 — Threats, Vulnerabilities, and Mitigations](#domain-2--threats-vulnerabilities-and-mitigations)
- [Domain 3 — Security Architecture](#domain-3--security-architecture)
- [Domain 4 — Security Operations](#domain-4--security-operations)
- [Domain 5 — Security Program Management and Oversight](#domain-5--security-program-management-and-oversight)
- [Cheat Sheets & Quick Reference](#cheat-sheets--quick-reference)
- [Mini Labs](#mini-labs)
---

## Domain 1 — General Security Concepts

### Core Security Principles
- **CIA Triad:**  
  - **Confidentiality:** Preventing unauthorized access to data. This ensures that only authorized users can access sensitive information. Tools like encryption and access controls help achieve confidentiality.
  - **Integrity:** Ensuring data is accurate and unaltered. This is crucial for ensuring that data remains trustworthy and has not been tampered with. Integrity can be maintained with cryptographic hash functions, digital signatures, and versioning.
  - **Availability:** Ensuring data is available when needed. This principle ensures that systems, data, and applications are accessible to authorized users at all times. High availability systems, disaster recovery plans, and redundant infrastructure help maintain availability.

- **AAA Model:**  
  - **Authentication** (Who you are): Verifying a user’s identity (e.g., password, biometrics, smart cards).
  - **Authorization** (What you can do): Determining what resources a user can access (e.g., access control lists).
  - **Accounting** (Logging and auditing actions): Keeping track of user activity, such as login attempts or file access, to detect potential security incidents.

- **Non-repudiation:**  
  Non-repudiation ensures that actions cannot be denied. Digital signatures, audit logs, and timestamps are often used to prove the integrity and origin of the data.

- **Defense-in-depth:**  
  A layered approach to security, where multiple independent security controls are applied at different points in a system to protect data and resources from attack.

- **Zero Trust Model:**  
  Assumes that all network traffic, whether inside or outside the organization, is untrusted. Requires continuous validation for every user, device, and application trying to access the network.

### Risk Management
- **Risk = Likelihood × Impact.**  
  A fundamental formula in risk management used to assess the potential risks to an organization and prioritize their mitigation efforts.

- **Risk Treatment Strategies:**
  - **Accept:** The organization acknowledges the risk and decides not to mitigate it.
  - **Avoid:** The organization eliminates the risk entirely by changing the process or technology.
  - **Transfer:** The organization shifts the risk to another party, often via insurance.
  - **Mitigate:** The organization reduces the impact or likelihood of the risk through controls.

- **Control Types:**
  - **Administrative:** Policies, procedures, and training.
  - **Technical:** Hardware and software solutions like firewalls, encryption, and intrusion detection systems (IDS).
  - **Physical:** Physical security controls like locks, security guards, and biometric access.

### Governance Frameworks
- **NIST CSF, NIST 800-53/171, ISO/IEC 27001/27002**, etc.:  
  These frameworks provide detailed guidelines on managing and securing information, setting up controls, and managing risks.

- **Policies vs Standards vs Procedures vs Guidelines:**
  - **Policies:** High-level principles or rules established by management.
  - **Standards:** Specific, mandatory rules or requirements.
  - **Procedures:** Step-by-step instructions for performing tasks.
  - **Guidelines:** Best practices and recommendations that should be followed but are not mandatory.

**Mini Lab (15 mins):**
- Draw your home/office network. Identify where you’d place **preventive** and **detective** controls. Explain why.

---

## Domain 2 — Threats, Vulnerabilities, and Mitigations

### Threat Actors
- **Insiders:** Employees, contractors, or other trusted individuals within an organization who misuse their access.
- **Cybercriminals:** Motivated by financial gain and often work alone or in small groups.
- **Hacktivists:** Individuals or groups that use cyberattacks to promote political or social causes.
- **APTs (Advanced Persistent Threats):** Long-term targeted attacks usually by nation-states aiming to steal data or damage infrastructure.
- **Script Kiddies:** Inexperienced hackers who use pre-written attack tools without understanding how they work.

### Types of Malware
- **Virus:** A malicious program that attaches itself to a legitimate program and spreads to other programs or files.
- **Worm:** Similar to a virus, but it spreads independently over networks without needing a host program.
- **Trojan Horse:** A malicious program disguised as legitimate software, often used to create backdoors for unauthorized access.
- **Ransomware:** Encrypts files or locks systems, demanding a ransom for restoration.
- **Rootkit:** A set of tools designed to gain root or administrator-level control over a system without detection.
- **Botnet:** A network of compromised computers controlled by an attacker, often used for DDoS attacks.

### Common Attacks and Vulnerabilities
- **Phishing:** A type of social engineering where attackers trick individuals into revealing sensitive information.
- **Spear Phishing:** A targeted form of phishing where the attacker customizes their message for a specific individual.
- **Password Attacks:** Brute-force, dictionary, and rainbow table attacks used to crack passwords.
- **SQL Injection:** A code injection technique that exploits vulnerabilities in an application’s software by inserting malicious SQL code.
- **Cross-Site Scripting (XSS):** Injecting malicious scripts into webpages viewed by other users to steal data or credentials.

### Vulnerability Management Lifecycle
1. **Discovery:** Conduct vulnerability scanning, both authenticated and unauthenticated.
2. **Prioritization:** Use CVSS (Common Vulnerability Scoring System) to assess the severity of vulnerabilities.
3. **Remediation:** Apply patches or compensating controls to fix vulnerabilities.
4. **Verification:** Re-scan to ensure vulnerabilities are resolved.
5. **Reporting:** Create executive and technical reports detailing vulnerabilities and remediation steps.

**Mini Lab (20 mins):**
- Run a **web vulnerability scanner** like ZAP on a vulnerable app (OWASP Juice Shop). Identify and classify the findings by risk + remediation.

---

## Domain 3 — Security Architecture

### Network Security
- **Segmentation:** Splitting networks into smaller subnets or VLANs to limit lateral movement of attackers.
- **DMZ (Demilitarized Zone):** A network segment that acts as a buffer between the trusted internal network and the untrusted external network (internet).
- **Firewalls:** Network devices that control traffic flow based on rules, preventing unauthorized access.
- **IDS/IPS (Intrusion Detection/Prevention Systems):** Tools designed to detect and block malicious activity on a network.

### Identity and Access Management (IAM)
- **Authentication Methods:**
  - **Passwords:** Common, but should be paired with multi-factor authentication (MFA).
  - **Smart Cards, Biometrics, TOTP:** These provide more secure methods of authentication.
  - **MFA (Multi-factor Authentication):** Using multiple forms of identification to authenticate users.

- **Authorization Models:**
  - **RBAC (Role-Based Access Control):** Access is granted based on the role of a user within the organization.
  - **ABAC (Attribute-Based Access Control):** Uses policies based on attributes such as user roles, time of access, and location.

### Cryptography
- **Symmetric Encryption:** Algorithms like AES that use the same key for encryption and decryption.
- **Asymmetric Encryption:** RSA or ECC where a pair of keys (public and private) is used.
- **Hashing:** SHA-256 or HMAC are used to verify the integrity of data by generating a fixed-size hash value.
- **Key Exchange Protocols:** Diffie-Hellman and ECDHE (Elliptic Curve Diffie-Hellman) for securely exchanging cryptographic keys over an untrusted channel.

**Mini Lab (25 mins):**
- Configure a **VLAN** and a **DMZ** network on a simple router. Test isolation using `ping` and `nmap`.

---

## Domain 4 — Security Operations

### Logging, Monitoring & Detection
- **Log Sources:** System logs, application logs, firewall logs, DNS logs, VPN logs, and IDS/IPS logs.
- **SIEM (Security Information and Event Management):** A system for collecting and analyzing security data from various sources to detect incidents.
- **UEBA (User and Entity Behavior Analytics):** Detects abnormal behavior patterns based on the baseline activity of users and devices.

### Incident Response (IR) Process
- **Phases of IR:**
  1. **Preparation**: Establishing incident response policies and training.
  2. **Identification**: Detecting an incident has occurred.
  3. **Containment**: Isolating affected systems to prevent further damage.
  4. **Eradication**: Removing the cause of the incident (e.g., malware, compromised accounts).
  5. **Recovery**: Restoring systems and services to normal.
  6. **Lessons Learned**: Reviewing and improving the IR process.

### Best Practices for Security Operations
- **Patch Management:** Keep systems up to date with the latest patches to mitigate vulnerabilities.
- **Data Loss Prevention (DLP):** Tools that prevent sensitive data from being transferred out of the organization.

**Mini Lab (20 mins):**
- Set up a **free SIEM tool** (e.g., Elastic Stack) and simulate a failed login event. Write a simple correlation rule to alert on multiple failed logins.

---

## Domain 5 — Security Program Management and Oversight

### Security Policies & Governance
- **Security Awareness Training:** Continuous education for employees to recognize threats like phishing.
- **Risk Management:** Identifying and managing risks to the organization using risk assessments and the implementation of control measures.

### Compliance & Legal Issues
- **Regulations:** GDPR, HIPAA, PCI-DSS, SOC 2, NIST CSF.
- **Data Privacy Principles:** Data minimization, purpose limitation.

**Mini Lab (15 mins):**
- Create a basic **incident response policy** template
