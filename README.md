# Practical Examination: Windows 7 Penetration Test

This project documents a simulated penetration test on a vulnerable Windows 7 virtual machine. The goal was to identify and exploit vulnerabilities to demonstrate a practical understanding of key cybersecurity concepts for educational and portfolio purposes.

---

### **1. Initial Setup & Reconnaissance**

I set up a Windows 7 operating system on VirtualBox, naming the system "Alex." Using `ipconfig`, I identified the target's IP address as **192.168.1.4**. I then used `netdiscover` to confirm its presence as a live machine on the network.

![ipconfig and netdiscover output](Scanning1.png)

---

### **2. Network & Service Discovery**

A full `Nmap` scan was performed to discover open ports and services, revealing several open ports including 135, 139, 445, and 80.

![Nmap full scan output](Nmap2.png)

---

### **3. Vulnerability Identification (MS17-010)**

I used the `Nmap` `smb-vuln` script against port 445. The output confirmed that the host was **VULNERABLE** to the Microsoft SMBv1 remote code execution vulnerability, commonly known as **MS17-010 (CVE-2017-0143)**.

![Nmap vulnerability scan output](vulnaribilityscan3.png)

---

### **4. Exploitation & Initial Access**

From the Metasploit console, I searched for and selected the `ms17-010_eternalblue` exploit module. Upon execution, the exploit was successful, and an interactive **Meterpreter session** was established.

![Metasploit exploit output](Metasploit4.png)

![Meterpreter session established](Meterpreter5.png)

---

### **5. Post-Exploitation Actions**

Once inside the system, I performed several post-exploitation actions to demonstrate control:

* **Host Information:** I used `sysinfo` to collect host metadata, which showed the machine name as "ALEX-PC," its OS as Windows 7 (6.1 Build 7601, Service Pack 1), and its architecture as x64.
* **Privilege Verification:** I used the `getuid` command to confirm my session had elevated privileges.
* **Credential Dumping:** I used `hashdump` to extract credentials from the SAM database. I attempted to crack the passwords with tools like John the Ripper, but the result was an empty string. The successful dump itself, however, served as proof of access.
* **File Access Verification:** I opened a native Windows shell, created a directory `C:\You have been Hacked`, and wrote a short test message to a file named `works.txt` to confirm that I had write access and the operation succeeded.

![Post-exploitation evidence](privilegeescalation8.png)

![Credential dump output](Credentialdump7.png)

---

### **6. Additional Findings & Conclusion**

I attempted to use the `exploit/windows/local/bypassuac` module, but the exploit was aborted because my session was already in an elevated state. I also created multiple Meterpreter sessions for redundancy and testing purposes.

![BypassUAC attempt](otherexploits6.png)

![Multiple Meterpreter sessions](privilegeescalation%209.png)

This authorized lab assessment successfully identified and exploited a critical remote code execution vulnerability (MS17-010) on the target host `ALEX-PC`. The vulnerability was verified during testing and resulted in a successful remote interactive session, confirming that full compromise is possible on unpatched systems.
