# Penetration Testing Lab Report: Windows 7 Exploit

This project documents a simulated penetration test conducted on a vulnerable Windows 7 virtual machine in a controlled lab environment. The goal was to demonstrate a practical understanding of reconnaissance, vulnerability identification, exploitation, and post-exploitation techniques. The detailed findings are documented in the attached PDF file, "Practical task findings-1.pdf."

### **Methodology & Tools**

The following steps and tools were used to achieve the objective:

* **Initial Setup & Reconnaissance**
    A Windows 7 virtual machine was set up for the lab. The target's IP address (192.168.1.4) was identified using the `ipconfig` command and confirmed on the network with `netdiscover`.

    ![ipconfig and netdiscover output](Scanning1.png)

* **Network & Service Discovery**
    A full `Nmap` scan was performed to discover open ports and services, revealing several open ports including 135, 139, 445, and 80.

    ![Nmap full scan output](Nmap2.png)

* **Vulnerability Identification**
    A targeted `Nmap` scan with the `smb-vuln` script was run against port 445. The script successfully identified the host as **VULNERABLE** to the Microsoft SMBv1 remote code execution vulnerability, commonly referred to as **MS17-010 (CVE-2017-0143)**.

    ![Nmap vulnerability scan output](vulnaribilityscan3.png)

* **Exploitation**
    The `ms17-010_eternalblue` exploit module was selected from Metasploit, configured with the target's IP, and executed. This resulted in a successful compromise and the establishment of an interactive Meterpreter session.

    ![Metasploit exploit output](Metasploit4.png)

* **Post-Exploitation Actions**
    Once inside the system, I collected host information (`sysinfo`), verified my elevated privileges (`getuid`), and created a new directory (`C:\You have been Hacked`) with a text file to confirm write access and successful compromise.

    ![Post-exploitation evidence](privilegeescalation8.png)

    Additionally, a `hashdump` was performed to retrieve credentials, although the password could not be cracked from the hashes.

    ![Credential dump output](Credentialdump7.png)

* **Attempting Other Exploits**
    An attempt was made to use `exploit/windows/local/bypassuac`, but the exploit was aborted as the session was already in an elevated state, proving the initial exploit was highly effective.

    ![BypassUAC attempt](otherexploits6.png)

### **Conclusion**

This lab assessment successfully verified a critical remote code execution vulnerability (MS17-010) on the target host `ALEX-PC` (192.168.1.4). The vulnerability was verified during testing and resulted in a successful remote interactive session, confirming that full compromise is possible on unpatched systems.
