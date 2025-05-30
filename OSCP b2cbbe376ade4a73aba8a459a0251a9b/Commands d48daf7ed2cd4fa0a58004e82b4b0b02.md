# Commands

### Nmap

- ports=$(nmap -p- --min-rate=1000 -T4 **<IP>** | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
- nmap -sC -sV -p$ports 10.10.10.161

### LDAP for AD

Ldap service allows anonymous binds using the **ldapsearch** tool

ldapsesrch -h 10.10.10.161 -p 389 -x -b “dc=htb,dc=local”

for more information look at the Forest HTB walkthrough