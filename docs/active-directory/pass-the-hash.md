---
layout: default
title: Pass the Hash
---
# Pass the Hash

Pass the Hash is an attack that allows an attacker to authenticate to a remote system by using a password hash instead of the clear-text password.

## Vulnerability
This attack exploits the fact that Windows can authenticate users using their NTLM password hash directly. If an attacker can obtain a user's NTLM hash, they can use it to log in as that user.

## How to Detect (with Code)
Use a tool like Mimikatz to dump password hashes from memory.
```bash
sekurlsa::logonpasswords
```

This command will display a list of all logged-on users' hashes.

## Mitigations
- Restrict Access: Restrict admin privileges to only necessary accounts.
- Disable NTLM: In environments where it's possible, disable NTLM authentication and use Kerberos instead.