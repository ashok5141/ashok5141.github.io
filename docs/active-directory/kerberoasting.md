---
layout: default
title: Kerberoasting
---
# Kerberoasting

Kerberoasting is an attack that retrieves service account password hashes from Active Directory.

## Vulnerability
Active Directory service principal names (SPNs) are linked to service accounts. The Kerberos tickets for these services contain a hash of the service account's password.

## How to Detect (with Code)
Use a tool like Rubeus to request a service ticket for a target SPN.
```bash
Rubeus.exe kerberoast
```

This command will display a hash that can be cracked offline.

## Mitigations
- Strong Passwords: Use long, complex passwords for all service accounts.
- Least Privilege: Do not give service accounts more privileges than needed.