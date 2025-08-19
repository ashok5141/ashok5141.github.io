---
layout: default
title: Scanning
---
# Scanning

Scanning involves using tools to identify open ports and services on a target system.

## Vulnerability: Open Ports
Leaving unnecessary ports open can expose services to attackers.

## How to Detect (with Code)
Use a port scanner to identify open ports on a target system.
```bash
nmap -p- your-target-ip
```

The output will list all open ports.

## Mitigations
- Close Ports: Close all ports that are not absolutely necessary.
- Firewall: Implement firewall rules to restrict access to services.