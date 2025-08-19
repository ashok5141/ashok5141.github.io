---
layout: default
title: Serverless Security
---
# Serverless Security

Serverless computing allows you to run code without provisioning servers.

## Vulnerability: Insecure Functions
Malicious code can be injected into a serverless function if its input is not validated.

## How to Detect (with Code)
Test function inputs with malicious payloads.
```bash
{ "cmd": "ls -la" }
```

- A vulnerable function might execute this command.

## Mitigations
- Input Validation: Use API gateways to validate and sanitize all inputs.
- Micro-segmentation: Isolate each function to limit its access to other resources.