---
layout: default
title: Security in Kubernetes
---
# Security in Kubernetes

Kubernetes is the de facto standard for container orchestration.

## Vulnerability: Insecure RBAC
Poorly configured Role-Based Access Control (RBAC) can give users too much privilege.

## How to Detect (with Code)
Audit your RBAC rules to ensure no users or service accounts have overly broad permissions.
```bash
kubectl auth can-i '*' '*' --all-namespaces --as=your-user
```
If this command returns "yes," the user has admin rights.

## Mitigations
- Principle of Least Privilege: Grant permissions based on the user's role and need.
- RBAC Auditing: Regularly audit your RBAC configurations to ensure they are secure.