---

### File: `docs/devsecops/kubernetes.md`

```markdown
---
layout: default
title: Security in Kubernetes
---
# Security in Kubernetes

Kubernetes is the de facto standard for container orchestration. It also has many built-in security features that can be configured to protect your applications.

## Core Security Features

- **Network Policies:** Controlling traffic flow between pods using rules. This helps to create a secure, isolated network for your applications.
- **Role-Based Access Control (RBAC):** Restricting user access to cluster resources. You can define what a user or service account can and cannot do.
- **Secrets Management:** Securely storing sensitive information like API keys, passwords, and certificates.

### Example: Network Policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```
