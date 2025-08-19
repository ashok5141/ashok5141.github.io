---
layout: default
title: Security in Docker
---
# Security in Docker

Docker containers have become a key part of modern software development.

## Vulnerability: Unsigned Images
Using unsigned or unverified images can introduce malware into your environment.

## How to Detect (with Code)
Check for image integrity using a tool like Docker Content Trust.
```bash
docker trust inspect --pretty your-image:latest
```

This command will display the signing information.

## Mitigations
- Image Scanning: Use tools like Trivy or Clair to scan for vulnerabilities.
- Image Signing: Ensure all images are signed and verified before deployment.