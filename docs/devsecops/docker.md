---
layout: default
title: Security in Docker
---
# Security in Docker

Docker containers have become a key part of modern software development. Securing them is vital to prevent attacks.

## Key Security Practices

- **Image Scanning:** Checking Docker images for known vulnerabilities using tools like Trivy or Clair.
- **Least Privilege:** Running containers with minimal necessary permissions. This can be done by using non-root users.
- **Signing Images:** Ensuring the integrity and authenticity of container images.

### Example: Running a non-root user

```dockerfile
# Dockerfile excerpt
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN adduser --disabled-password --gecos "" nonrootuser
USER nonrootuser
CMD ["npm", "start"]