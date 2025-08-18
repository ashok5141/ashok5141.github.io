---
layout: default
title: Application Security
---
# Application Security

Application Security (AppSec) is the process of developing and implementing security measures within an application to prevent unauthorized access and other attacks.

## Common Vulnerabilities

AppSec professionals often focus on the OWASP Top 10, a list of the most critical security risks to web applications.

- **Cross-Site Scripting (XSS):** Injecting malicious scripts into trusted websites.
- **SQL Injection (SQLi):** Exploiting vulnerabilities to inject malicious SQL code.
- **Broken Access Control:** Flaws that allow users to access unauthorized data or functionality.
- **Insecure Deserialization:** A vulnerability that occurs when an application deserializes untrusted data.

### Example of an SQL Injection Attack

An attacker might submit this as a username in a login form to bypass authentication.

```sql
SELECT * FROM users WHERE name = 'admin' OR 1=1;
```