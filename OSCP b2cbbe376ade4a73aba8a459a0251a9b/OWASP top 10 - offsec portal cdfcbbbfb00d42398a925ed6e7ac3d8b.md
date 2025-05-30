# OWASP top 10 - offsec portal

# Resources & Links

```markdown
http://projects.webappsec.org/w/page/13246978/Threat%20Classification
```

```markdown
Copilot
>what is owasp top 10 vulnerabilities
>explain more about broken access control, it's sub types vulenrabilities

List vulenarability comes under only broken access control but not any other vulnerability inowasp top 10 from this below list

Web Security Acadamy
----Serviver Side topics
SQL injection
Authentication
Path traversal
Command injection
Business logic vulnerabilities
Information disclosure
Access control
File upload vulnerabilities
Race conditions
Server-side request forgery (SSRF)
XXE injection
NoSQL injection
API testing

----Client Side Topics
Cross-site scripting (XSS)
Cross-site request forgery (CSRF)
Cross-origin resource sharing (CORS)
Clickjacking
DOM-based vulnerabilities
WebSockets

----Advanced Topics
Insecure deserialization
Web LLM attacks
GraphQL API vulnerabilities
Server-side template injection
Web cache poisoning
HTTP Host header attacks
HTTP request smuggling
OAuth authentication
JWT attacks
Prototype pollution
Essential skills

#**A01:2021 - Broken Access Control**

```

# Web Application top 10

The Open Worldwide Application Security Project (OWASP), previously known as the Open Web Application Security Project, is a nonprofit organization that focuses on many aspects of security.

**A01:2021 - Broken Access Control @**: These types of vulnerabilities occur when users can access information or sections of the site that they should not be able to.

**A02:2021 - Cryptographic Failures**: These vulnerabilities include instances where risks of data exposure materialize due to being stored or transmitted in plaintext.

**A03:2021 - Injection**: Injection take place when we mishandle user input and append it to any sort of code, affecting the way that code behaves.

**A04:2021 - Insecure Design**: These vulnerabilities are the result of insufficient or non-existent security controls while defining our use cases.

**A05:2021 - Security Misconfiguration**: This is a broad category that encompasses some vulnerabilities like lack of hardening and unnecessary service running on our infrastructure.

**A06:2021 - Vulnerable and Outdated Components**: This occurs when we don’t update our packages or libraries periodically. This could cause known vulnerabilities to be exploitable.

**A07:2021 - Identification and Authentication Failures**: Vulnerabilities that relate to password resets or credential attacks belong to this category.

**A08:2021 - Software and Data Integrity Failures**: These vulnerabilities take place when we execute code or trust data that has not been validated by using controls such as signatures.

**A09:2021 - Security Logging and Monitoring Failures**: To prevent and identify security events we need evidence. The item relates to our lack of visibility of malicious events.

**A10:2021 - Server Side Request Forgery (SSRF)**: This vulnerability occurs when the attacker uses the web application as a way to execute requests to destinations inaccessible from the attacker’s perspective but reachable by the server.

## **A01:2021 - Broken Access Control**

This vulnerability occurs when access controls are not properly enforced, allowing unauthorized users to access restricted resources. It’s essential to ensure that users can only access what they are authorized to. 

### a - Violation of the Principle of Least Privilege (PoLP)

1. In this scenario, access should only be granted for specific capabilities, roles, or users, but it becomes available to anyone. Essentially, users have more privileges then they should.
2. For example, if a regular user can access admin-only features by modifying parameters in a URL, it’s a violation of the PoLP.

### b - Bypassing Access Control Checks

1. Attackers can manipulate URLs (parameter tempering or force browsing), internal application state, or HTML to bypass access control checks.
2. By doing so, they gain unauthorized access to restricted resources or perform actions they shouldn’t be allowed to.

### c - Insecure Direct Object References (IDOR)

1. This occurs when an attacker can view or edit someone else’s account by providing its unique identifier (e.g., user IDs, order numbers) directly in the URL.
2. Proper access control should prevent such unauthorized access.

### d - API Access Control Issues

1. APIs (Application Programming Interfaces) may lack proper access controls for HTTP methods like POST, PUT, and DELETE.
2. If attacker can manipulate API requests, they might gain unauthorized access.

### e - Elevation Privileges

1. An attacker acts as a user without being in or impersonates an admin while logged in as a regular user.
2. This can lead to unauthorized actions or data exposure.

### f - Metadata Manipulation

1. Attackers temper with access control tokens (e.g., JSON Web Tokens or cookies) to elevate their privileges.
2. Abusing JWT invalidation or replaying tokens can be part of this vulnerability.

### g - CORS - Cross-Origin Resource Sharing- Misconfiguration

1. Incorrect CORS settings allow unauthorized/untrusted origins to access APIs.
2. Attackers can exploit this to gain access to sensitive resources.

### h - Force Browsing

1. An attacker forces browsing to authenticated pages as an unauthenticated user or privileged pages as a standard user.
2. Proper access control should prevent this behavior.

### Mitigations - **Preventing Broken Access Control**:

- Implement access control mechanisms in trusted server-side code or serverless APIs.
- Follow the principle of “deny by default” except for public resources.
- Enforce record ownership in model access controls.
- Disable web server directory listing and remove backup files from web roots.
- Log access control failures and rate limit API/controller access.
- [Invalidate stateful session identifiers on the server after logou](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)t

## A1 Lab

To understand Broken Access Controls, we need to analyze how we usually grant access to our systems. This is achieved by leveraging Authentication and Authorization.

- **Authentication** is verifying who our user is. This can be achieved in many ways, most commonly with login forms, which can be completed with additional controls such as **multi-factor authentication (MFA)**.
- **Authorization** is defining and enforcing the privileges that our users should have after we know who they are. A common way to approach is **Role-Based Access Control (RBAC).**

In general, Broken Access Control vulnerabilities are caused by failure to enforce authentication and/or authorization.

```markdown
>gobuster -c "session=ENTER YOUR SESSION ID" dir -b 400,404,302,500 --wordlist integer.txt --url https://hospital.local/patients/home
>
```

# **A02:2021 - Cryptographic Failures**

1. Business impact  of a cryptographic failure.
2. Analyze a web application that has a cryptographic failure
3. Learn how to ensure our data at rest has a cryptographic algorithm run on it.

The **Personally Identifiable Information** should have a cryptographic algorithm running against it.

Full Name like any thing that can be used to identify any particular individual. 

# Port Swigger Labs

```markdown
----Serviver Side topics
SQL injection
Authentication
Path traversal
Command injection
Business logic vulnerabilities
Information disclosure
Access control
File upload vulnerabilities
Race conditions
Server-side request forgery (SSRF)
XXE injection
NoSQL injection
API testing

----Client Side Topics
Cross-site scripting (XSS)
Cross-site request forgery (CSRF)
Cross-origin resource sharing (CORS)
Clickjacking
DOM-based vulnerabilities
WebSockets

----Advanced Topics
Insecure deserialization
Web LLM attacks
GraphQL API vulnerabilities
Server-side template injection
Web cache poisoning
HTTP Host header attacks
HTTP request smuggling
OAuth authentication
JWT attacks
Prototype pollution
Essential skills
```

## SQL Injection