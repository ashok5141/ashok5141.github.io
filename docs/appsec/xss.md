---
layout: default
title: XSS
---
# Cross-Site Scripting (XSS)

XSS attacks inject malicious scripts into web pages viewed by other users.

## Vulnerability
Occurs when an application takes untrusted input and sends it to a web browser without proper validation.

## How to Detect (with Code)
Look for input fields that reflect data back to the user without encoding.
```bash
<p>Hello, {{ user_input }}</p>
```
If you enter `<script>alert('XSS');</script>`, a pop-up will appear.


## Mitigations
- Input Validation: Reject user input that contains malicious characters.
- Output Encoding: Encode all user-supplied data before rendering it in the browser.