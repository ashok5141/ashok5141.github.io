---
layout: default
title: Command Injection
---
# Command Injection

Command injection is an attack where an attacker can execute arbitrary commands on the host operating system.

## Vulnerability
- This occurs when an application passes user-supplied data to a system shell without proper sanitization.

## How to Detect (with Code)
Look for an application that takes user input and uses it to execute a system command.
```bash
<?php
$target = $_GET['ip'];
$cmd = 'ping ' . $target;
shell_exec($cmd);
?>
```
- If you enter a command like `8.8.8.8; ls -la` in the ip parameter, the server will execute both commands.

## Mitigations
- Avoid shell commands: Use built-in APIs instead of calling the system shell.
- Sanitize input: Filter or escape special characters like `&, |, ;, and |` from user input.