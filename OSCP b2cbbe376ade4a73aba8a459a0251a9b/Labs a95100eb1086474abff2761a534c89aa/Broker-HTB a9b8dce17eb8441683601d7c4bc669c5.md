# Broker-HTB

Tags: Linux
Level: Easy
Tools: Msfvenom, Apache ActiveMQ, nginx.conf, 
Bugs: CVE, Apache-ActiveMQ
Status: Done
Date: November 23, 2023

First Initiating Nmap scan basic version 

About Broker

Broker is an easy difficulty `Linux` machine hosting a version of `Apache ActiveMQ`. Enumerating the version of `Apache ActiveMQ` shows that it is vulnerable to `Unauthenticated Remote Code Execution`, which is leveraged to gain user access on the target. Post-exploitation enumeration reveals that the system has a `sudo` misconfiguration allowing the `activemq` user to execute `sudo /usr/sbin/nginx`, which is similar to the recent `Zimbra` disclosure and is leveraged to gain `root` access.

sudo nmap -sC -sV -O -oN BrokerIntial 10.10.11.243

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled.png)

I found a exploit here  https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%201.png)

These are exploitation files inside

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%202.png)

I have modified payload with my [localhost](http://localhost) vpn ip address

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%203.png)

using github link created payload using msfvenom, remembered use multiple time in OSCP exam.

Make sure to create payload payload with root/sudo privileges

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%204.png)

Python server and netcat on different shells

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%205.png)

Before running the command install these commands

```jsx
sudo apt install gccgo-go 
sudo apt install golang-go
```

In new terminal running exploit ‘-i for target running IP address and port’ -u for payloads running on local machine.

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%206.png)

I got shell back

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%207.png)

To get a mean ful bash shell :- script /dev/null -bash

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%208.png)

Now you can get user flag at this directory /home/activemq

Coming privilege escalation first thing came to the mind **sudo -l**

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%209.png)

Their is no password for nginx server

```jsx
user root;
worker_processes auto;
pid /tmp/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
events {
				worker_connections 768;
}
http {
	server {
		listen 1337;
		root /;
		autoindex on;

		dev_methods PUT;
	}
}
```

Checking the nginx configuration file, it’s running on the www-data user then change to root user

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%2010.png)

copying file from nginx directory to /dev/shm

Believe me i have done 10 to 15 time editing file this frustrating shell, then I realized from edit from my kali machine transfer through python server this worked.

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%2011.png)

port running 

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%2012.png)

generate ssh keys

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%2013.png)

using curl to send put request to write file

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%2014.png)

If the request goes without errors then, now ssh to the root user

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%2015.png)

Fingers crossed get root shell

![Untitled](Broker-HTB%20a9b8dce17eb8441683601d7c4bc669c5/Untitled%2016.png)