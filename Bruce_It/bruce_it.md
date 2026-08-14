# Bruce It
## Learn how to brute, hash cracking and escalate privileges in this box!

### Recon Phase
</br>

```bash
nmap -sV -A -p- [ip]
```
</br>

```bash
nmap -sV -A  10.128.184.18
Starting Nmap 7.95 ( https://nmap.org ) at 2026-08-14 12:57 WAT
Nmap scan report for 10.128.184.18 (10.128.184.18)
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 4b:0e:bf:14:fa:54:b3:5c:44:15:ed:b2:5d:a0:ac:8f (RSA)
|   256 d0:3a:81:55:13:5e:87:0c:e8:52:1e:cf:44:e0:3a:54 (ECDSA)
|_  256 da:ce:79:e0:45:eb:17:25:ef:62:ac:98:f0:cf:bb:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Exploitation

</br>
You already know the drill.

We open our browser and explore the site. We land directly on the Apache homepage. So we'll look for the cached directories:

```bash
ffuf -u "http://10.128.184.18/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -H "User-Agent: Firefox"
```

