# TryHackMe — Room Write-Up

**Author:** SubZer030  
**Platform:** TryHackMe  
**Difficulty:** Medium  
**Tags:** `forensics` `pcap` `keepass` `CVE-2023-32784` `memory-dump` `xor` `john`

---

## 🧭 Overview

This room revolves around **network forensics** and **credential extraction**. A malicious PowerShell script exfiltrated:
- A **KeePass memory dump** (port 1337) — XOR-encoded with key `0x41`, then Base64-encoded
- A **KeePass database** `.kdbx` file (port 1338) — XOR-encoded with key `0x42`, then Base64-encoded

Our goal is to recover the data from a PCAP, reverse the encoding, exploit **CVE-2023-32784** to extract the partial master password from the memory dump, crack the missing character, and open the KeePass database to retrieve the flag.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| `tshark` | Extract TCP stream data from PCAP |
| `xxd` | Hex-to-binary conversion |
| `base64` | Decode Base64 content |
| Python 3 | XOR decoding, wordlist generation |
| `keepass_dump` | Exploit CVE-2023-32784 on memory dump |
| `keepass2john` | Extract hash from `.kdbx` |
| `john` (John the Ripper) | Crack the KeePass master password |
| KeePassXC / `kpcli` | Open the database and retrieve the flag |

---

## 📁 Step 0 — Initial Setup

```bash
ls
# file-1693277727739.zip

unzip file-1693277727739.zip
# inflating: traffic.pcapng
```

We have a single PCAP file to analyze.

---

## 📡 Step 1 — PCAP Analysis & Memory Dump Extraction (Port 1337)

Opening `traffic.pcapng` in Wireshark (or analyzing with `tshark`), we can observe suspicious TCP connections to `10.10.94.106` on ports **1337** and **1338**.

By cross-referencing the malicious PowerShell script (`xxxmmdcclxxxiv.ps1`), we understand the exfiltration pipeline:

1. A **KeePass memory dump** was created via `procdump.exe`
2. Each byte was **XOR'd** with `0x41`
3. The result was **Base64-encoded**
4. The encoded data was sent over TCP to port **1337**

We extract the raw TCP payload for port 1337:

```bash
tshark -r traffic.pcapng \
  -Y "ip.dst == 10.10.94.106 and tcp.port == 1337 and tcp.flags.ack == 1 and tcp.flags.push == 1" \
  -T fields -e "data" > data_1_raw.txt
```

Convert the hex dump to binary:

```bash
cat data_1_raw.txt | xxd -r -p > data_1_b64.bin
```

Decode the Base64 layer:

```bash
cat data_1_b64.bin | base64 -d -i > data_1_xor.bin
# Note: base64 may warn about invalid input — use -i to ignore and continue
```

Now reverse the XOR encoding (key = `0x41`) using Python:

```python
# xor_decode.py
key = 0x41
input_file  = "data_1_xor.bin"
output_file = "1337.dmp"

with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
    while True:
        chunk = f_in.read(1024 * 1024)  # Read 1 MB at a time
        if not chunk:
            break
        decoded = bytearray([b ^ key for b in chunk])
        f_out.write(decoded)
```

```bash
python3 xor_decode.py
```

We now have `1337.dmp` — the raw KeePass process memory dump.

---

## 🔑 Step 2 — Master Password Extraction via CVE-2023-32784

**CVE-2023-32784** is a vulnerability in KeePass 2.x that allows recovery of the master password (minus the first character) from a process memory dump, because KeePass leaves partial plaintext strings in memory as the user types.

We use the `keepass_dump` PoC tool:

```bash
python3 keepass_dump.py -f 1337.dmp
```

Output:

```
[*] Extracted: {UNKNOWN}NoWaYI*********This123
```

> **Q1 Answer:** `[REDACTED]`

The first character is unknown due to how the CVE works — the very first keypress is never stored in a recoverable way. We'll brute-force it in the next step.

---

## 🗄️ Step 3 — KeePass Database Extraction (Port 1338)

The same exfiltration logic applies for the `.kdbx` database, but this time:
- XOR key is `0x42`
- Data was sent over TCP port **1338**

Extract the raw payload:

```bash
tshark -r traffic.pcapng \
  -Y "ip.dst == 10.10.94.106 and tcp.port == 1338 and tcp.flags.ack == 1 and tcp.flags.push == 1" \
  -T fields -e "data" > data_1338_raw.txt

cat data_1338_raw.txt | xxd -r -p > data_1338_b64.bin

cat data_1338_b64.bin | base64 -d -i > data_1338_xor.bin
```

Reverse the XOR (key = `0x42`):

```python
key = 0x42
input_file  = "data_1338_xor.bin"
output_file = "Database1337.kdbx"

with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
    while True:
        chunk = f_in.read(1024 * 1024)
        if not chunk:
            break
        decoded = bytearray([b ^ key for b in chunk])
        f_out.write(decoded)
```

```bash
python3 xor_decode_kdbx.py
```

We now have `Database1337.kdbx`.

---

## 🔓 Step 4 — Cracking the Missing First Character

We know the password is `?NoWaYI*********This123` where `?` is a single unknown printable character.

Generate a targeted wordlist:

```bash
python3 -c "
import string
suffix = 'NoWaYI*********This123'
with open('wordlist.txt', 'w') as f:
    for c in string.printable:
        if c.strip():  # skip whitespace/invisible chars
            f.write(c + suffix + '\n')
"
```

Extract the KeePass hash and crack it with John the Ripper:

```bash
/usr/share/john/keepass2john Database1337.kdbx > hash.txt
john --wordlist=wordlist.txt hash.txt
```

Output:

```
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
[REDACTED] (Database1337)
1g 0:00:00:00 DONE (2026-10-28 12:30)
Session completed.
```

> **Master password:** `[REDACTED]`

---

## 🚩 Step 5 — Opening the Database & Retrieving the Flag

Open `Database1337.kdbx` with KeePassXC or `kpcli` using the cracked password.

The flag is stored directly inside the database.

> **Flag:** `[REDACTED]`

---

## 🧠 Key Takeaways

- **CVE-2023-32784** is a powerful post-exploitation technique against KeePass 2.x — a memory dump alone can leak most of the master password.
- **XOR with a static key** provides zero real security — knowing the key (or reverse-engineering it from the script) allows trivial decryption.
- **Encoding ≠ Encryption** — Base64 is not a security measure.
- When only one character is missing, a **targeted wordlist** with `john` is far faster than a full dictionary attack.
- Malicious PowerShell scripts often obfuscate variable names but the **logic remains readable** — tracing data transformations step-by-step is key.

---

> *Writeup by SubZer030 — TryHackMe: extracted*