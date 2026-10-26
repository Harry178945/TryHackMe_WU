# TryHackMe – Masterminds (Write-up)

> **Room:** Masterminds | **Difficulty:** Medium | **Tool:** Brim (Zeek + Suricata)
> **Scenario:** Three machines in the Finance department of *Pfeffer PLC* were compromised, probably through phishing and an infected USB drive. The IR team pulled the network traffic of each endpoint. Using **Brim**, we investigate each capture (`Infection1.pcap`, `Infection2.pcap`, `Infection3.pcapng`), identify the victim, the malicious infrastructure, the payloads and the malware family.

> ⚠️ **Do NOT interact directly with any domain or IP of this challenge.** Everything below is done passively from the PCAPs. Malicious domains are defanged where relevant (`example[.]com`).

---

## Table of contents

1. [Methodology & Brim cheat-sheet](#1-methodology--brim-cheat-sheet)
2. [Infection 1](#2-infection-1)
3. [Infection 2](#3-infection-2)
4. [Infection 3](#4-infection-3)
5. [Summary of IOCs](#5-summary-of-iocs)

---

## 1. Methodology & Brim cheat-sheet

Brim imports a PCAP into a **pool**, runs it through **Zeek** (and Suricata when alerts are enabled) and lets us query the resulting logs with the **ZQL / Zed** language.

Each pool is loaded by clicking it in the **POOLS** panel (left), then typing queries in the search bar.

My workflow was the same for the three captures:

| Step | Goal | Query |
|------|------|-------|
| 1 | Get an overview of the log types in the capture | `count() by _path \| sort -r` |
| 2 | Identify the victim and where it talks (HTTP) | `_path=="http" \| cut id.orig_h, id.resp_h, id.resp_p, method, host, uri \| uniq -c` |
| 3 | Look at DNS activity (rare / suspicious domains) | `_path=="dns" \| count() by query \| sort -r` |
| 4 | Pivot on a suspicious host / IP | add the domain or IP at the end of the previous query |
| 5 | Look at the transferred files (hashes, MIME types) | `filename!=null \| cut _path, tx_hosts, rx_hosts, conn_uids, mime_type, filename, md5, sha1` |
| 6 | Check Suricata alerts (if any) | `event_type=="alert" \| count() by alert.severity,alert.category \| sort count` |
| 7 | Take the hash of the downloaded file to **VirusTotal** | – |

Useful fields: `id.orig_h` (source / victim), `id.resp_h` (destination), `id.resp_p` (dest. port), `host`, `uri`, `method`, `status_code`, `response_body_len`, `mime_type`, `md5`, `sha1`.

---

## 2. Infection 1

**Pool:** `Infection1.pcap` (7.9 KB, ~9 min, 29 Aug 2021 20:34 → 20:43)

![Infection 1 – Brim overview](assets/injection_1_task_1.png)

### Task 1 – Victim's IP address

First, I listed the log types present in the capture to understand what I was dealing with:

```
count() by _path | sort -r
```

Then I listed the HTTP conversations to see which internal host initiates them:

```
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c
```

The internal host (`192.168.75.0/24` range) that originates all the HTTP/DNS traffic is the victim. It also queries the internal DNS server `192.168.75.2` on port 53.

**Answer:** `192.168.75.249`

![Task 1](assets/injection_1_task_1.png)

### Task 2 – Domains returning `404 Not Found`

The victim tried to reach two suspicious domains that answered with **404**. I filtered on the HTTP status code (my first attempt had a typo, `statuts_code`, which returned nothing – the corrected query is the second one):

```
_path=="http" | statuts_code==404 | uniq -c      # typo → no result
_path=="http" | status_code==404 | uniq -c
```

Then I looked at the associated hosts with:

```
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c
```

**Answer:** `TODO – the two hosts with status 404 (comma separated, defanged)`

![Task 2](assets/injection_1_task_2.png)

### Task 3 – Successful connection with `response_body_len` = 1309

One of the domains answered successfully with a body of **1309 bytes**. I pivoted on this field and sorted by `uid`:

```
_path=="http" | response_body_len == 1309 | uniq -c | sort uid
```

This gives the domain and the destination IP of the successful connection. I double-checked the IP with a connection-log query:

```
_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h | sort | uniq
```

**Answer:** `TODO – domain, IP`

![Task 3](assets/injection_1_task_3.png)

### Task 4 – Unique DNS requests to `cab[.]myfkn[.]com`

I counted DNS requests per queried name and sorted the result in descending order:

```
_path=="dns" | count() by query | sort -r
```

The question asks for the number of **unique** queries for this domain, **including the capitalized variants** (DNS is case-insensitive but malware often randomizes the case, so `CAB.myfkn.com`, `cAb.MyFkn.com`, … all appear as different strings in Brim). Counting every row that matches the domain gives the answer.

**Answer:** `TODO – number`

![Task 4](assets/injection_1_task_4.png)

### Task 5 – URI requested on `bhaktivrind[.]com`

```
_path=="http" | cut host, uri | bhaktivrind.com
```

The `uri` column shows the path the victim requested over HTTP on this domain.

**Answer:** `TODO – URI`

![Task 5](assets/injection_1_task_5.png)

### Task 6 – Malicious server IP and downloaded executable

I listed the files transferred during the session with their hashes and MIME types:

```
filename!=null | cut _path, tx_hosts, rx_hosts, conn_uids, mime_type, filename, md5, sha1
```

The row with MIME type `application/x-dosexec` (a Windows PE) and `rx_hosts` = victim gives the executable name, while `tx_hosts` is the malicious server. The HTTP logs confirm the request:

```
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c
```

**Answer:** `TODO – IP, executable name`

![Task 6](assets/injection_1_task_6.png)

### Task 7 – Malware family

I copied the **MD5 / SHA1** of the executable from the previous query into **VirusTotal**. The vendors' detection names agree on the family.

**Answer:** `TODO – malware name`

![Task 7](assets/injection_1_task_7.png)

---

## 3. Infection 2

**Pool:** `Infection2.pcap` (11.8 KB, ~3 min, 29 Aug 2021 20:19 → 20:22)

This capture is small but contains a lot of TLS (`ssl`, `x509`) and `files` records. The victim is `192.168.75.146` (visible as the source of every connection in the log view).

![Infection 2 – Brim overview](assets/injection_2_task_1.png)

### Task 1 – Victim's IP address

```
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c
```

**Answer:** `192.168.75.146`

![Task 1](assets/injection_2_task_1.png)

### Task 2 – IP address receiving the POST requests

```
method=="POST" | cut ts, uid, id, method, host, uri, status_code
```

In the log view, the `POST` request at `20:21:40` goes from `192.168.75.146:1052` to `5.181.156.252:80`.

**Answer:** `5.181.156.252` *(confirm on your screenshot)*

![Task 2](assets/injection2_task_2.png)

### Task 3 – Number of POST requests to that IP

I counted the rows returned by the previous query (or with `method=="POST" | count()`).

**Answer:** `TODO – number`

![Task 3](assets/injection_2_task_3.png)

### Task 4 – Domain associated with the IP

I used the HTTP logs and the DNS logs to map the IP to its domain:

```
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c
_path=="dns" | count() by query | sort -r
```

**Answer:** `TODO – domain (defanged)`

![Task 4](assets/injection_2_task_4.png)

### Task 5 – Additional pivot on the malicious infrastructure

I looked at the Suricata alerts to see how the capture was classified and which categories/IPs were involved:

```
event_type=="alert" | count() by alert.severity,alert.category | sort count
event_type=="alert" | alerts := union(alert.category) by src_ip, dest_ip
event_type=="alert" | alerts := union(alert.category) by network_of(dest_ip)
```

> The last query groups the alerts per destination **/24 network**, which helps spot a malicious hosting range rather than a single IP.

**Answer:** `TODO`

![Task 5](assets/injection_2_task_5.png)

### Task 6 – Connections to the C2 (conn log)

```
_path=="conn" | put classnet := network_of(id.resp_h) | cut classnet | count() by classnet | sort -r
_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes
```

The first query counts connections per destination network; the second ranks connections by total transferred bytes to spot exfiltration / large downloads.

**Answer:** `TODO`

![Task 6](assets/injection2_task_6.png)

### Task 7 – Files and certificates

```
filename!=null | cut _path, tx_hosts, rx_hosts, conn_uids, mime_type, filename, md5, sha1
```

I also checked the `x509` records for the certificate subjects (`CN=*.events...`) used by the TLS traffic.

**Answer:** `TODO`

![Task 7](assets/injection_2_task_7.png)

### Task 8 – Malware family / attribution

The hashes and domains were checked on VirusTotal to identify the family.

**Answer:** `TODO – malware name(s)`

![Task 8](assets/injection_2_task_8.png)

---

## 4. Infection 3

**Pool:** `Infection3.pcapng` (296.3 KB, ~11 min, 29 Aug 2021 00:25 → 00:37)

This capture is bigger and contains a Zeek **`notice`** record (red tag) at the end of the timeline, which is a good first lead. The victim is `192.168.75.232`.

![Infection 3 – Brim overview](assets/injection_3_task_1.png)

### Task 1 – Victim's IP address

```
count() by _path | sort -r
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c
```

**Answer:** `192.168.75.232`

![Task 1](assets/injection_3_task_1.png)

### Task 2 – Suspicious HTTP traffic

To get a chronological view of the HTTP requests, I added the timestamp and sorted on it:

```
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | sort ts
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c | sort ts
_path=="http" | cut ts, id.orig_h, id.resp_h, method, host, uri | sort ts
```

**Answer:** `TODO`

![Task 2](assets/injection_3_task_2.png)

### Task 3 – DNS analysis

```
_path=="dns" | count()
_path=="dns" | count() by query | sort -r
```

The first query gives the total number of DNS requests; the second ranks the queried names. One domain stands out: `efhoahegue[.]ru` (a `.ru` domain with a random-looking name, queried many times).

**Answer:** `TODO`

![Task 3](assets/injection_3_task_3.png)

### Task 4 – Resolving the malicious domain

I searched for the domain inside the DNS logs, and then for the IP it resolved to:

```
_path=="dns" | count() by query | sort -r | efhoahegue.ru
_path=="dns" | count() by query | sort -r | 162.217.98.146
_path=="dns" | count() by query | sort -r | ip==162.217.98.146
```

The IP `162.217.98.146` is the one tied to the suspicious domains.

**Answer:** `TODO`

![Task 4](assets/injection_3_task_4.png)

### Task 5 – Content downloaded from the domain

```
_path=="http" | efhoahegue.ru | cut uri, mime_type | uniq -c
```

This shows every URI requested on `efhoahegue[.]ru` and the MIME type of the response (executables, archives, text, …).

**Answer:** `TODO`

![Task 5](assets/injection_3_task5.png)

### Task 6 – User-Agent

I searched for the `user_agent` field in the HTTP logs. An unusual or outdated user-agent is a typical sign of a script or malware talking to its C2:

```
user agent
```

**Answer:** `TODO`

![Task 6](assets/injection_3_task_6.png)

### Task 7 – Notice / TLS traffic

Zeek raised a `notice` for the TLS session `192.168.75.232:55456 → 20.44.10.123:443` (cert `CN=*.events...`). I reviewed it together with `ssl`, `x509` and `files` records.

**Answer:** `TODO`

![Task 7](assets/injection_3_task_7.png)

### Task 8 – Malware family

The IPs, domains and file hashes were checked on VirusTotal to identify the family.

**Answer:** `TODO – malware name`

![Task 8](assets/injection_3_task_8.png)

---

## 5. Summary of IOCs

| Capture | Victim | Notable indicators |
|---------|--------|--------------------|
| Infection 1 | `192.168.75.249` | `bhaktivrind[.]com`, `82.223.9.183`, `160.153.253.42`, `199.59.242.153`, `103.224.212.222`, `cab[.]myfkn[.]com` (case-randomized DNS) |
| Infection 2 | `192.168.75.146` | `5.181.156.252` (POST), `13.69.239.72`, `20.189.173.6` |
| Infection 3 | `192.168.75.232` | `efhoahegue[.]ru`, `162.217.98.146`, `20.44.10.123`, `52.177.161.122` |

> Some of these addresses (Azure ranges such as `13.69.x.x`, `20.x.x.x`, `52.177.x.x`) look like legitimate Microsoft traffic – always validate before blocking.

---


> *Writeup by SubZer030 — TryHackMe: masterminds* 