# TryHackMe — 0x41haz Writeup

> **Difficulty:** Easy | **Category:** Reverse Engineering  
> **Platform:** TryHackMe  
> **Goal:** Find the password accepted by the binary

---

## Table of Contents

- [Initial Recon](#initial-recon)
- [Fixing the ELF Header](#fixing-the-elf-header)
- [Static Analysis](#static-analysis)
- [Verification](#verification)
- [Bonus — Buffer Overflow](#bonus--buffer-overflow)
- [Key Takeaways](#key-takeaways)
- [Summary](#summary)

---

## Initial Recon

We start with a single binary file:

```bash
$ file 0x41haz-1640335532346.0x41haz
0x41haz-1640335532346.0x41haz: ELF 64-bit MSB *unknown arch 0x3e00* (SYSV)
```

Two red flags immediately:

- **MSB** = Most Significant Byte first = **big-endian**. Linux x86-64 binaries are always little-endian.
- **unknown arch `0x3e00`** — the correct value for x86-64 is `0x3e`, so `0x3e00` is `0x3e` with its bytes swapped.

Confirming with `readelf`:

```bash
$ readelf -h 0x41haz-1640335532346.0x41haz
ELF Header:
  Class:                             ELF64
  Data:                              2's complement, big endian
  Type:                              <unknown>: 300
  Machine:                           <unknown>: 0x3e00
  Entry point address:               0x8010000000000000
  ...
readelf: Error: Too many program headers - 0xb00 - the file is not that big
```

`objdump` refuses to open it entirely:

```bash
$ objdump -f 0x41haz-1640335532346.0x41haz
objdump: file format not recognized
```

### Diagnosis

Every multi-byte field in the ELF header has been **byte-swapped** and the endianness flag (`EI_DATA`) has been set to **big-endian** to trick analysis tools into reading everything backwards.

| Field | Read value | Real value (swapped) |
|---|---|---|
| `e_machine`   | `0x3e00` (unknown) | `0x003e` (x86-64) |
| `e_ehsize`    | `0x4000` (16384)   | `0x0040` (64)     |
| `e_phentsize` | `0x3800` (14336)   | `0x0038` (56)     |
| `e_phnum`     | `0x0b00` (2816)    | `0x000b` (11)     |
| `e_shnum`     | `0x1c00` (7168)    | `0x001c` (28)     |
| `e_entry`     | `0x8010000000000000` | `0x1080`        |

> ⚠️ The `.text` section itself is untouched — only the ELF header is corrupted.

---

## Fixing the ELF Header

We write a Python script that:

1. Sets `EI_DATA` to `1` (little-endian).
2. Reads all 13 header fields as big-endian (to undo the swap).
3. Writes each value back in the correct little-endian order.

```python
#!/usr/bin/env python3
import struct, sys

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <elf> [output]")
    sys.exit(1)

src = sys.argv[1]
dst = sys.argv[2] if len(sys.argv) > 2 else src + ".fixed"

data = bytearray(open(src, "rb").read())

# Fix EI_DATA: little-endian
data[5] = 1

def sw16(x): return ((x & 0xFF) << 8) | ((x >> 8) & 0xFF)
def sw32(x): return int.from_bytes(x.to_bytes(4, 'big'), 'little')
def sw64(x): return int.from_bytes(x.to_bytes(8, 'big'), 'little')

(t, m, v, entry, phoff, shoff, fl,
 ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = \
    struct.unpack_from(">HHIQQQIHHHHHH", data, 16)

t, m, v             = sw16(t), sw16(m), sw32(v)
entry, phoff, shoff = sw64(entry), sw64(phoff), sw64(shoff)
fl                  = sw32(fl)
ehsize, phentsize   = sw16(ehsize), sw16(phentsize)
phnum               = sw16(phnum)
shentsize, shnum    = sw16(shentsize), sw16(shnum)
shstrndx            = sw16(shstrndx)

struct.pack_into("<HHIQQQIHHHHHH", data, 16,
    t, m, v, entry, phoff, shoff, fl,
    ehsize, phentsize, phnum, shentsize, shnum, shstrndx)

open(dst, "wb").write(data)
print(f"[+] Written: {dst}")
```

```bash
$ python3 fix.py 0x41haz-1640335532346.0x41haz fixed2
$ readelf -h fixed2
  Data:     2's complement, little endian
  Type:     DYN (Position-Independent Executable file)
  Machine:  Advanced Micro Devices X86-64
  Entry point address: 0x1080
  Number of program headers: 11
  Number of section headers: 28
```

✅ Clean header. `objdump` now disassembles the binary normally.

---

## Static Analysis

### Locating `main`

The standard `_start` at `0x1080` passes `0x1240` to `__libc_start_main` via `%rcx`:

```asm
108f: lea    0x20a(%rip),%r8
1096: lea    0x1a3(%rip),%rcx    # 1240 <main>
```

`main` at `0x1240` is just glibc boilerplate — it delegates to the real check function at **`0x1165`**.

### The Password-Check Function

```asm
1165: push   %rbp
1166: mov    %rsp,%rbp
1169: sub    $0x40,%rsp

; Build the reference string on the stack
116d: movabs $0x6667243532404032,%rax
1177: mov    %rax,-0x16(%rbp)        ; 8 bytes: "2@@25$gf"
117b: movl   $0x40265473,-0xe(%rbp)  ; 4 bytes: "sT&@"
1182: movw   $0x4c,-0xa(%rbp)        ; 2 bytes: "L\0"

; Read user input (unsafe gets)
11ac: lea    -0x40(%rbp),%rax
11b0: mov    %rax,%rdi
11b3: mov    $0x0,%eax
11b8: call   gets@plt

; Length check
11cc: cmpl   $0xd,-0x8(%rbp)    ; len == 13 ?
11d0: je     11e8
11d2: ...                       ; wrong length -> exit
```

Byte-by-byte comparison loop:

```asm
11e8: movl   $0x0,-0x4(%rbp)    ; i = 0
; ...
11f6: movzbl -0x16(%rbp,%rax,1),%edx   ; ref[i]
1200: movzbl -0x40(%rbp,%rax,1),%eax   ; input[i]
1205: cmp    %al,%dl
1207: jne    120f                       ; mismatch -> wrong
```

**Logic:** `strlen(input) == 13` AND `input[i] == ref[i]` for every `i`.

### Reconstructing the String

On x86-64 (little-endian), `movabs` writes bytes from LSB to MSB in memory:

| Instruction | Immediate value | Bytes in memory | ASCII |
|---|---|---|---|
| `movabs $0x6667243532404032` | `0x6667243532404032` | `32 40 40 32 35 24 67 66` | `2@@25$gf` |
| `movl $0x40265473`           | `0x40265473`         | `73 54 26 40`             | `sT&@`     |
| `movw $0x4c`                 | `0x4c`               | `4c 00`                   | `L\0`      |

Concatenated (13 chars + null terminator):

```
[REDACTED]
```

---

## Verification

```bash
$ chmod +x fixed2
$ ./fixed2
=======================
Hey , Can You Crackme ?
=======================
It's just a simple binary

Tell Me the Password :
[REDACTED]
Well Done !!
```

✅ **Password: `[REDACTED]`**

---

## Bonus — Buffer Overflow

At `0x11b8`, the binary calls **`gets()`** on a 64-byte stack buffer (`-0x40(%rbp)`).

`gets()` performs **no bounds checking**, meaning an input longer than 64 bytes will:

1. Overflow the input buffer.
2. Overwrite the **reference string** at `-0x16(%rbp)`.
3. Overwrite the saved `%rbp`.
4. Overwrite the **return address** → full control flow hijack.

> `gets()` was **removed from the C11 standard** for exactly this reason. Always use `fgets()` with an explicit size limit.

---

## Key Takeaways

| Concept | Lesson |
|---|---|
| ELF header manipulation | Tools (`file`, `readelf`, `objdump`, Ghidra) trust the header. Corrupt it → break every tool. |
| Endianness | x86-64 is little-endian. `0x3e00` vs `0x003e` is a single byte swap. |
| `EI_DATA` flag | Setting it to `2` (big-endian) forces every tool to read all multi-byte fields backwards. |
| Static reversing | The password is **built on the stack** via `movabs` / `movl` / `movw` — `strings` is useless here. |
| Consecutive `movabs` pattern | Seeing `movabs $0x...` followed by `movl` / `movw` at consecutive stack offsets = hardcoded string to reconstruct. |
| Secure coding | `gets()` is unsafe. Always use `fgets()` with a size limit. |

---

## Summary

```
Corrupted binary (byte-swapped header + EI_DATA = big-endian)
        ↓
Python script → patch the 13 ELF header fields
        ↓
readelf / objdump / Ghidra functional
        ↓
main (0x1240) → check function (0x1165)
        ↓
Reference string built on stack: movabs + movl + movw
        ↓
Little-endian reconstruction → "[REDACTED]"
        ↓
Password: [REDACTED] ✅
```

---

> *Writeup by SubZer030 — TryHackMe: 0x41haz*