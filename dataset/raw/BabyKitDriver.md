# BabyKitDriver

## Description

Pwnable, 7 solved, 647 Pts.

qemu+macOS ventura 13.6.1

upload your exploit binary and the server will run it for you, you can get the
output of your exploit.

the flag is at /flag

Just pwn my first IOKit Driver!

nc baby-kit-driver.ctf.0ops.sjtu.cn 20001

[attachment](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/BabyKitDriver.kext_D5ED88B9E517723BF57C28E742D3AE49.zip)

## Summary

macOS 13.6.1 kernel module pwn. Solve quite an expensive PoW, send a binary,
and  
get its output back.

## TL;DR

* Install [OSX-KVM](https://github.com/kholia/OSX-KVM) using the [offline](  
https://github.com/kholia/OSX-KVM/blob/master/run_offline.md) method.  
* Boot with `./OpenCore-Boot.sh`.  
 * Add `-s` to `OpenCore-Boot.sh` for enabling the [qemu gdbstub](  
https://wiki.qemu.org/Features/gdbstub) for kernel debugging.  
 * If dropped to the [UEFI shell](  
https://chriswayg.gitbook.io/opencore-visual-beginners-guide/advanced-
topics/opencore-uefi-shell  
   ), do:  
   ```  
   fs0:  
   cd efi/boot  
   bootx64.efi  
   ```  
* Use [docker-osxcross](https://github.com/crazy-max/docker-osxcross) for  
 [compiling the
exploit](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/Makefile).  
* Build [gdb](https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git) with  
 `--target=x86_64-apple-darwin13` for kernel debugging.  
* [Enable SSH](https://support.apple.com/lt-lt/guide/mac-help/mchlp1066/mac).  
* Copy and load the vulnerable kernel module with `kextload`. The first time an  
 approval via GUI and a reboot are needed.  
* Copy the kernel from `/System/Library/Kernels/kernel` to the host, load it  
 into the favorite decompiler. The kernel sources can be found [here](  
https://github.com/apple-oss-distributions/xnu).  
* Check `/Library/Logs/DiagnosticReports/Kernel-*.panic` for panic messages.  
* After gdb is attached, the VM is normally stopped in [`machine_idle()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-10002.41.9/osfmk/i386/pmCPU.c#L175  
 ). This makes it possible to [infer the KASLR
base](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/gdbscript)
for debugging  
 purposes.  
* Breakpoints work reliably. Single-stepping is only possible with `stepi`.  
 Other commands, like `nexti`, more often than not, cause gdb to lose control.  
 When using `si`, disable interrupts by clearing IF using  
 `set $eflags=$eflags&~0x200`, and set it back before `continue`.  
* The kernel module allows reading and writing a buffer, which is stored in the  
 following format:  
 ```  
 union message {  
   struct {  
     void (*output)(void *dest, const void *src);  
     char buf[0x100];  
   } v1;  
   struct v2 {  
     size_t size;  
     void (*output)(void *dest, const void *src, size_t size);  
     char buf[0x200];  
   };  
   char raw[0x300];  
 };  
 ```  
* Leak the kernel stack contents by reading -1 bytes from a v2 buffer.  
* Obtain the RIP + RSI + *RSI control by racing reading vs the v2 -> v1  
 transition. Stabilize the race by storing the *RSI payload in advance.  
* Pivot stack to RSI using JOP.  
* Disable SMEP/SMAP and jump to the userspace shellcode using ROP.  
* Get root by calling `proc_update_label()` and `kauth_cred_setresuid()`. The  
 creds are stored in read-only pages, so a direct write is not an option.  
* Restore the original RSP by scanning for leaked data starting at  
 `current_cpu_datap()->cpu_kernel_stack`. Tweak a few other registers and  
 values in memory, and return to the kernel module.  
* Try reading the flag, retry the race on failure.  
* `flag{7ac21f7848a39f0aea63fa29d304226a}`

## Setup

### OS

As the description states, the challenge runs in QEMU, so it should be
possible  
to recreate the remote setup on the local Linux host. OSX-KVM turned up in  
search and was quite usable. The installation steps from the front page worked  
like a charm, but resulted in macOS 13.5.2, which was not what the challenge  
description said. Using `softwareupdate -i 'macOS Ventura 13.6.1-22G313'`  
failed with `MSU_ERR_STAGE_SPLAT_FAILED` with no further explanations. The  
attempt to do a manual upgrade by downloading the image with
[`./macrecovery.py  
download -b Mac-B4831CEBD52A0C4C -m 00000000000000000`](  
https://github.com/acidanthera/OpenCorePkg/tree/0.9.7/Utilities/macrecovery)  
bricked the system. The offline installer worked, though.

Booting the system with `./OpenCore-Boot.sh` sometimes dropped me to the scary  
UEFI shell instead of the nice graphical menu. To get to the menu, I needed to  
run `fs0:/efi/boot/bootx64.efi` manually.

### Building

It should be possible to build the exploit natively, but I preferred to use
the  
host as much as possible, so I used the `crazymax/osxcross:13.1-ubuntu` docker  
image with the cross-compilers and the SDK. Somewhat counter-intuitively, the  
image comes only with the cross-toolchain and nothing else. So I had to create  
a [`Dockerfile`](image/Dockerfile) that added the base system.

### Testing

Enabling SSH in the guest helped create automation for the other steps, such
as  
loading the kernel module, uploading and running the exploit, and reading
crash  
logs, which I put into the
[Makefile](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/Makefile).
The port forwarding was  
already set up in `OpenCore-Boot.sh`, so I only had to upload my public key  
and put the following into `~/.ssh/config` on the host:

```  
Host OSX-KVM  
       Hostname localhost  
       Port 2222  
       IdentityFile ~/.ssh/id_ecdsa  
       IdentitiesOnly yes  
```

### Debugging

The kernel is stored in `/System/Library/Kernels/kernel` inside the guest and  
can be easily copied to the host with `scp`. There are symbols inside it, so I  
hoped I could use it with GDB. Unfortunately, my distro `gdb-multiarch` didn't  
support Mach-O binaries, [Apple GDB](https://opensource.apple.com/source/gdb/)  
could not be built on Linux, and building GDB from source for the  
`x86_64-apple-darwin` target did not produce a GDB binary. After staring at
the  
GDB's `configure` script for a while, I realized that I had to target  
`x86_64-apple-darwin13`! The resulting GDB accepted the kernel, but did not  
load any symbols anyway, so I had to proceed with debugging the raw asm.

Knowing the randomized kernel base is important for debugging. It can be
easily  
calculated using the observation that attaching the debugger almost always  
interrupts the VM at the `*fc6: cli` instruction, which can be then found in  
the kernel binary like this:  
```  
$ llvm-objdump -d kernel|grep fc6.*cli  
ffffff80004dafc6: fa                    cli  
```

The randomized kernel module base is also important. The `kextstat  
-b keen.BabyKitDriver` command shows the non-randomized base, which then needs  
to be adjusted by the value of `vm_kernel_slide`. Yes, kernel and modules use  
the same slide value.

With that, it's possible to put breakpoints on the kernel and on the module.

## Analysis

As the description states, the module is written using the IOKit framework.  
That's the first time I've seen it; the [old Apple docs](  
https://developer.apple.com/library/archive/documentation/DeviceDrivers/Conceptual/IOKitFundamentals/Introduction/Introduction.html  
) read like marketing materials, and the [new Apple docs](  
https://developer.apple.com/documentation/kernel/iokit_fundamentals) are quite  
concise, but in general it's not that different from Windows or Linux driver  
frameworks.

The driver provides the following two `externalMethods`, which are quite  
similar to ioctls:

```  
kern_return_t BabyKitDriverUserClient::baby_read(void *ref,
IOExternalMethodArguments *args) {  
 BabyKitDriver *drv;  
 kern_return_t ret;  
 char buf_v1[256];  
 char buf_v2[512];  
 size_t size;  
 bool is_v2;

 drv = (BabyKitDriver *)getProvider();  
 is_v2 = drv->is_v2;  
 IOLog("BabyKitDriverUserClient::baby_read\n");  
 IOLog("version:%lld\n", is_v2);  
 if (!drv->message)  
   return 0;  
 if (is_v2) {  
   size = args->scalarInput[1];  
   if ((int64_t)size > (int64_t)drv->message->v2.size)  
     size = drv->message->v2.size;  
   memset(buf_v2, 0, sizeof(buf_v2));  
   drv->message->v2.output(buf_v2, drv->message->v2.buf,
drv->message->v2.size);  
   ret = copyout(buf_v2, args->scalarInput[0], (size - 1) & 0xFFF);  
 } else {  
   memset(buf_v1, 0, sizeof(buf_v1));  
   drv->message->v1.output(buf_v1, &drv->message->v1.buf);  
   ret = copyout(buf_v1, args->scalarInput[0], 0x100);  
 }  
 return ret;  
}

kern_return_t BabyKitDriverUserClient::baby_leaveMessage(void *ref,
IOExternalMethodArguments *args) {  
 BabyKitDriver *drv;  
 kern_return_t ret;  
 __int64 is_v2;  
 size_t size;

 drv = (BabyKitDriver *)getProvider();  
 is_v2 = args->scalarInput[0];  
 IOLog("BabyKitDriverUserClient::baby_leaveMessage\n");  
 if (!drv->message) {  
   drv->message = (struct message *)IOMalloc(sizeof(struct message));  
   if (is_v2)  
     drv->message->v2.output = output2;  
   else  
     drv->message->v1.output = output1;  
 }  
 if (is_v2) {  
   drv->message->v2.output = output2;  
   size = args->scalarInput[2];  
   if ((int64_t)size > 0x200)  
     size = 0x200LL;  
   drv->message->v2.size = size;  
   ret = copyin(args->scalarInput[1], &drv->message->v2.buf, size);  
 } else {  
   drv->message->v1.output = output1;  
   ret = copyin(args->scalarInput[1], &drv->message->v1.buf, 0x100uLL);  
 }  
 drv->is_v2 = is_v2;  
 return ret;  
}  
```

One vulnerability stands out, since there is no good reason for doing  
`(size - 1) & 0xFFF`. It draws attention to the `(int64_t)size >  
(int64_t)drv->message->v2.size` comparison, which also has no good reason to
be  
signed. And indeed, storing an empty v2 message and then reading -1 bytes
leaks  
0xFFF bytes of stack.

A similar problem exists for writing v2 messages.

Finally, the code does not use synchronization, so there are various data  
races.

## Exploitation

### Breaking KASLR

In the `baby_read(-1)` leak, one can find the address for returning to the  
`is_io_connect_method()` at a fixed offset, which makes it possible to compute  
the kernel base.

### Controlling RIP

It's tempting to do `baby_leaveMessage(v2, -1)`, making `copyout()` write as  
many bytes as we want to the heap - arranging it to stop by putting the  
userspace buffer right before a `PROT_NONE` page. Unfortunately, `copyout()`  
[panics](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-10002.41.9/osfmk/x86_64/copyio.c#L182  
) on large sizes, downgrading this bug to a mere DoS.

Race, on the other hand, is quite viable. The goal is to overwrite `v2.output`  
with a controlled value by racing reads with writes that switch from v1 to v2:

```  
writer                               reader  
-----------------------------------  ----------------------------------------------  
                                    if (is_v2) {  
                                    ...  
                                    memset(buf_v2, 0, sizeof(buf_v2));  
ret = copyin(args->scalarInput[1],  
            &drv->message->v1.buf,  
            0x100uLL);  
                                    drv->message->v2.output(buf_v2,  
                                                            drv->message->v2.buf,  
                                                            drv->message->v2.size);  
```

Missing the race is not dangerous in most situations, except when the writer  
thread updates `drv->message->v1.output` and stalls. In this case the reader  
thread will use a very large size, causing a panic. But the probability of
this  
happening doesn't seem to be significant enough for a CTF challenge.

As a result, we can jump anywhere, with RDI (`buf_v2`) pointing to stack, and  
RSI (`drv->message->v2.buf`) pointing to up to 0x200 bytes of controlled data.

### Pivoting stack

Since we control the data at RSI, we can perform JOP. It's hard to do many  
useful things with JOP alone, so we need to convert it to ROP like this:

```  
gadget_1: add rsi, 0x58 ; call rax  
gadget_2: mov rsp, rsi  ; call rdi  
```

Unfortunately there are not enough gadgets for setting up RAX and RDI that do  
not conflict with each other. So we need to go for an even simpler chain that  
loads a constant into RSI, and for that we need to leak the message address,  
which is as easy as using a single `mov [rdi+8], rsi; ret` gadget.

With that, we can build a JOP chain that [pivots to RSI +
0x70](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L238).

### Executing shellcode

It should be possible to achieve privilege escalation with ROP alone, but I  
deemed it to be too hard to debug, therefore I wanted to go for jumping to  
userspace shellcode that would do all the heavy lifting. The [chain](  
pwnit.c#L270) for that is quite simple: we only need to disable SMEP and SMAP  
in CR4, for which the good gadgets exist.

I've decided to write as much
[shellcode](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L147)
in C as possible. I  
needed assembly only for
[switching](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L172)
to the statically allocated  
stack in order to avoid damaging the kernel heap, and then for [switching](  
pwnit.c#L159) back to the kernel stack.

### Escalating privileges

While kernel functions cannot be called from shellcode directly, since it's  
not linked with the kernel, calculating their addresses from the known kernel  
base and casting them to strongly typed function pointers is easy. The kernel  
base is stored by the userspace portion of the exploit in a global variable,  
and this variable is available from the shellcode.

The kernel allocates credentials in read-only memory, so they cannot be
updated  
directly. Instead, there are a couple kernel functions that need to be used:  
[`proc_update_label()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_proc.c#L1813  
) and [`kauth_cred_setresuid()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_credential.c#L3924  
). The usage example can be found in the [`setuid()` implementation](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_prot.c#L679  
).

One difficulty is that `proc_update_label()` takes a closure as an argument.  
For the purpose of making one in the exploit, a closure is just an array of  
3 pointers, the last one being a function pointer.

With that, we can safely set all kinds of uids to 0.

### Resuming the kernel module

Now we need to return to userspace. There is `return_to_user()` for that,  
however, using it directly results in all sorts of nasty consequences.

For instance, IOKit takes some lock, which is then not released. There is a  
sanity check that causes a panic if `current_thread()->rwlock_count` is not 0  
when returning to userspace. It can be fooled by manually decrementing that  
value, but of course this causes a deadlock sooner or later.

Therefore, we better return back to the kernel module. For that, the exploit  
needs to switch back to the kernel stack. We've lost the original value when  
pivoting, so we need to calculate it. The kernel stack base is stored in  
`current_cpu_datap()->cpu_kernel_stack`. We can then scan it for known
pointers  
that have to be there, such as the return address to `is_io_connect_method()`,  
and subtract a fixed offset from that.

We also need to restore a handful of values that were damaged by the exploit:  
* RBP, which is at the fixed offset from RSP.  
* The saved length, which was set to a very large value by the race, and needs  
 to be changed to something more reasonable for `copyout()` to not panic.  
* R14, which is used by `is_io_connect_method()` and has to be 0.

With that, we happily return to userspace as root, and can read the flag
and/or  
spawn the shell.

# Conclusion

That was quite an interesting introduction to the macOS kernel pwn. Definitely  
not the easiest possible, but at least no knowledge of heap feng-shui was  
required.

OSX-KVM + GDB provides a reasonable debugging environment, which could  
nevertheless be improved, first and foremost, by adding or fixing the GDB  
support for parsing Mach-O symbols.

The amount of learning materials on the web is limited, comparing to the Linux  
kernel pwn, but still enough for getting started. The availability of the XNU  
kernel source code is a godsend. I found the following links especially
useful:

* https://www.usenix.org/system/files/conference/woot17/woot17-paper-xu.pdf  
* https://github.com/A2nkF/macOS-Kernel-Exploit

The macOS kernel mitigations and sanity checks are somewhat different from  
those in the Linux kernel, but the challenge author was merciful enough to
give  
us the tools to circumvent them with reasonable effort.

Overall, this was quite hard as a first macOS kernel pwn experience - it took  
me about 20 hours to solve it (including install and reinstall times) - but
I'm  
still glad I looked into it.  

Original writeup
(https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver).# BabyKitDriver

## Description

Pwnable, 7 solved, 647 Pts.

qemu+macOS ventura 13.6.1

upload your exploit binary and the server will run it for you, you can get the
output of your exploit.

the flag is at /flag

Just pwn my first IOKit Driver!

nc baby-kit-driver.ctf.0ops.sjtu.cn 20001

[attachment](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/BabyKitDriver.kext_D5ED88B9E517723BF57C28E742D3AE49.zip)

## Summary

macOS 13.6.1 kernel module pwn. Solve quite an expensive PoW, send a binary,
and  
get its output back.

## TL;DR

* Install [OSX-KVM](https://github.com/kholia/OSX-KVM) using the [offline](  
https://github.com/kholia/OSX-KVM/blob/master/run_offline.md) method.  
* Boot with `./OpenCore-Boot.sh`.  
 * Add `-s` to `OpenCore-Boot.sh` for enabling the [qemu gdbstub](  
https://wiki.qemu.org/Features/gdbstub) for kernel debugging.  
 * If dropped to the [UEFI shell](  
https://chriswayg.gitbook.io/opencore-visual-beginners-guide/advanced-
topics/opencore-uefi-shell  
   ), do:  
   ```  
   fs0:  
   cd efi/boot  
   bootx64.efi  
   ```  
* Use [docker-osxcross](https://github.com/crazy-max/docker-osxcross) for  
 [compiling the
exploit](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/Makefile).  
* Build [gdb](https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git) with  
 `--target=x86_64-apple-darwin13` for kernel debugging.  
* [Enable SSH](https://support.apple.com/lt-lt/guide/mac-help/mchlp1066/mac).  
* Copy and load the vulnerable kernel module with `kextload`. The first time an  
 approval via GUI and a reboot are needed.  
* Copy the kernel from `/System/Library/Kernels/kernel` to the host, load it  
 into the favorite decompiler. The kernel sources can be found [here](  
https://github.com/apple-oss-distributions/xnu).  
* Check `/Library/Logs/DiagnosticReports/Kernel-*.panic` for panic messages.  
* After gdb is attached, the VM is normally stopped in [`machine_idle()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-10002.41.9/osfmk/i386/pmCPU.c#L175  
 ). This makes it possible to [infer the KASLR
base](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/gdbscript)
for debugging  
 purposes.  
* Breakpoints work reliably. Single-stepping is only possible with `stepi`.  
 Other commands, like `nexti`, more often than not, cause gdb to lose control.  
 When using `si`, disable interrupts by clearing IF using  
 `set $eflags=$eflags&~0x200`, and set it back before `continue`.  
* The kernel module allows reading and writing a buffer, which is stored in the  
 following format:  
 ```  
 union message {  
   struct {  
     void (*output)(void *dest, const void *src);  
     char buf[0x100];  
   } v1;  
   struct v2 {  
     size_t size;  
     void (*output)(void *dest, const void *src, size_t size);  
     char buf[0x200];  
   };  
   char raw[0x300];  
 };  
 ```  
* Leak the kernel stack contents by reading -1 bytes from a v2 buffer.  
* Obtain the RIP + RSI + *RSI control by racing reading vs the v2 -> v1  
 transition. Stabilize the race by storing the *RSI payload in advance.  
* Pivot stack to RSI using JOP.  
* Disable SMEP/SMAP and jump to the userspace shellcode using ROP.  
* Get root by calling `proc_update_label()` and `kauth_cred_setresuid()`. The  
 creds are stored in read-only pages, so a direct write is not an option.  
* Restore the original RSP by scanning for leaked data starting at  
 `current_cpu_datap()->cpu_kernel_stack`. Tweak a few other registers and  
 values in memory, and return to the kernel module.  
* Try reading the flag, retry the race on failure.  
* `flag{7ac21f7848a39f0aea63fa29d304226a}`

## Setup

### OS

As the description states, the challenge runs in QEMU, so it should be
possible  
to recreate the remote setup on the local Linux host. OSX-KVM turned up in  
search and was quite usable. The installation steps from the front page worked  
like a charm, but resulted in macOS 13.5.2, which was not what the challenge  
description said. Using `softwareupdate -i 'macOS Ventura 13.6.1-22G313'`  
failed with `MSU_ERR_STAGE_SPLAT_FAILED` with no further explanations. The  
attempt to do a manual upgrade by downloading the image with
[`./macrecovery.py  
download -b Mac-B4831CEBD52A0C4C -m 00000000000000000`](  
https://github.com/acidanthera/OpenCorePkg/tree/0.9.7/Utilities/macrecovery)  
bricked the system. The offline installer worked, though.

Booting the system with `./OpenCore-Boot.sh` sometimes dropped me to the scary  
UEFI shell instead of the nice graphical menu. To get to the menu, I needed to  
run `fs0:/efi/boot/bootx64.efi` manually.

### Building

It should be possible to build the exploit natively, but I preferred to use
the  
host as much as possible, so I used the `crazymax/osxcross:13.1-ubuntu` docker  
image with the cross-compilers and the SDK. Somewhat counter-intuitively, the  
image comes only with the cross-toolchain and nothing else. So I had to create  
a [`Dockerfile`](image/Dockerfile) that added the base system.

### Testing

Enabling SSH in the guest helped create automation for the other steps, such
as  
loading the kernel module, uploading and running the exploit, and reading
crash  
logs, which I put into the
[Makefile](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/Makefile).
The port forwarding was  
already set up in `OpenCore-Boot.sh`, so I only had to upload my public key  
and put the following into `~/.ssh/config` on the host:

```  
Host OSX-KVM  
       Hostname localhost  
       Port 2222  
       IdentityFile ~/.ssh/id_ecdsa  
       IdentitiesOnly yes  
```

### Debugging

The kernel is stored in `/System/Library/Kernels/kernel` inside the guest and  
can be easily copied to the host with `scp`. There are symbols inside it, so I  
hoped I could use it with GDB. Unfortunately, my distro `gdb-multiarch` didn't  
support Mach-O binaries, [Apple GDB](https://opensource.apple.com/source/gdb/)  
could not be built on Linux, and building GDB from source for the  
`x86_64-apple-darwin` target did not produce a GDB binary. After staring at
the  
GDB's `configure` script for a while, I realized that I had to target  
`x86_64-apple-darwin13`! The resulting GDB accepted the kernel, but did not  
load any symbols anyway, so I had to proceed with debugging the raw asm.

Knowing the randomized kernel base is important for debugging. It can be
easily  
calculated using the observation that attaching the debugger almost always  
interrupts the VM at the `*fc6: cli` instruction, which can be then found in  
the kernel binary like this:  
```  
$ llvm-objdump -d kernel|grep fc6.*cli  
ffffff80004dafc6: fa                    cli  
```

The randomized kernel module base is also important. The `kextstat  
-b keen.BabyKitDriver` command shows the non-randomized base, which then needs  
to be adjusted by the value of `vm_kernel_slide`. Yes, kernel and modules use  
the same slide value.

With that, it's possible to put breakpoints on the kernel and on the module.

## Analysis

As the description states, the module is written using the IOKit framework.  
That's the first time I've seen it; the [old Apple docs](  
https://developer.apple.com/library/archive/documentation/DeviceDrivers/Conceptual/IOKitFundamentals/Introduction/Introduction.html  
) read like marketing materials, and the [new Apple docs](  
https://developer.apple.com/documentation/kernel/iokit_fundamentals) are quite  
concise, but in general it's not that different from Windows or Linux driver  
frameworks.

The driver provides the following two `externalMethods`, which are quite  
similar to ioctls:

```  
kern_return_t BabyKitDriverUserClient::baby_read(void *ref,
IOExternalMethodArguments *args) {  
 BabyKitDriver *drv;  
 kern_return_t ret;  
 char buf_v1[256];  
 char buf_v2[512];  
 size_t size;  
 bool is_v2;

 drv = (BabyKitDriver *)getProvider();  
 is_v2 = drv->is_v2;  
 IOLog("BabyKitDriverUserClient::baby_read\n");  
 IOLog("version:%lld\n", is_v2);  
 if (!drv->message)  
   return 0;  
 if (is_v2) {  
   size = args->scalarInput[1];  
   if ((int64_t)size > (int64_t)drv->message->v2.size)  
     size = drv->message->v2.size;  
   memset(buf_v2, 0, sizeof(buf_v2));  
   drv->message->v2.output(buf_v2, drv->message->v2.buf,
drv->message->v2.size);  
   ret = copyout(buf_v2, args->scalarInput[0], (size - 1) & 0xFFF);  
 } else {  
   memset(buf_v1, 0, sizeof(buf_v1));  
   drv->message->v1.output(buf_v1, &drv->message->v1.buf);  
   ret = copyout(buf_v1, args->scalarInput[0], 0x100);  
 }  
 return ret;  
}

kern_return_t BabyKitDriverUserClient::baby_leaveMessage(void *ref,
IOExternalMethodArguments *args) {  
 BabyKitDriver *drv;  
 kern_return_t ret;  
 __int64 is_v2;  
 size_t size;

 drv = (BabyKitDriver *)getProvider();  
 is_v2 = args->scalarInput[0];  
 IOLog("BabyKitDriverUserClient::baby_leaveMessage\n");  
 if (!drv->message) {  
   drv->message = (struct message *)IOMalloc(sizeof(struct message));  
   if (is_v2)  
     drv->message->v2.output = output2;  
   else  
     drv->message->v1.output = output1;  
 }  
 if (is_v2) {  
   drv->message->v2.output = output2;  
   size = args->scalarInput[2];  
   if ((int64_t)size > 0x200)  
     size = 0x200LL;  
   drv->message->v2.size = size;  
   ret = copyin(args->scalarInput[1], &drv->message->v2.buf, size);  
 } else {  
   drv->message->v1.output = output1;  
   ret = copyin(args->scalarInput[1], &drv->message->v1.buf, 0x100uLL);  
 }  
 drv->is_v2 = is_v2;  
 return ret;  
}  
```

One vulnerability stands out, since there is no good reason for doing  
`(size - 1) & 0xFFF`. It draws attention to the `(int64_t)size >  
(int64_t)drv->message->v2.size` comparison, which also has no good reason to
be  
signed. And indeed, storing an empty v2 message and then reading -1 bytes
leaks  
0xFFF bytes of stack.

A similar problem exists for writing v2 messages.

Finally, the code does not use synchronization, so there are various data  
races.

## Exploitation

### Breaking KASLR

In the `baby_read(-1)` leak, one can find the address for returning to the  
`is_io_connect_method()` at a fixed offset, which makes it possible to compute  
the kernel base.

### Controlling RIP

It's tempting to do `baby_leaveMessage(v2, -1)`, making `copyout()` write as  
many bytes as we want to the heap - arranging it to stop by putting the  
userspace buffer right before a `PROT_NONE` page. Unfortunately, `copyout()`  
[panics](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-10002.41.9/osfmk/x86_64/copyio.c#L182  
) on large sizes, downgrading this bug to a mere DoS.

Race, on the other hand, is quite viable. The goal is to overwrite `v2.output`  
with a controlled value by racing reads with writes that switch from v1 to v2:

```  
writer                               reader  
-----------------------------------  ----------------------------------------------  
                                    if (is_v2) {  
                                    ...  
                                    memset(buf_v2, 0, sizeof(buf_v2));  
ret = copyin(args->scalarInput[1],  
            &drv->message->v1.buf,  
            0x100uLL);  
                                    drv->message->v2.output(buf_v2,  
                                                            drv->message->v2.buf,  
                                                            drv->message->v2.size);  
```

Missing the race is not dangerous in most situations, except when the writer  
thread updates `drv->message->v1.output` and stalls. In this case the reader  
thread will use a very large size, causing a panic. But the probability of
this  
happening doesn't seem to be significant enough for a CTF challenge.

As a result, we can jump anywhere, with RDI (`buf_v2`) pointing to stack, and  
RSI (`drv->message->v2.buf`) pointing to up to 0x200 bytes of controlled data.

### Pivoting stack

Since we control the data at RSI, we can perform JOP. It's hard to do many  
useful things with JOP alone, so we need to convert it to ROP like this:

```  
gadget_1: add rsi, 0x58 ; call rax  
gadget_2: mov rsp, rsi  ; call rdi  
```

Unfortunately there are not enough gadgets for setting up RAX and RDI that do  
not conflict with each other. So we need to go for an even simpler chain that  
loads a constant into RSI, and for that we need to leak the message address,  
which is as easy as using a single `mov [rdi+8], rsi; ret` gadget.

With that, we can build a JOP chain that [pivots to RSI +
0x70](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L238).

### Executing shellcode

It should be possible to achieve privilege escalation with ROP alone, but I  
deemed it to be too hard to debug, therefore I wanted to go for jumping to  
userspace shellcode that would do all the heavy lifting. The [chain](  
pwnit.c#L270) for that is quite simple: we only need to disable SMEP and SMAP  
in CR4, for which the good gadgets exist.

I've decided to write as much
[shellcode](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L147)
in C as possible. I  
needed assembly only for
[switching](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L172)
to the statically allocated  
stack in order to avoid damaging the kernel heap, and then for [switching](  
pwnit.c#L159) back to the kernel stack.

### Escalating privileges

While kernel functions cannot be called from shellcode directly, since it's  
not linked with the kernel, calculating their addresses from the known kernel  
base and casting them to strongly typed function pointers is easy. The kernel  
base is stored by the userspace portion of the exploit in a global variable,  
and this variable is available from the shellcode.

The kernel allocates credentials in read-only memory, so they cannot be
updated  
directly. Instead, there are a couple kernel functions that need to be used:  
[`proc_update_label()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_proc.c#L1813  
) and [`kauth_cred_setresuid()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_credential.c#L3924  
). The usage example can be found in the [`setuid()` implementation](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_prot.c#L679  
).

One difficulty is that `proc_update_label()` takes a closure as an argument.  
For the purpose of making one in the exploit, a closure is just an array of  
3 pointers, the last one being a function pointer.

With that, we can safely set all kinds of uids to 0.

### Resuming the kernel module

Now we need to return to userspace. There is `return_to_user()` for that,  
however, using it directly results in all sorts of nasty consequences.

For instance, IOKit takes some lock, which is then not released. There is a  
sanity check that causes a panic if `current_thread()->rwlock_count` is not 0  
when returning to userspace. It can be fooled by manually decrementing that  
value, but of course this causes a deadlock sooner or later.

Therefore, we better return back to the kernel module. For that, the exploit  
needs to switch back to the kernel stack. We've lost the original value when  
pivoting, so we need to calculate it. The kernel stack base is stored in  
`current_cpu_datap()->cpu_kernel_stack`. We can then scan it for known
pointers  
that have to be there, such as the return address to `is_io_connect_method()`,  
and subtract a fixed offset from that.

We also need to restore a handful of values that were damaged by the exploit:  
* RBP, which is at the fixed offset from RSP.  
* The saved length, which was set to a very large value by the race, and needs  
 to be changed to something more reasonable for `copyout()` to not panic.  
* R14, which is used by `is_io_connect_method()` and has to be 0.

With that, we happily return to userspace as root, and can read the flag
and/or  
spawn the shell.

# Conclusion

That was quite an interesting introduction to the macOS kernel pwn. Definitely  
not the easiest possible, but at least no knowledge of heap feng-shui was  
required.

OSX-KVM + GDB provides a reasonable debugging environment, which could  
nevertheless be improved, first and foremost, by adding or fixing the GDB  
support for parsing Mach-O symbols.

The amount of learning materials on the web is limited, comparing to the Linux  
kernel pwn, but still enough for getting started. The availability of the XNU  
kernel source code is a godsend. I found the following links especially
useful:

* https://www.usenix.org/system/files/conference/woot17/woot17-paper-xu.pdf  
* https://github.com/A2nkF/macOS-Kernel-Exploit

The macOS kernel mitigations and sanity checks are somewhat different from  
those in the Linux kernel, but the challenge author was merciful enough to
give  
us the tools to circumvent them with reasonable effort.

Overall, this was quite hard as a first macOS kernel pwn experience - it took  
me about 20 hours to solve it (including install and reinstall times) - but
I'm  
still glad I looked into it.  

Original writeup
(https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver).# BabyKitDriver

## Description

Pwnable, 7 solved, 647 Pts.

qemu+macOS ventura 13.6.1

upload your exploit binary and the server will run it for you, you can get the
output of your exploit.

the flag is at /flag

Just pwn my first IOKit Driver!

nc baby-kit-driver.ctf.0ops.sjtu.cn 20001

[attachment](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/BabyKitDriver.kext_D5ED88B9E517723BF57C28E742D3AE49.zip)

## Summary

macOS 13.6.1 kernel module pwn. Solve quite an expensive PoW, send a binary,
and  
get its output back.

## TL;DR

* Install [OSX-KVM](https://github.com/kholia/OSX-KVM) using the [offline](  
https://github.com/kholia/OSX-KVM/blob/master/run_offline.md) method.  
* Boot with `./OpenCore-Boot.sh`.  
 * Add `-s` to `OpenCore-Boot.sh` for enabling the [qemu gdbstub](  
https://wiki.qemu.org/Features/gdbstub) for kernel debugging.  
 * If dropped to the [UEFI shell](  
https://chriswayg.gitbook.io/opencore-visual-beginners-guide/advanced-
topics/opencore-uefi-shell  
   ), do:  
   ```  
   fs0:  
   cd efi/boot  
   bootx64.efi  
   ```  
* Use [docker-osxcross](https://github.com/crazy-max/docker-osxcross) for  
 [compiling the
exploit](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/Makefile).  
* Build [gdb](https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git) with  
 `--target=x86_64-apple-darwin13` for kernel debugging.  
* [Enable SSH](https://support.apple.com/lt-lt/guide/mac-help/mchlp1066/mac).  
* Copy and load the vulnerable kernel module with `kextload`. The first time an  
 approval via GUI and a reboot are needed.  
* Copy the kernel from `/System/Library/Kernels/kernel` to the host, load it  
 into the favorite decompiler. The kernel sources can be found [here](  
https://github.com/apple-oss-distributions/xnu).  
* Check `/Library/Logs/DiagnosticReports/Kernel-*.panic` for panic messages.  
* After gdb is attached, the VM is normally stopped in [`machine_idle()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-10002.41.9/osfmk/i386/pmCPU.c#L175  
 ). This makes it possible to [infer the KASLR
base](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/gdbscript)
for debugging  
 purposes.  
* Breakpoints work reliably. Single-stepping is only possible with `stepi`.  
 Other commands, like `nexti`, more often than not, cause gdb to lose control.  
 When using `si`, disable interrupts by clearing IF using  
 `set $eflags=$eflags&~0x200`, and set it back before `continue`.  
* The kernel module allows reading and writing a buffer, which is stored in the  
 following format:  
 ```  
 union message {  
   struct {  
     void (*output)(void *dest, const void *src);  
     char buf[0x100];  
   } v1;  
   struct v2 {  
     size_t size;  
     void (*output)(void *dest, const void *src, size_t size);  
     char buf[0x200];  
   };  
   char raw[0x300];  
 };  
 ```  
* Leak the kernel stack contents by reading -1 bytes from a v2 buffer.  
* Obtain the RIP + RSI + *RSI control by racing reading vs the v2 -> v1  
 transition. Stabilize the race by storing the *RSI payload in advance.  
* Pivot stack to RSI using JOP.  
* Disable SMEP/SMAP and jump to the userspace shellcode using ROP.  
* Get root by calling `proc_update_label()` and `kauth_cred_setresuid()`. The  
 creds are stored in read-only pages, so a direct write is not an option.  
* Restore the original RSP by scanning for leaked data starting at  
 `current_cpu_datap()->cpu_kernel_stack`. Tweak a few other registers and  
 values in memory, and return to the kernel module.  
* Try reading the flag, retry the race on failure.  
* `flag{7ac21f7848a39f0aea63fa29d304226a}`

## Setup

### OS

As the description states, the challenge runs in QEMU, so it should be
possible  
to recreate the remote setup on the local Linux host. OSX-KVM turned up in  
search and was quite usable. The installation steps from the front page worked  
like a charm, but resulted in macOS 13.5.2, which was not what the challenge  
description said. Using `softwareupdate -i 'macOS Ventura 13.6.1-22G313'`  
failed with `MSU_ERR_STAGE_SPLAT_FAILED` with no further explanations. The  
attempt to do a manual upgrade by downloading the image with
[`./macrecovery.py  
download -b Mac-B4831CEBD52A0C4C -m 00000000000000000`](  
https://github.com/acidanthera/OpenCorePkg/tree/0.9.7/Utilities/macrecovery)  
bricked the system. The offline installer worked, though.

Booting the system with `./OpenCore-Boot.sh` sometimes dropped me to the scary  
UEFI shell instead of the nice graphical menu. To get to the menu, I needed to  
run `fs0:/efi/boot/bootx64.efi` manually.

### Building

It should be possible to build the exploit natively, but I preferred to use
the  
host as much as possible, so I used the `crazymax/osxcross:13.1-ubuntu` docker  
image with the cross-compilers and the SDK. Somewhat counter-intuitively, the  
image comes only with the cross-toolchain and nothing else. So I had to create  
a [`Dockerfile`](image/Dockerfile) that added the base system.

### Testing

Enabling SSH in the guest helped create automation for the other steps, such
as  
loading the kernel module, uploading and running the exploit, and reading
crash  
logs, which I put into the
[Makefile](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/Makefile).
The port forwarding was  
already set up in `OpenCore-Boot.sh`, so I only had to upload my public key  
and put the following into `~/.ssh/config` on the host:

```  
Host OSX-KVM  
       Hostname localhost  
       Port 2222  
       IdentityFile ~/.ssh/id_ecdsa  
       IdentitiesOnly yes  
```

### Debugging

The kernel is stored in `/System/Library/Kernels/kernel` inside the guest and  
can be easily copied to the host with `scp`. There are symbols inside it, so I  
hoped I could use it with GDB. Unfortunately, my distro `gdb-multiarch` didn't  
support Mach-O binaries, [Apple GDB](https://opensource.apple.com/source/gdb/)  
could not be built on Linux, and building GDB from source for the  
`x86_64-apple-darwin` target did not produce a GDB binary. After staring at
the  
GDB's `configure` script for a while, I realized that I had to target  
`x86_64-apple-darwin13`! The resulting GDB accepted the kernel, but did not  
load any symbols anyway, so I had to proceed with debugging the raw asm.

Knowing the randomized kernel base is important for debugging. It can be
easily  
calculated using the observation that attaching the debugger almost always  
interrupts the VM at the `*fc6: cli` instruction, which can be then found in  
the kernel binary like this:  
```  
$ llvm-objdump -d kernel|grep fc6.*cli  
ffffff80004dafc6: fa                    cli  
```

The randomized kernel module base is also important. The `kextstat  
-b keen.BabyKitDriver` command shows the non-randomized base, which then needs  
to be adjusted by the value of `vm_kernel_slide`. Yes, kernel and modules use  
the same slide value.

With that, it's possible to put breakpoints on the kernel and on the module.

## Analysis

As the description states, the module is written using the IOKit framework.  
That's the first time I've seen it; the [old Apple docs](  
https://developer.apple.com/library/archive/documentation/DeviceDrivers/Conceptual/IOKitFundamentals/Introduction/Introduction.html  
) read like marketing materials, and the [new Apple docs](  
https://developer.apple.com/documentation/kernel/iokit_fundamentals) are quite  
concise, but in general it's not that different from Windows or Linux driver  
frameworks.

The driver provides the following two `externalMethods`, which are quite  
similar to ioctls:

```  
kern_return_t BabyKitDriverUserClient::baby_read(void *ref,
IOExternalMethodArguments *args) {  
 BabyKitDriver *drv;  
 kern_return_t ret;  
 char buf_v1[256];  
 char buf_v2[512];  
 size_t size;  
 bool is_v2;

 drv = (BabyKitDriver *)getProvider();  
 is_v2 = drv->is_v2;  
 IOLog("BabyKitDriverUserClient::baby_read\n");  
 IOLog("version:%lld\n", is_v2);  
 if (!drv->message)  
   return 0;  
 if (is_v2) {  
   size = args->scalarInput[1];  
   if ((int64_t)size > (int64_t)drv->message->v2.size)  
     size = drv->message->v2.size;  
   memset(buf_v2, 0, sizeof(buf_v2));  
   drv->message->v2.output(buf_v2, drv->message->v2.buf,
drv->message->v2.size);  
   ret = copyout(buf_v2, args->scalarInput[0], (size - 1) & 0xFFF);  
 } else {  
   memset(buf_v1, 0, sizeof(buf_v1));  
   drv->message->v1.output(buf_v1, &drv->message->v1.buf);  
   ret = copyout(buf_v1, args->scalarInput[0], 0x100);  
 }  
 return ret;  
}

kern_return_t BabyKitDriverUserClient::baby_leaveMessage(void *ref,
IOExternalMethodArguments *args) {  
 BabyKitDriver *drv;  
 kern_return_t ret;  
 __int64 is_v2;  
 size_t size;

 drv = (BabyKitDriver *)getProvider();  
 is_v2 = args->scalarInput[0];  
 IOLog("BabyKitDriverUserClient::baby_leaveMessage\n");  
 if (!drv->message) {  
   drv->message = (struct message *)IOMalloc(sizeof(struct message));  
   if (is_v2)  
     drv->message->v2.output = output2;  
   else  
     drv->message->v1.output = output1;  
 }  
 if (is_v2) {  
   drv->message->v2.output = output2;  
   size = args->scalarInput[2];  
   if ((int64_t)size > 0x200)  
     size = 0x200LL;  
   drv->message->v2.size = size;  
   ret = copyin(args->scalarInput[1], &drv->message->v2.buf, size);  
 } else {  
   drv->message->v1.output = output1;  
   ret = copyin(args->scalarInput[1], &drv->message->v1.buf, 0x100uLL);  
 }  
 drv->is_v2 = is_v2;  
 return ret;  
}  
```

One vulnerability stands out, since there is no good reason for doing  
`(size - 1) & 0xFFF`. It draws attention to the `(int64_t)size >  
(int64_t)drv->message->v2.size` comparison, which also has no good reason to
be  
signed. And indeed, storing an empty v2 message and then reading -1 bytes
leaks  
0xFFF bytes of stack.

A similar problem exists for writing v2 messages.

Finally, the code does not use synchronization, so there are various data  
races.

## Exploitation

### Breaking KASLR

In the `baby_read(-1)` leak, one can find the address for returning to the  
`is_io_connect_method()` at a fixed offset, which makes it possible to compute  
the kernel base.

### Controlling RIP

It's tempting to do `baby_leaveMessage(v2, -1)`, making `copyout()` write as  
many bytes as we want to the heap - arranging it to stop by putting the  
userspace buffer right before a `PROT_NONE` page. Unfortunately, `copyout()`  
[panics](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-10002.41.9/osfmk/x86_64/copyio.c#L182  
) on large sizes, downgrading this bug to a mere DoS.

Race, on the other hand, is quite viable. The goal is to overwrite `v2.output`  
with a controlled value by racing reads with writes that switch from v1 to v2:

```  
writer                               reader  
-----------------------------------  ----------------------------------------------  
                                    if (is_v2) {  
                                    ...  
                                    memset(buf_v2, 0, sizeof(buf_v2));  
ret = copyin(args->scalarInput[1],  
            &drv->message->v1.buf,  
            0x100uLL);  
                                    drv->message->v2.output(buf_v2,  
                                                            drv->message->v2.buf,  
                                                            drv->message->v2.size);  
```

Missing the race is not dangerous in most situations, except when the writer  
thread updates `drv->message->v1.output` and stalls. In this case the reader  
thread will use a very large size, causing a panic. But the probability of
this  
happening doesn't seem to be significant enough for a CTF challenge.

As a result, we can jump anywhere, with RDI (`buf_v2`) pointing to stack, and  
RSI (`drv->message->v2.buf`) pointing to up to 0x200 bytes of controlled data.

### Pivoting stack

Since we control the data at RSI, we can perform JOP. It's hard to do many  
useful things with JOP alone, so we need to convert it to ROP like this:

```  
gadget_1: add rsi, 0x58 ; call rax  
gadget_2: mov rsp, rsi  ; call rdi  
```

Unfortunately there are not enough gadgets for setting up RAX and RDI that do  
not conflict with each other. So we need to go for an even simpler chain that  
loads a constant into RSI, and for that we need to leak the message address,  
which is as easy as using a single `mov [rdi+8], rsi; ret` gadget.

With that, we can build a JOP chain that [pivots to RSI +
0x70](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L238).

### Executing shellcode

It should be possible to achieve privilege escalation with ROP alone, but I  
deemed it to be too hard to debug, therefore I wanted to go for jumping to  
userspace shellcode that would do all the heavy lifting. The [chain](  
pwnit.c#L270) for that is quite simple: we only need to disable SMEP and SMAP  
in CR4, for which the good gadgets exist.

I've decided to write as much
[shellcode](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L147)
in C as possible. I  
needed assembly only for
[switching](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L172)
to the statically allocated  
stack in order to avoid damaging the kernel heap, and then for [switching](  
pwnit.c#L159) back to the kernel stack.

### Escalating privileges

While kernel functions cannot be called from shellcode directly, since it's  
not linked with the kernel, calculating their addresses from the known kernel  
base and casting them to strongly typed function pointers is easy. The kernel  
base is stored by the userspace portion of the exploit in a global variable,  
and this variable is available from the shellcode.

The kernel allocates credentials in read-only memory, so they cannot be
updated  
directly. Instead, there are a couple kernel functions that need to be used:  
[`proc_update_label()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_proc.c#L1813  
) and [`kauth_cred_setresuid()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_credential.c#L3924  
). The usage example can be found in the [`setuid()` implementation](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_prot.c#L679  
).

One difficulty is that `proc_update_label()` takes a closure as an argument.  
For the purpose of making one in the exploit, a closure is just an array of  
3 pointers, the last one being a function pointer.

With that, we can safely set all kinds of uids to 0.

### Resuming the kernel module

Now we need to return to userspace. There is `return_to_user()` for that,  
however, using it directly results in all sorts of nasty consequences.

For instance, IOKit takes some lock, which is then not released. There is a  
sanity check that causes a panic if `current_thread()->rwlock_count` is not 0  
when returning to userspace. It can be fooled by manually decrementing that  
value, but of course this causes a deadlock sooner or later.

Therefore, we better return back to the kernel module. For that, the exploit  
needs to switch back to the kernel stack. We've lost the original value when  
pivoting, so we need to calculate it. The kernel stack base is stored in  
`current_cpu_datap()->cpu_kernel_stack`. We can then scan it for known
pointers  
that have to be there, such as the return address to `is_io_connect_method()`,  
and subtract a fixed offset from that.

We also need to restore a handful of values that were damaged by the exploit:  
* RBP, which is at the fixed offset from RSP.  
* The saved length, which was set to a very large value by the race, and needs  
 to be changed to something more reasonable for `copyout()` to not panic.  
* R14, which is used by `is_io_connect_method()` and has to be 0.

With that, we happily return to userspace as root, and can read the flag
and/or  
spawn the shell.

# Conclusion

That was quite an interesting introduction to the macOS kernel pwn. Definitely  
not the easiest possible, but at least no knowledge of heap feng-shui was  
required.

OSX-KVM + GDB provides a reasonable debugging environment, which could  
nevertheless be improved, first and foremost, by adding or fixing the GDB  
support for parsing Mach-O symbols.

The amount of learning materials on the web is limited, comparing to the Linux  
kernel pwn, but still enough for getting started. The availability of the XNU  
kernel source code is a godsend. I found the following links especially
useful:

* https://www.usenix.org/system/files/conference/woot17/woot17-paper-xu.pdf  
* https://github.com/A2nkF/macOS-Kernel-Exploit

The macOS kernel mitigations and sanity checks are somewhat different from  
those in the Linux kernel, but the challenge author was merciful enough to
give  
us the tools to circumvent them with reasonable effort.

Overall, this was quite hard as a first macOS kernel pwn experience - it took  
me about 20 hours to solve it (including install and reinstall times) - but
I'm  
still glad I looked into it.  

Original writeup
(https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver).# BabyKitDriver

## Description

Pwnable, 7 solved, 647 Pts.

qemu+macOS ventura 13.6.1

upload your exploit binary and the server will run it for you, you can get the
output of your exploit.

the flag is at /flag

Just pwn my first IOKit Driver!

nc baby-kit-driver.ctf.0ops.sjtu.cn 20001

[attachment](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/BabyKitDriver.kext_D5ED88B9E517723BF57C28E742D3AE49.zip)

## Summary

macOS 13.6.1 kernel module pwn. Solve quite an expensive PoW, send a binary,
and  
get its output back.

## TL;DR

* Install [OSX-KVM](https://github.com/kholia/OSX-KVM) using the [offline](  
https://github.com/kholia/OSX-KVM/blob/master/run_offline.md) method.  
* Boot with `./OpenCore-Boot.sh`.  
 * Add `-s` to `OpenCore-Boot.sh` for enabling the [qemu gdbstub](  
https://wiki.qemu.org/Features/gdbstub) for kernel debugging.  
 * If dropped to the [UEFI shell](  
https://chriswayg.gitbook.io/opencore-visual-beginners-guide/advanced-
topics/opencore-uefi-shell  
   ), do:  
   ```  
   fs0:  
   cd efi/boot  
   bootx64.efi  
   ```  
* Use [docker-osxcross](https://github.com/crazy-max/docker-osxcross) for  
 [compiling the
exploit](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/Makefile).  
* Build [gdb](https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git) with  
 `--target=x86_64-apple-darwin13` for kernel debugging.  
* [Enable SSH](https://support.apple.com/lt-lt/guide/mac-help/mchlp1066/mac).  
* Copy and load the vulnerable kernel module with `kextload`. The first time an  
 approval via GUI and a reboot are needed.  
* Copy the kernel from `/System/Library/Kernels/kernel` to the host, load it  
 into the favorite decompiler. The kernel sources can be found [here](  
https://github.com/apple-oss-distributions/xnu).  
* Check `/Library/Logs/DiagnosticReports/Kernel-*.panic` for panic messages.  
* After gdb is attached, the VM is normally stopped in [`machine_idle()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-10002.41.9/osfmk/i386/pmCPU.c#L175  
 ). This makes it possible to [infer the KASLR
base](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/gdbscript)
for debugging  
 purposes.  
* Breakpoints work reliably. Single-stepping is only possible with `stepi`.  
 Other commands, like `nexti`, more often than not, cause gdb to lose control.  
 When using `si`, disable interrupts by clearing IF using  
 `set $eflags=$eflags&~0x200`, and set it back before `continue`.  
* The kernel module allows reading and writing a buffer, which is stored in the  
 following format:  
 ```  
 union message {  
   struct {  
     void (*output)(void *dest, const void *src);  
     char buf[0x100];  
   } v1;  
   struct v2 {  
     size_t size;  
     void (*output)(void *dest, const void *src, size_t size);  
     char buf[0x200];  
   };  
   char raw[0x300];  
 };  
 ```  
* Leak the kernel stack contents by reading -1 bytes from a v2 buffer.  
* Obtain the RIP + RSI + *RSI control by racing reading vs the v2 -> v1  
 transition. Stabilize the race by storing the *RSI payload in advance.  
* Pivot stack to RSI using JOP.  
* Disable SMEP/SMAP and jump to the userspace shellcode using ROP.  
* Get root by calling `proc_update_label()` and `kauth_cred_setresuid()`. The  
 creds are stored in read-only pages, so a direct write is not an option.  
* Restore the original RSP by scanning for leaked data starting at  
 `current_cpu_datap()->cpu_kernel_stack`. Tweak a few other registers and  
 values in memory, and return to the kernel module.  
* Try reading the flag, retry the race on failure.  
* `flag{7ac21f7848a39f0aea63fa29d304226a}`

## Setup

### OS

As the description states, the challenge runs in QEMU, so it should be
possible  
to recreate the remote setup on the local Linux host. OSX-KVM turned up in  
search and was quite usable. The installation steps from the front page worked  
like a charm, but resulted in macOS 13.5.2, which was not what the challenge  
description said. Using `softwareupdate -i 'macOS Ventura 13.6.1-22G313'`  
failed with `MSU_ERR_STAGE_SPLAT_FAILED` with no further explanations. The  
attempt to do a manual upgrade by downloading the image with
[`./macrecovery.py  
download -b Mac-B4831CEBD52A0C4C -m 00000000000000000`](  
https://github.com/acidanthera/OpenCorePkg/tree/0.9.7/Utilities/macrecovery)  
bricked the system. The offline installer worked, though.

Booting the system with `./OpenCore-Boot.sh` sometimes dropped me to the scary  
UEFI shell instead of the nice graphical menu. To get to the menu, I needed to  
run `fs0:/efi/boot/bootx64.efi` manually.

### Building

It should be possible to build the exploit natively, but I preferred to use
the  
host as much as possible, so I used the `crazymax/osxcross:13.1-ubuntu` docker  
image with the cross-compilers and the SDK. Somewhat counter-intuitively, the  
image comes only with the cross-toolchain and nothing else. So I had to create  
a [`Dockerfile`](image/Dockerfile) that added the base system.

### Testing

Enabling SSH in the guest helped create automation for the other steps, such
as  
loading the kernel module, uploading and running the exploit, and reading
crash  
logs, which I put into the
[Makefile](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/Makefile).
The port forwarding was  
already set up in `OpenCore-Boot.sh`, so I only had to upload my public key  
and put the following into `~/.ssh/config` on the host:

```  
Host OSX-KVM  
       Hostname localhost  
       Port 2222  
       IdentityFile ~/.ssh/id_ecdsa  
       IdentitiesOnly yes  
```

### Debugging

The kernel is stored in `/System/Library/Kernels/kernel` inside the guest and  
can be easily copied to the host with `scp`. There are symbols inside it, so I  
hoped I could use it with GDB. Unfortunately, my distro `gdb-multiarch` didn't  
support Mach-O binaries, [Apple GDB](https://opensource.apple.com/source/gdb/)  
could not be built on Linux, and building GDB from source for the  
`x86_64-apple-darwin` target did not produce a GDB binary. After staring at
the  
GDB's `configure` script for a while, I realized that I had to target  
`x86_64-apple-darwin13`! The resulting GDB accepted the kernel, but did not  
load any symbols anyway, so I had to proceed with debugging the raw asm.

Knowing the randomized kernel base is important for debugging. It can be
easily  
calculated using the observation that attaching the debugger almost always  
interrupts the VM at the `*fc6: cli` instruction, which can be then found in  
the kernel binary like this:  
```  
$ llvm-objdump -d kernel|grep fc6.*cli  
ffffff80004dafc6: fa                    cli  
```

The randomized kernel module base is also important. The `kextstat  
-b keen.BabyKitDriver` command shows the non-randomized base, which then needs  
to be adjusted by the value of `vm_kernel_slide`. Yes, kernel and modules use  
the same slide value.

With that, it's possible to put breakpoints on the kernel and on the module.

## Analysis

As the description states, the module is written using the IOKit framework.  
That's the first time I've seen it; the [old Apple docs](  
https://developer.apple.com/library/archive/documentation/DeviceDrivers/Conceptual/IOKitFundamentals/Introduction/Introduction.html  
) read like marketing materials, and the [new Apple docs](  
https://developer.apple.com/documentation/kernel/iokit_fundamentals) are quite  
concise, but in general it's not that different from Windows or Linux driver  
frameworks.

The driver provides the following two `externalMethods`, which are quite  
similar to ioctls:

```  
kern_return_t BabyKitDriverUserClient::baby_read(void *ref,
IOExternalMethodArguments *args) {  
 BabyKitDriver *drv;  
 kern_return_t ret;  
 char buf_v1[256];  
 char buf_v2[512];  
 size_t size;  
 bool is_v2;

 drv = (BabyKitDriver *)getProvider();  
 is_v2 = drv->is_v2;  
 IOLog("BabyKitDriverUserClient::baby_read\n");  
 IOLog("version:%lld\n", is_v2);  
 if (!drv->message)  
   return 0;  
 if (is_v2) {  
   size = args->scalarInput[1];  
   if ((int64_t)size > (int64_t)drv->message->v2.size)  
     size = drv->message->v2.size;  
   memset(buf_v2, 0, sizeof(buf_v2));  
   drv->message->v2.output(buf_v2, drv->message->v2.buf,
drv->message->v2.size);  
   ret = copyout(buf_v2, args->scalarInput[0], (size - 1) & 0xFFF);  
 } else {  
   memset(buf_v1, 0, sizeof(buf_v1));  
   drv->message->v1.output(buf_v1, &drv->message->v1.buf);  
   ret = copyout(buf_v1, args->scalarInput[0], 0x100);  
 }  
 return ret;  
}

kern_return_t BabyKitDriverUserClient::baby_leaveMessage(void *ref,
IOExternalMethodArguments *args) {  
 BabyKitDriver *drv;  
 kern_return_t ret;  
 __int64 is_v2;  
 size_t size;

 drv = (BabyKitDriver *)getProvider();  
 is_v2 = args->scalarInput[0];  
 IOLog("BabyKitDriverUserClient::baby_leaveMessage\n");  
 if (!drv->message) {  
   drv->message = (struct message *)IOMalloc(sizeof(struct message));  
   if (is_v2)  
     drv->message->v2.output = output2;  
   else  
     drv->message->v1.output = output1;  
 }  
 if (is_v2) {  
   drv->message->v2.output = output2;  
   size = args->scalarInput[2];  
   if ((int64_t)size > 0x200)  
     size = 0x200LL;  
   drv->message->v2.size = size;  
   ret = copyin(args->scalarInput[1], &drv->message->v2.buf, size);  
 } else {  
   drv->message->v1.output = output1;  
   ret = copyin(args->scalarInput[1], &drv->message->v1.buf, 0x100uLL);  
 }  
 drv->is_v2 = is_v2;  
 return ret;  
}  
```

One vulnerability stands out, since there is no good reason for doing  
`(size - 1) & 0xFFF`. It draws attention to the `(int64_t)size >  
(int64_t)drv->message->v2.size` comparison, which also has no good reason to
be  
signed. And indeed, storing an empty v2 message and then reading -1 bytes
leaks  
0xFFF bytes of stack.

A similar problem exists for writing v2 messages.

Finally, the code does not use synchronization, so there are various data  
races.

## Exploitation

### Breaking KASLR

In the `baby_read(-1)` leak, one can find the address for returning to the  
`is_io_connect_method()` at a fixed offset, which makes it possible to compute  
the kernel base.

### Controlling RIP

It's tempting to do `baby_leaveMessage(v2, -1)`, making `copyout()` write as  
many bytes as we want to the heap - arranging it to stop by putting the  
userspace buffer right before a `PROT_NONE` page. Unfortunately, `copyout()`  
[panics](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-10002.41.9/osfmk/x86_64/copyio.c#L182  
) on large sizes, downgrading this bug to a mere DoS.

Race, on the other hand, is quite viable. The goal is to overwrite `v2.output`  
with a controlled value by racing reads with writes that switch from v1 to v2:

```  
writer                               reader  
-----------------------------------  ----------------------------------------------  
                                    if (is_v2) {  
                                    ...  
                                    memset(buf_v2, 0, sizeof(buf_v2));  
ret = copyin(args->scalarInput[1],  
            &drv->message->v1.buf,  
            0x100uLL);  
                                    drv->message->v2.output(buf_v2,  
                                                            drv->message->v2.buf,  
                                                            drv->message->v2.size);  
```

Missing the race is not dangerous in most situations, except when the writer  
thread updates `drv->message->v1.output` and stalls. In this case the reader  
thread will use a very large size, causing a panic. But the probability of
this  
happening doesn't seem to be significant enough for a CTF challenge.

As a result, we can jump anywhere, with RDI (`buf_v2`) pointing to stack, and  
RSI (`drv->message->v2.buf`) pointing to up to 0x200 bytes of controlled data.

### Pivoting stack

Since we control the data at RSI, we can perform JOP. It's hard to do many  
useful things with JOP alone, so we need to convert it to ROP like this:

```  
gadget_1: add rsi, 0x58 ; call rax  
gadget_2: mov rsp, rsi  ; call rdi  
```

Unfortunately there are not enough gadgets for setting up RAX and RDI that do  
not conflict with each other. So we need to go for an even simpler chain that  
loads a constant into RSI, and for that we need to leak the message address,  
which is as easy as using a single `mov [rdi+8], rsi; ret` gadget.

With that, we can build a JOP chain that [pivots to RSI +
0x70](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L238).

### Executing shellcode

It should be possible to achieve privilege escalation with ROP alone, but I  
deemed it to be too hard to debug, therefore I wanted to go for jumping to  
userspace shellcode that would do all the heavy lifting. The [chain](  
pwnit.c#L270) for that is quite simple: we only need to disable SMEP and SMAP  
in CR4, for which the good gadgets exist.

I've decided to write as much
[shellcode](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L147)
in C as possible. I  
needed assembly only for
[switching](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L172)
to the statically allocated  
stack in order to avoid damaging the kernel heap, and then for [switching](  
pwnit.c#L159) back to the kernel stack.

### Escalating privileges

While kernel functions cannot be called from shellcode directly, since it's  
not linked with the kernel, calculating their addresses from the known kernel  
base and casting them to strongly typed function pointers is easy. The kernel  
base is stored by the userspace portion of the exploit in a global variable,  
and this variable is available from the shellcode.

The kernel allocates credentials in read-only memory, so they cannot be
updated  
directly. Instead, there are a couple kernel functions that need to be used:  
[`proc_update_label()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_proc.c#L1813  
) and [`kauth_cred_setresuid()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_credential.c#L3924  
). The usage example can be found in the [`setuid()` implementation](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_prot.c#L679  
).

One difficulty is that `proc_update_label()` takes a closure as an argument.  
For the purpose of making one in the exploit, a closure is just an array of  
3 pointers, the last one being a function pointer.

With that, we can safely set all kinds of uids to 0.

### Resuming the kernel module

Now we need to return to userspace. There is `return_to_user()` for that,  
however, using it directly results in all sorts of nasty consequences.

For instance, IOKit takes some lock, which is then not released. There is a  
sanity check that causes a panic if `current_thread()->rwlock_count` is not 0  
when returning to userspace. It can be fooled by manually decrementing that  
value, but of course this causes a deadlock sooner or later.

Therefore, we better return back to the kernel module. For that, the exploit  
needs to switch back to the kernel stack. We've lost the original value when  
pivoting, so we need to calculate it. The kernel stack base is stored in  
`current_cpu_datap()->cpu_kernel_stack`. We can then scan it for known
pointers  
that have to be there, such as the return address to `is_io_connect_method()`,  
and subtract a fixed offset from that.

We also need to restore a handful of values that were damaged by the exploit:  
* RBP, which is at the fixed offset from RSP.  
* The saved length, which was set to a very large value by the race, and needs  
 to be changed to something more reasonable for `copyout()` to not panic.  
* R14, which is used by `is_io_connect_method()` and has to be 0.

With that, we happily return to userspace as root, and can read the flag
and/or  
spawn the shell.

# Conclusion

That was quite an interesting introduction to the macOS kernel pwn. Definitely  
not the easiest possible, but at least no knowledge of heap feng-shui was  
required.

OSX-KVM + GDB provides a reasonable debugging environment, which could  
nevertheless be improved, first and foremost, by adding or fixing the GDB  
support for parsing Mach-O symbols.

The amount of learning materials on the web is limited, comparing to the Linux  
kernel pwn, but still enough for getting started. The availability of the XNU  
kernel source code is a godsend. I found the following links especially
useful:

* https://www.usenix.org/system/files/conference/woot17/woot17-paper-xu.pdf  
* https://github.com/A2nkF/macOS-Kernel-Exploit

The macOS kernel mitigations and sanity checks are somewhat different from  
those in the Linux kernel, but the challenge author was merciful enough to
give  
us the tools to circumvent them with reasonable effort.

Overall, this was quite hard as a first macOS kernel pwn experience - it took  
me about 20 hours to solve it (including install and reinstall times) - but
I'm  
still glad I looked into it.  

Original writeup
(https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver).# BabyKitDriver

## Description

Pwnable, 7 solved, 647 Pts.

qemu+macOS ventura 13.6.1

upload your exploit binary and the server will run it for you, you can get the
output of your exploit.

the flag is at /flag

Just pwn my first IOKit Driver!

nc baby-kit-driver.ctf.0ops.sjtu.cn 20001

[attachment](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/BabyKitDriver.kext_D5ED88B9E517723BF57C28E742D3AE49.zip)

## Summary

macOS 13.6.1 kernel module pwn. Solve quite an expensive PoW, send a binary,
and  
get its output back.

## TL;DR

* Install [OSX-KVM](https://github.com/kholia/OSX-KVM) using the [offline](  
https://github.com/kholia/OSX-KVM/blob/master/run_offline.md) method.  
* Boot with `./OpenCore-Boot.sh`.  
 * Add `-s` to `OpenCore-Boot.sh` for enabling the [qemu gdbstub](  
https://wiki.qemu.org/Features/gdbstub) for kernel debugging.  
 * If dropped to the [UEFI shell](  
https://chriswayg.gitbook.io/opencore-visual-beginners-guide/advanced-
topics/opencore-uefi-shell  
   ), do:  
   ```  
   fs0:  
   cd efi/boot  
   bootx64.efi  
   ```  
* Use [docker-osxcross](https://github.com/crazy-max/docker-osxcross) for  
 [compiling the
exploit](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/Makefile).  
* Build [gdb](https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git) with  
 `--target=x86_64-apple-darwin13` for kernel debugging.  
* [Enable SSH](https://support.apple.com/lt-lt/guide/mac-help/mchlp1066/mac).  
* Copy and load the vulnerable kernel module with `kextload`. The first time an  
 approval via GUI and a reboot are needed.  
* Copy the kernel from `/System/Library/Kernels/kernel` to the host, load it  
 into the favorite decompiler. The kernel sources can be found [here](  
https://github.com/apple-oss-distributions/xnu).  
* Check `/Library/Logs/DiagnosticReports/Kernel-*.panic` for panic messages.  
* After gdb is attached, the VM is normally stopped in [`machine_idle()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-10002.41.9/osfmk/i386/pmCPU.c#L175  
 ). This makes it possible to [infer the KASLR
base](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/gdbscript)
for debugging  
 purposes.  
* Breakpoints work reliably. Single-stepping is only possible with `stepi`.  
 Other commands, like `nexti`, more often than not, cause gdb to lose control.  
 When using `si`, disable interrupts by clearing IF using  
 `set $eflags=$eflags&~0x200`, and set it back before `continue`.  
* The kernel module allows reading and writing a buffer, which is stored in the  
 following format:  
 ```  
 union message {  
   struct {  
     void (*output)(void *dest, const void *src);  
     char buf[0x100];  
   } v1;  
   struct v2 {  
     size_t size;  
     void (*output)(void *dest, const void *src, size_t size);  
     char buf[0x200];  
   };  
   char raw[0x300];  
 };  
 ```  
* Leak the kernel stack contents by reading -1 bytes from a v2 buffer.  
* Obtain the RIP + RSI + *RSI control by racing reading vs the v2 -> v1  
 transition. Stabilize the race by storing the *RSI payload in advance.  
* Pivot stack to RSI using JOP.  
* Disable SMEP/SMAP and jump to the userspace shellcode using ROP.  
* Get root by calling `proc_update_label()` and `kauth_cred_setresuid()`. The  
 creds are stored in read-only pages, so a direct write is not an option.  
* Restore the original RSP by scanning for leaked data starting at  
 `current_cpu_datap()->cpu_kernel_stack`. Tweak a few other registers and  
 values in memory, and return to the kernel module.  
* Try reading the flag, retry the race on failure.  
* `flag{7ac21f7848a39f0aea63fa29d304226a}`

## Setup

### OS

As the description states, the challenge runs in QEMU, so it should be
possible  
to recreate the remote setup on the local Linux host. OSX-KVM turned up in  
search and was quite usable. The installation steps from the front page worked  
like a charm, but resulted in macOS 13.5.2, which was not what the challenge  
description said. Using `softwareupdate -i 'macOS Ventura 13.6.1-22G313'`  
failed with `MSU_ERR_STAGE_SPLAT_FAILED` with no further explanations. The  
attempt to do a manual upgrade by downloading the image with
[`./macrecovery.py  
download -b Mac-B4831CEBD52A0C4C -m 00000000000000000`](  
https://github.com/acidanthera/OpenCorePkg/tree/0.9.7/Utilities/macrecovery)  
bricked the system. The offline installer worked, though.

Booting the system with `./OpenCore-Boot.sh` sometimes dropped me to the scary  
UEFI shell instead of the nice graphical menu. To get to the menu, I needed to  
run `fs0:/efi/boot/bootx64.efi` manually.

### Building

It should be possible to build the exploit natively, but I preferred to use
the  
host as much as possible, so I used the `crazymax/osxcross:13.1-ubuntu` docker  
image with the cross-compilers and the SDK. Somewhat counter-intuitively, the  
image comes only with the cross-toolchain and nothing else. So I had to create  
a [`Dockerfile`](image/Dockerfile) that added the base system.

### Testing

Enabling SSH in the guest helped create automation for the other steps, such
as  
loading the kernel module, uploading and running the exploit, and reading
crash  
logs, which I put into the
[Makefile](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/Makefile).
The port forwarding was  
already set up in `OpenCore-Boot.sh`, so I only had to upload my public key  
and put the following into `~/.ssh/config` on the host:

```  
Host OSX-KVM  
       Hostname localhost  
       Port 2222  
       IdentityFile ~/.ssh/id_ecdsa  
       IdentitiesOnly yes  
```

### Debugging

The kernel is stored in `/System/Library/Kernels/kernel` inside the guest and  
can be easily copied to the host with `scp`. There are symbols inside it, so I  
hoped I could use it with GDB. Unfortunately, my distro `gdb-multiarch` didn't  
support Mach-O binaries, [Apple GDB](https://opensource.apple.com/source/gdb/)  
could not be built on Linux, and building GDB from source for the  
`x86_64-apple-darwin` target did not produce a GDB binary. After staring at
the  
GDB's `configure` script for a while, I realized that I had to target  
`x86_64-apple-darwin13`! The resulting GDB accepted the kernel, but did not  
load any symbols anyway, so I had to proceed with debugging the raw asm.

Knowing the randomized kernel base is important for debugging. It can be
easily  
calculated using the observation that attaching the debugger almost always  
interrupts the VM at the `*fc6: cli` instruction, which can be then found in  
the kernel binary like this:  
```  
$ llvm-objdump -d kernel|grep fc6.*cli  
ffffff80004dafc6: fa                    cli  
```

The randomized kernel module base is also important. The `kextstat  
-b keen.BabyKitDriver` command shows the non-randomized base, which then needs  
to be adjusted by the value of `vm_kernel_slide`. Yes, kernel and modules use  
the same slide value.

With that, it's possible to put breakpoints on the kernel and on the module.

## Analysis

As the description states, the module is written using the IOKit framework.  
That's the first time I've seen it; the [old Apple docs](  
https://developer.apple.com/library/archive/documentation/DeviceDrivers/Conceptual/IOKitFundamentals/Introduction/Introduction.html  
) read like marketing materials, and the [new Apple docs](  
https://developer.apple.com/documentation/kernel/iokit_fundamentals) are quite  
concise, but in general it's not that different from Windows or Linux driver  
frameworks.

The driver provides the following two `externalMethods`, which are quite  
similar to ioctls:

```  
kern_return_t BabyKitDriverUserClient::baby_read(void *ref,
IOExternalMethodArguments *args) {  
 BabyKitDriver *drv;  
 kern_return_t ret;  
 char buf_v1[256];  
 char buf_v2[512];  
 size_t size;  
 bool is_v2;

 drv = (BabyKitDriver *)getProvider();  
 is_v2 = drv->is_v2;  
 IOLog("BabyKitDriverUserClient::baby_read\n");  
 IOLog("version:%lld\n", is_v2);  
 if (!drv->message)  
   return 0;  
 if (is_v2) {  
   size = args->scalarInput[1];  
   if ((int64_t)size > (int64_t)drv->message->v2.size)  
     size = drv->message->v2.size;  
   memset(buf_v2, 0, sizeof(buf_v2));  
   drv->message->v2.output(buf_v2, drv->message->v2.buf,
drv->message->v2.size);  
   ret = copyout(buf_v2, args->scalarInput[0], (size - 1) & 0xFFF);  
 } else {  
   memset(buf_v1, 0, sizeof(buf_v1));  
   drv->message->v1.output(buf_v1, &drv->message->v1.buf);  
   ret = copyout(buf_v1, args->scalarInput[0], 0x100);  
 }  
 return ret;  
}

kern_return_t BabyKitDriverUserClient::baby_leaveMessage(void *ref,
IOExternalMethodArguments *args) {  
 BabyKitDriver *drv;  
 kern_return_t ret;  
 __int64 is_v2;  
 size_t size;

 drv = (BabyKitDriver *)getProvider();  
 is_v2 = args->scalarInput[0];  
 IOLog("BabyKitDriverUserClient::baby_leaveMessage\n");  
 if (!drv->message) {  
   drv->message = (struct message *)IOMalloc(sizeof(struct message));  
   if (is_v2)  
     drv->message->v2.output = output2;  
   else  
     drv->message->v1.output = output1;  
 }  
 if (is_v2) {  
   drv->message->v2.output = output2;  
   size = args->scalarInput[2];  
   if ((int64_t)size > 0x200)  
     size = 0x200LL;  
   drv->message->v2.size = size;  
   ret = copyin(args->scalarInput[1], &drv->message->v2.buf, size);  
 } else {  
   drv->message->v1.output = output1;  
   ret = copyin(args->scalarInput[1], &drv->message->v1.buf, 0x100uLL);  
 }  
 drv->is_v2 = is_v2;  
 return ret;  
}  
```

One vulnerability stands out, since there is no good reason for doing  
`(size - 1) & 0xFFF`. It draws attention to the `(int64_t)size >  
(int64_t)drv->message->v2.size` comparison, which also has no good reason to
be  
signed. And indeed, storing an empty v2 message and then reading -1 bytes
leaks  
0xFFF bytes of stack.

A similar problem exists for writing v2 messages.

Finally, the code does not use synchronization, so there are various data  
races.

## Exploitation

### Breaking KASLR

In the `baby_read(-1)` leak, one can find the address for returning to the  
`is_io_connect_method()` at a fixed offset, which makes it possible to compute  
the kernel base.

### Controlling RIP

It's tempting to do `baby_leaveMessage(v2, -1)`, making `copyout()` write as  
many bytes as we want to the heap - arranging it to stop by putting the  
userspace buffer right before a `PROT_NONE` page. Unfortunately, `copyout()`  
[panics](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-10002.41.9/osfmk/x86_64/copyio.c#L182  
) on large sizes, downgrading this bug to a mere DoS.

Race, on the other hand, is quite viable. The goal is to overwrite `v2.output`  
with a controlled value by racing reads with writes that switch from v1 to v2:

```  
writer                               reader  
-----------------------------------  ----------------------------------------------  
                                    if (is_v2) {  
                                    ...  
                                    memset(buf_v2, 0, sizeof(buf_v2));  
ret = copyin(args->scalarInput[1],  
            &drv->message->v1.buf,  
            0x100uLL);  
                                    drv->message->v2.output(buf_v2,  
                                                            drv->message->v2.buf,  
                                                            drv->message->v2.size);  
```

Missing the race is not dangerous in most situations, except when the writer  
thread updates `drv->message->v1.output` and stalls. In this case the reader  
thread will use a very large size, causing a panic. But the probability of
this  
happening doesn't seem to be significant enough for a CTF challenge.

As a result, we can jump anywhere, with RDI (`buf_v2`) pointing to stack, and  
RSI (`drv->message->v2.buf`) pointing to up to 0x200 bytes of controlled data.

### Pivoting stack

Since we control the data at RSI, we can perform JOP. It's hard to do many  
useful things with JOP alone, so we need to convert it to ROP like this:

```  
gadget_1: add rsi, 0x58 ; call rax  
gadget_2: mov rsp, rsi  ; call rdi  
```

Unfortunately there are not enough gadgets for setting up RAX and RDI that do  
not conflict with each other. So we need to go for an even simpler chain that  
loads a constant into RSI, and for that we need to leak the message address,  
which is as easy as using a single `mov [rdi+8], rsi; ret` gadget.

With that, we can build a JOP chain that [pivots to RSI +
0x70](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L238).

### Executing shellcode

It should be possible to achieve privilege escalation with ROP alone, but I  
deemed it to be too hard to debug, therefore I wanted to go for jumping to  
userspace shellcode that would do all the heavy lifting. The [chain](  
pwnit.c#L270) for that is quite simple: we only need to disable SMEP and SMAP  
in CR4, for which the good gadgets exist.

I've decided to write as much
[shellcode](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L147)
in C as possible. I  
needed assembly only for
[switching](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L172)
to the statically allocated  
stack in order to avoid damaging the kernel heap, and then for [switching](  
pwnit.c#L159) back to the kernel stack.

### Escalating privileges

While kernel functions cannot be called from shellcode directly, since it's  
not linked with the kernel, calculating their addresses from the known kernel  
base and casting them to strongly typed function pointers is easy. The kernel  
base is stored by the userspace portion of the exploit in a global variable,  
and this variable is available from the shellcode.

The kernel allocates credentials in read-only memory, so they cannot be
updated  
directly. Instead, there are a couple kernel functions that need to be used:  
[`proc_update_label()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_proc.c#L1813  
) and [`kauth_cred_setresuid()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_credential.c#L3924  
). The usage example can be found in the [`setuid()` implementation](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_prot.c#L679  
).

One difficulty is that `proc_update_label()` takes a closure as an argument.  
For the purpose of making one in the exploit, a closure is just an array of  
3 pointers, the last one being a function pointer.

With that, we can safely set all kinds of uids to 0.

### Resuming the kernel module

Now we need to return to userspace. There is `return_to_user()` for that,  
however, using it directly results in all sorts of nasty consequences.

For instance, IOKit takes some lock, which is then not released. There is a  
sanity check that causes a panic if `current_thread()->rwlock_count` is not 0  
when returning to userspace. It can be fooled by manually decrementing that  
value, but of course this causes a deadlock sooner or later.

Therefore, we better return back to the kernel module. For that, the exploit  
needs to switch back to the kernel stack. We've lost the original value when  
pivoting, so we need to calculate it. The kernel stack base is stored in  
`current_cpu_datap()->cpu_kernel_stack`. We can then scan it for known
pointers  
that have to be there, such as the return address to `is_io_connect_method()`,  
and subtract a fixed offset from that.

We also need to restore a handful of values that were damaged by the exploit:  
* RBP, which is at the fixed offset from RSP.  
* The saved length, which was set to a very large value by the race, and needs  
 to be changed to something more reasonable for `copyout()` to not panic.  
* R14, which is used by `is_io_connect_method()` and has to be 0.

With that, we happily return to userspace as root, and can read the flag
and/or  
spawn the shell.

# Conclusion

That was quite an interesting introduction to the macOS kernel pwn. Definitely  
not the easiest possible, but at least no knowledge of heap feng-shui was  
required.

OSX-KVM + GDB provides a reasonable debugging environment, which could  
nevertheless be improved, first and foremost, by adding or fixing the GDB  
support for parsing Mach-O symbols.

The amount of learning materials on the web is limited, comparing to the Linux  
kernel pwn, but still enough for getting started. The availability of the XNU  
kernel source code is a godsend. I found the following links especially
useful:

* https://www.usenix.org/system/files/conference/woot17/woot17-paper-xu.pdf  
* https://github.com/A2nkF/macOS-Kernel-Exploit

The macOS kernel mitigations and sanity checks are somewhat different from  
those in the Linux kernel, but the challenge author was merciful enough to
give  
us the tools to circumvent them with reasonable effort.

Overall, this was quite hard as a first macOS kernel pwn experience - it took  
me about 20 hours to solve it (including install and reinstall times) - but
I'm  
still glad I looked into it.  

Original writeup
(https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver).# BabyKitDriver

## Description

Pwnable, 7 solved, 647 Pts.

qemu+macOS ventura 13.6.1

upload your exploit binary and the server will run it for you, you can get the
output of your exploit.

the flag is at /flag

Just pwn my first IOKit Driver!

nc baby-kit-driver.ctf.0ops.sjtu.cn 20001

[attachment](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/BabyKitDriver.kext_D5ED88B9E517723BF57C28E742D3AE49.zip)

## Summary

macOS 13.6.1 kernel module pwn. Solve quite an expensive PoW, send a binary,
and  
get its output back.

## TL;DR

* Install [OSX-KVM](https://github.com/kholia/OSX-KVM) using the [offline](  
https://github.com/kholia/OSX-KVM/blob/master/run_offline.md) method.  
* Boot with `./OpenCore-Boot.sh`.  
 * Add `-s` to `OpenCore-Boot.sh` for enabling the [qemu gdbstub](  
https://wiki.qemu.org/Features/gdbstub) for kernel debugging.  
 * If dropped to the [UEFI shell](  
https://chriswayg.gitbook.io/opencore-visual-beginners-guide/advanced-
topics/opencore-uefi-shell  
   ), do:  
   ```  
   fs0:  
   cd efi/boot  
   bootx64.efi  
   ```  
* Use [docker-osxcross](https://github.com/crazy-max/docker-osxcross) for  
 [compiling the
exploit](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/Makefile).  
* Build [gdb](https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git) with  
 `--target=x86_64-apple-darwin13` for kernel debugging.  
* [Enable SSH](https://support.apple.com/lt-lt/guide/mac-help/mchlp1066/mac).  
* Copy and load the vulnerable kernel module with `kextload`. The first time an  
 approval via GUI and a reboot are needed.  
* Copy the kernel from `/System/Library/Kernels/kernel` to the host, load it  
 into the favorite decompiler. The kernel sources can be found [here](  
https://github.com/apple-oss-distributions/xnu).  
* Check `/Library/Logs/DiagnosticReports/Kernel-*.panic` for panic messages.  
* After gdb is attached, the VM is normally stopped in [`machine_idle()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-10002.41.9/osfmk/i386/pmCPU.c#L175  
 ). This makes it possible to [infer the KASLR
base](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/gdbscript)
for debugging  
 purposes.  
* Breakpoints work reliably. Single-stepping is only possible with `stepi`.  
 Other commands, like `nexti`, more often than not, cause gdb to lose control.  
 When using `si`, disable interrupts by clearing IF using  
 `set $eflags=$eflags&~0x200`, and set it back before `continue`.  
* The kernel module allows reading and writing a buffer, which is stored in the  
 following format:  
 ```  
 union message {  
   struct {  
     void (*output)(void *dest, const void *src);  
     char buf[0x100];  
   } v1;  
   struct v2 {  
     size_t size;  
     void (*output)(void *dest, const void *src, size_t size);  
     char buf[0x200];  
   };  
   char raw[0x300];  
 };  
 ```  
* Leak the kernel stack contents by reading -1 bytes from a v2 buffer.  
* Obtain the RIP + RSI + *RSI control by racing reading vs the v2 -> v1  
 transition. Stabilize the race by storing the *RSI payload in advance.  
* Pivot stack to RSI using JOP.  
* Disable SMEP/SMAP and jump to the userspace shellcode using ROP.  
* Get root by calling `proc_update_label()` and `kauth_cred_setresuid()`. The  
 creds are stored in read-only pages, so a direct write is not an option.  
* Restore the original RSP by scanning for leaked data starting at  
 `current_cpu_datap()->cpu_kernel_stack`. Tweak a few other registers and  
 values in memory, and return to the kernel module.  
* Try reading the flag, retry the race on failure.  
* `flag{7ac21f7848a39f0aea63fa29d304226a}`

## Setup

### OS

As the description states, the challenge runs in QEMU, so it should be
possible  
to recreate the remote setup on the local Linux host. OSX-KVM turned up in  
search and was quite usable. The installation steps from the front page worked  
like a charm, but resulted in macOS 13.5.2, which was not what the challenge  
description said. Using `softwareupdate -i 'macOS Ventura 13.6.1-22G313'`  
failed with `MSU_ERR_STAGE_SPLAT_FAILED` with no further explanations. The  
attempt to do a manual upgrade by downloading the image with
[`./macrecovery.py  
download -b Mac-B4831CEBD52A0C4C -m 00000000000000000`](  
https://github.com/acidanthera/OpenCorePkg/tree/0.9.7/Utilities/macrecovery)  
bricked the system. The offline installer worked, though.

Booting the system with `./OpenCore-Boot.sh` sometimes dropped me to the scary  
UEFI shell instead of the nice graphical menu. To get to the menu, I needed to  
run `fs0:/efi/boot/bootx64.efi` manually.

### Building

It should be possible to build the exploit natively, but I preferred to use
the  
host as much as possible, so I used the `crazymax/osxcross:13.1-ubuntu` docker  
image with the cross-compilers and the SDK. Somewhat counter-intuitively, the  
image comes only with the cross-toolchain and nothing else. So I had to create  
a [`Dockerfile`](image/Dockerfile) that added the base system.

### Testing

Enabling SSH in the guest helped create automation for the other steps, such
as  
loading the kernel module, uploading and running the exploit, and reading
crash  
logs, which I put into the
[Makefile](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/Makefile).
The port forwarding was  
already set up in `OpenCore-Boot.sh`, so I only had to upload my public key  
and put the following into `~/.ssh/config` on the host:

```  
Host OSX-KVM  
       Hostname localhost  
       Port 2222  
       IdentityFile ~/.ssh/id_ecdsa  
       IdentitiesOnly yes  
```

### Debugging

The kernel is stored in `/System/Library/Kernels/kernel` inside the guest and  
can be easily copied to the host with `scp`. There are symbols inside it, so I  
hoped I could use it with GDB. Unfortunately, my distro `gdb-multiarch` didn't  
support Mach-O binaries, [Apple GDB](https://opensource.apple.com/source/gdb/)  
could not be built on Linux, and building GDB from source for the  
`x86_64-apple-darwin` target did not produce a GDB binary. After staring at
the  
GDB's `configure` script for a while, I realized that I had to target  
`x86_64-apple-darwin13`! The resulting GDB accepted the kernel, but did not  
load any symbols anyway, so I had to proceed with debugging the raw asm.

Knowing the randomized kernel base is important for debugging. It can be
easily  
calculated using the observation that attaching the debugger almost always  
interrupts the VM at the `*fc6: cli` instruction, which can be then found in  
the kernel binary like this:  
```  
$ llvm-objdump -d kernel|grep fc6.*cli  
ffffff80004dafc6: fa                    cli  
```

The randomized kernel module base is also important. The `kextstat  
-b keen.BabyKitDriver` command shows the non-randomized base, which then needs  
to be adjusted by the value of `vm_kernel_slide`. Yes, kernel and modules use  
the same slide value.

With that, it's possible to put breakpoints on the kernel and on the module.

## Analysis

As the description states, the module is written using the IOKit framework.  
That's the first time I've seen it; the [old Apple docs](  
https://developer.apple.com/library/archive/documentation/DeviceDrivers/Conceptual/IOKitFundamentals/Introduction/Introduction.html  
) read like marketing materials, and the [new Apple docs](  
https://developer.apple.com/documentation/kernel/iokit_fundamentals) are quite  
concise, but in general it's not that different from Windows or Linux driver  
frameworks.

The driver provides the following two `externalMethods`, which are quite  
similar to ioctls:

```  
kern_return_t BabyKitDriverUserClient::baby_read(void *ref,
IOExternalMethodArguments *args) {  
 BabyKitDriver *drv;  
 kern_return_t ret;  
 char buf_v1[256];  
 char buf_v2[512];  
 size_t size;  
 bool is_v2;

 drv = (BabyKitDriver *)getProvider();  
 is_v2 = drv->is_v2;  
 IOLog("BabyKitDriverUserClient::baby_read\n");  
 IOLog("version:%lld\n", is_v2);  
 if (!drv->message)  
   return 0;  
 if (is_v2) {  
   size = args->scalarInput[1];  
   if ((int64_t)size > (int64_t)drv->message->v2.size)  
     size = drv->message->v2.size;  
   memset(buf_v2, 0, sizeof(buf_v2));  
   drv->message->v2.output(buf_v2, drv->message->v2.buf,
drv->message->v2.size);  
   ret = copyout(buf_v2, args->scalarInput[0], (size - 1) & 0xFFF);  
 } else {  
   memset(buf_v1, 0, sizeof(buf_v1));  
   drv->message->v1.output(buf_v1, &drv->message->v1.buf);  
   ret = copyout(buf_v1, args->scalarInput[0], 0x100);  
 }  
 return ret;  
}

kern_return_t BabyKitDriverUserClient::baby_leaveMessage(void *ref,
IOExternalMethodArguments *args) {  
 BabyKitDriver *drv;  
 kern_return_t ret;  
 __int64 is_v2;  
 size_t size;

 drv = (BabyKitDriver *)getProvider();  
 is_v2 = args->scalarInput[0];  
 IOLog("BabyKitDriverUserClient::baby_leaveMessage\n");  
 if (!drv->message) {  
   drv->message = (struct message *)IOMalloc(sizeof(struct message));  
   if (is_v2)  
     drv->message->v2.output = output2;  
   else  
     drv->message->v1.output = output1;  
 }  
 if (is_v2) {  
   drv->message->v2.output = output2;  
   size = args->scalarInput[2];  
   if ((int64_t)size > 0x200)  
     size = 0x200LL;  
   drv->message->v2.size = size;  
   ret = copyin(args->scalarInput[1], &drv->message->v2.buf, size);  
 } else {  
   drv->message->v1.output = output1;  
   ret = copyin(args->scalarInput[1], &drv->message->v1.buf, 0x100uLL);  
 }  
 drv->is_v2 = is_v2;  
 return ret;  
}  
```

One vulnerability stands out, since there is no good reason for doing  
`(size - 1) & 0xFFF`. It draws attention to the `(int64_t)size >  
(int64_t)drv->message->v2.size` comparison, which also has no good reason to
be  
signed. And indeed, storing an empty v2 message and then reading -1 bytes
leaks  
0xFFF bytes of stack.

A similar problem exists for writing v2 messages.

Finally, the code does not use synchronization, so there are various data  
races.

## Exploitation

### Breaking KASLR

In the `baby_read(-1)` leak, one can find the address for returning to the  
`is_io_connect_method()` at a fixed offset, which makes it possible to compute  
the kernel base.

### Controlling RIP

It's tempting to do `baby_leaveMessage(v2, -1)`, making `copyout()` write as  
many bytes as we want to the heap - arranging it to stop by putting the  
userspace buffer right before a `PROT_NONE` page. Unfortunately, `copyout()`  
[panics](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-10002.41.9/osfmk/x86_64/copyio.c#L182  
) on large sizes, downgrading this bug to a mere DoS.

Race, on the other hand, is quite viable. The goal is to overwrite `v2.output`  
with a controlled value by racing reads with writes that switch from v1 to v2:

```  
writer                               reader  
-----------------------------------  ----------------------------------------------  
                                    if (is_v2) {  
                                    ...  
                                    memset(buf_v2, 0, sizeof(buf_v2));  
ret = copyin(args->scalarInput[1],  
            &drv->message->v1.buf,  
            0x100uLL);  
                                    drv->message->v2.output(buf_v2,  
                                                            drv->message->v2.buf,  
                                                            drv->message->v2.size);  
```

Missing the race is not dangerous in most situations, except when the writer  
thread updates `drv->message->v1.output` and stalls. In this case the reader  
thread will use a very large size, causing a panic. But the probability of
this  
happening doesn't seem to be significant enough for a CTF challenge.

As a result, we can jump anywhere, with RDI (`buf_v2`) pointing to stack, and  
RSI (`drv->message->v2.buf`) pointing to up to 0x200 bytes of controlled data.

### Pivoting stack

Since we control the data at RSI, we can perform JOP. It's hard to do many  
useful things with JOP alone, so we need to convert it to ROP like this:

```  
gadget_1: add rsi, 0x58 ; call rax  
gadget_2: mov rsp, rsi  ; call rdi  
```

Unfortunately there are not enough gadgets for setting up RAX and RDI that do  
not conflict with each other. So we need to go for an even simpler chain that  
loads a constant into RSI, and for that we need to leak the message address,  
which is as easy as using a single `mov [rdi+8], rsi; ret` gadget.

With that, we can build a JOP chain that [pivots to RSI +
0x70](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L238).

### Executing shellcode

It should be possible to achieve privilege escalation with ROP alone, but I  
deemed it to be too hard to debug, therefore I wanted to go for jumping to  
userspace shellcode that would do all the heavy lifting. The [chain](  
pwnit.c#L270) for that is quite simple: we only need to disable SMEP and SMAP  
in CR4, for which the good gadgets exist.

I've decided to write as much
[shellcode](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L147)
in C as possible. I  
needed assembly only for
[switching](https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver/pwnit.c#L172)
to the statically allocated  
stack in order to avoid damaging the kernel heap, and then for [switching](  
pwnit.c#L159) back to the kernel stack.

### Escalating privileges

While kernel functions cannot be called from shellcode directly, since it's  
not linked with the kernel, calculating their addresses from the known kernel  
base and casting them to strongly typed function pointers is easy. The kernel  
base is stored by the userspace portion of the exploit in a global variable,  
and this variable is available from the shellcode.

The kernel allocates credentials in read-only memory, so they cannot be
updated  
directly. Instead, there are a couple kernel functions that need to be used:  
[`proc_update_label()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_proc.c#L1813  
) and [`kauth_cred_setresuid()`](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_credential.c#L3924  
). The usage example can be found in the [`setuid()` implementation](  
https://github.com/apple-oss-
distributions/xnu/blob/xnu-8796.101.5/bsd/kern/kern_prot.c#L679  
).

One difficulty is that `proc_update_label()` takes a closure as an argument.  
For the purpose of making one in the exploit, a closure is just an array of  
3 pointers, the last one being a function pointer.

With that, we can safely set all kinds of uids to 0.

### Resuming the kernel module

Now we need to return to userspace. There is `return_to_user()` for that,  
however, using it directly results in all sorts of nasty consequences.

For instance, IOKit takes some lock, which is then not released. There is a  
sanity check that causes a panic if `current_thread()->rwlock_count` is not 0  
when returning to userspace. It can be fooled by manually decrementing that  
value, but of course this causes a deadlock sooner or later.

Therefore, we better return back to the kernel module. For that, the exploit  
needs to switch back to the kernel stack. We've lost the original value when  
pivoting, so we need to calculate it. The kernel stack base is stored in  
`current_cpu_datap()->cpu_kernel_stack`. We can then scan it for known
pointers  
that have to be there, such as the return address to `is_io_connect_method()`,  
and subtract a fixed offset from that.

We also need to restore a handful of values that were damaged by the exploit:  
* RBP, which is at the fixed offset from RSP.  
* The saved length, which was set to a very large value by the race, and needs  
 to be changed to something more reasonable for `copyout()` to not panic.  
* R14, which is used by `is_io_connect_method()` and has to be 0.

With that, we happily return to userspace as root, and can read the flag
and/or  
spawn the shell.

# Conclusion

That was quite an interesting introduction to the macOS kernel pwn. Definitely  
not the easiest possible, but at least no knowledge of heap feng-shui was  
required.

OSX-KVM + GDB provides a reasonable debugging environment, which could  
nevertheless be improved, first and foremost, by adding or fixing the GDB  
support for parsing Mach-O symbols.

The amount of learning materials on the web is limited, comparing to the Linux  
kernel pwn, but still enough for getting started. The availability of the XNU  
kernel source code is a godsend. I found the following links especially
useful:

* https://www.usenix.org/system/files/conference/woot17/woot17-paper-xu.pdf  
* https://github.com/A2nkF/macOS-Kernel-Exploit

The macOS kernel mitigations and sanity checks are somewhat different from  
those in the Linux kernel, but the challenge author was merciful enough to
give  
us the tools to circumvent them with reasonable effort.

Overall, this was quite hard as a first macOS kernel pwn experience - it took  
me about 20 hours to solve it (including install and reinstall times) - but
I'm  
still glad I looked into it.  

Original writeup
(https://github.com/mephi42/ctf/tree/master/2023.12.09-0CTF_TCTF_2023/BabyKitDriver).