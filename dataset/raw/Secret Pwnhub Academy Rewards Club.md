# Secret Pwnhub Academy Rewards Club

## Solution

Nice intro to SPARC challenge. The vulnerability is straightforward and is a
classic stack-based buffer overflow. We are provided with a stack leak and can
overwrite the stored instruction pointer. Because the stack is RWX, we can
jump back to our input that is stored at the leaked stack address. Once you
find the `fn` function in the binary, Ghidra's decompilation makes the
vulnerability straightforward to see:

```c  
void fn(void)  
{  
 int iVar1;  
 ssize_t sVar2;  
 int *piVar3;  
 char *pcVar4;  
 int iVar5;  
 longlong lVar6;  
 undefined auStackX0 [92];  
 undefined auStack128 [128];  
  
 lVar6 = ZEXT48(register0x00000038) << 0x20;  
 printf("%p\n",auStack128);  
 read(0,(void *)((int)((ulonglong)lVar6 >> 0x20) + -0x80),0x200);  
 do {  
   sVar2 = read(0,(void *)((int)((ulonglong)lVar6 >> 0x20) + -0x80),0x200 -
already_read);  
   iVar1 = sVar2 + last_read;  
   last_read = iVar1;  
   if (iVar1 < 0) {  
     piVar3 = __errno_location();  
     iVar5 = *piVar3;  
     piVar3 = __errno_location();  
     pcVar4 = strerror(*piVar3);  
     printf("Read error: %d, errno: %d [%s]\n",iVar1,iVar5,pcVar4);  
                   /* WARNING: Subroutine does not return */  
     exit(1);  
   }  
   already_read = already_read + iVar1;  
 } while ((already_read != 0x200) &&  
         (*(char *)((int)((ulonglong)lVar6 >> 0x20) + already_read + -0x81) != '\n'));  
 return;  
```

It was nice of the challenge author to provide various scripts and a
[`Dockerfile`](./Dockerfile) for running and debugging the challenge in a
production environment. I did make a small edit to the
[`run_docker_gdbserver.sh`](./run_docker_gdbserver.sh) script so that I could
use `gdb-multiarch` from my host. This resulted in workflow like:

* Run `./run_docker_gdbserver.sh` in one terminal. This starts the (emulated) challenge binary, which we can connect to on port `4444` on our host. Our first connection to this port will launch the target binary wrapped in gdbserver, listening on port `1234`.  
* Run `./solve.py REMOTE HOST=localhost PORT=4444` to start running our solution and kick off gdbserver.  
* Run `gdb-multiarch ./sparc-1 -ex "target remote :1234"` to debug the binary in the Docker container from our host.

After bumbling around with offsets and using a 32-bit SPARC shellcode found
online, we can eventually pop a shell.

## Resources

* [Good SPARC overview](https://en.wikibooks.org/wiki/SPARC_Assembly/SPARC_Details#Registers)  
* [SPARC instruction guide](https://arcb.csc.ncsu.edu/~mueller/codeopt/codeopt00/notes/sparc.html)  
* [Detailed SPARC instruction reference](https://www.cs.princeton.edu/courses/archive/spring02/cs217/precepts/sparcassem.pdf)  
* [SPARC shellcoding guide and samples](https://www.exploit-db.com/papers/13218)  

Original writeup
(https://github.com/welchbj/ctf/tree/master/writeups/2020/hack-lu/secret-
pwnhub-academy-rewards-club).