# wisdom2  
Category: zahjebischte, pwn

Solves: 1  
Points: 1000

# Description  
[Oops, I did it
again.](https://2019.ctf.link/internal/challenge/1fef0346-a1de-4aa4-8df9-2d18229c6dbb/)
:^)

This is commit # 4232874270015d940a2ba62c113bcf12986a2151 with the attached
patch applied. Flag is in /dev/hdb.

Note that the setup of this task is perhaps a bit shaky: If you don’t get a
shell prompt within a few seconds after solving the proof of work, something
is wrong. Each connection has a time limit of 10 minutes; you may contact us
in case this causes problems for you.

# Files  
[wisdom2-c46f03732e9dceef.tar.xz](https://2020.ctf.link/assets/files/wisdom2-c46f03732e9dceef.tar.xz)

# Solution  
## Vulnerability  
The goal of this task was to find a vulneraility in the latest release of
[SerenityOS](http://serenityos.org) in order to read the flag from /dev/hdb.
After looking through the code for a while I noticed a vulnerability in the
ptrace implementation:  
When setting the registers of a thread by calling ptrace(PT\_SETREGS, pid,
&regs, 0), eventually the following code is reached (in
[Kernel/Ptrace.cpp](https://github.com/SerenityOS/serenity/blob/2dfe5751f35d0067747c6615bf139871cc105fa6/Kernel/Ptrace.cpp#L175)):  
```C++  
void copy_ptrace_registers_into_kernel_registers(RegisterState& kernel_regs,
const PtraceRegisters& ptrace_regs)  
{  
   kernel_regs.eax = ptrace_regs.eax;  
   kernel_regs.ecx = ptrace_regs.ecx;  
   kernel_regs.edx = ptrace_regs.edx;  
   kernel_regs.ebx = ptrace_regs.ebx;  
   kernel_regs.esp = ptrace_regs.esp;  
   kernel_regs.ebp = ptrace_regs.ebp;  
   kernel_regs.esi = ptrace_regs.esi;  
   kernel_regs.edi = ptrace_regs.edi;  
   kernel_regs.eip = ptrace_regs.eip;  
   kernel_regs.eflags = ptrace_regs.eflags;  
}  
```  
kernel\_regs are the register contents of the ptrace'd process, while
ptrace\_regs are the passed-in registers. Note that ptrace\_regs is not
checked at all. Can you spot the vulnerability?

If not, maybe [this](https://en.wikipedia.org/wiki/FLAGS_register) will help
you.

The vulnerability is that eflags can be set to arbitrary values. For example,
it is possible to set the IOPL bits (bits 12/13) to one, therefore allowing
access to I/O Ports (and the interrupt flag) in Ring 3 (userspace).

## Exploitation  
There are multiple ways to exploit this vulnerability, but the easiest one is
to set IOPL to 3 and then write (or copy ;) an ATA driver to read the flag
directly from the IDE drive (using ATA PIO mode). Note that it is also
possible to gain root privileges by writing to the main drive (just overwrite
a setuid binary or change the owner/mode of your own binary).  
Fortunately, simple ATA PIO drivers already exist and I decided to just use
[this
one](https://github.com/dhavalhirdhav/LearnOS/blob/fe764387c9f01bf67937adac13daace909e4093e/drivers/ata/ata.c).  
The exploit can be found
[here](https://github.com/allesctf/writeups/blob/master/2020/hxpctf/wisdom2/exploit.c).

## Fix  
I recommend to always clear the IOPL bits and to always set the interrupt
flag. If the nested task flag is not used in SerenityOS, it should also be
cleared.  
Also note that the same vulnerability is present in
[sigreturn](https://github.com/SerenityOS/serenity/blob/2dfe5751f35d0067747c6615bf139871cc105fa6/Kernel/Syscalls/sigaction.cpp#L112).

## Flag  
hxp{alL3\_j4Hr3\_w1eD3r\_k0MmT\_d3R\_r0oT\_eXpLO1t|http://serenityos.org/bounty}  

Original writeup
(https://github.com/allesctf/writeups/blob/master/2020/hxpctf/wisdom2/writeup.md).