# wooter - Byte Bandits CTF 2020 (reverse, 500p)
## Introduction

wooter is a reverse task. It consists of a single elf64 binary, `lang`.

Runing it prints a bad boy.

```
% ./lang; echo $?
Epic Fail
127
```

Opening the binary in Ghidra shows it is very complex. It would be very
time-consuming to reverse it.


## Identifying input

Using `strace` shows that the binary does not issue particularly strange
syscalls. It means that the binary does not interact with the filesystem.
Therefore, it means that the flag is not store on the file system.

```
% strace ./lang 
execve("./lang", ["./lang"], 0x7d0589ebc160 /* 47 vars */) = 0
[...]
ioctl(0, TCGETS, {B38400 opost isig icanon echo ...}) = 0
brk(NULL)                               = 0xd843513697f
brk(0xd843515797f)                      = 0xd843515797f
brk(0xd8435158000)                      = 0xd8435158000
mmap(NULL, 909312, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x6ba6cb5a9000
select(2, [], [1], [1], NULL)           = 1 (out [1])
write(1, "Epic Fail\n", 10Epic Fail
)             = 10
ioctl(0, SNDCTL_TMR_START or TCSETS, {B38400 opost isig icanon echo ...}) = 0
exit_group(127)                         = ?
+++ exited with 127 +++
```

The remaining options are arguments and environment.

This can be checked with a watchpoint in `gdb`
```
% gdb ./lang
Reading symbols from ./lang...
(No debugging symbols found in ./lang)
(gdb) starti flag{lorem_ipsum}
Starting program: /mnt/ctf/2020/2020-04-11-bytebandits/re/wooter/lang flag{lorem_ipsum}

Program stopped.
0x00007ffff7fd3100 in _start () from /lib64/ld-linux-x86-64.so.2
=> 0x00007ffff7fd3100 <_start+0>:	48 89 e7	mov    rdi,rsp


(gdb) x/8gz $rsp
0x7fffffffd3f0:	0x0000000000000002	0x00007fffffffd706
0x7fffffffd400:	0x00007fffffffd73a	0x0000000000000000
0x7fffffffd410:	0x00007fffffffd74c	0x00007fffffffd75f
0x7fffffffd420:	0x00007fffffffd77f	0x00007fffffffd787

(gdb) x/s *((char**)0x7fffffffd400)
0x7fffffffd73a:	"flag{lorem_ipsum}"

(gdb) rwatch *0x7fffffffd400
Hardware read watchpoint 1: *0x7fffffffd400

(gdb) c
Continuing.

Hardware read watchpoint 1: *0x7fffffffd400

Value = -10438
0x00000001000042ba in ?? ()
=> 0x00000001000042ba:	be 00 00 00 00	mov    esi,0x0

(gdb) where
#0  0x00000001000042ba in ?? ()
#1  0x0000000100006a18 in ?? ()
#2  0x00000001000072fb in ?? ()
#3  0x00007ffff7e03023 in __libc_start_main () from /usr/lib/libc.so.6
#4  0x00000001000018da in ?? ()
```

This shows that, the instruction at address `base + 0x42ba` does read `argv[1]`,
hinting that the program parses the first argument at some point.

## Dynamic analysis

`ltrace` shows interesting library calls :

```
% ltrace ./lang
time(0)                                                                  = 1586791791
srand(0x5e94856f, 0x78459e207de8, 0x6ca4b66f4080, 0x6ca4b66c1578)        = 0
tcgetattr(0, 0x307ceccb00)                                               = 0
realloc(0, 908560)                                                       = 0x6ca4b6424010
memcpy(0x6ca4b6428498, "iota", 4)                                        = 0x6ca4b6428498
memcpy(0x6ca4b64284a8, "=", 1)                                           = 0x6ca4b64284a8
memcpy(0x6ca4b64284b8, "<", 1)                                           = 0x6ca4b64284b8
memcpy(0x6ca4b64284c8, "<<", 2)                                          = 0x6ca4b64284c8
memcpy(0x6ca4b64284d8, ">>", 2)                                          = 0x6ca4b64284d8

[...]

memcpy(0x6ca4b643d1d0, "ERROR: fd 1111 with 1111111 had "..., 49)        = 0x6ca4b643d1d0
memcpy(0x6ca4b643d210, " - 11111111", 11)                                = 0x6ca4b643d210
memcpy(0x6ca4b643d228, "1111111111111111111111 ", 23)                    = 0x6ca4b643d228
memcpy(0x6ca4b643d248, "1111111111111111111111 ", 23)                    = 0x6ca4b643d248
memcpy(0x6ca4b643d268, "not sure how to 11111 ", 22)                     = 0x6ca4b643d268
memcpy(0x6ca4b643e0f8, "1111", 4)                                        = 0x6ca4b643e0f8
memcpy(0x6ca4b643e108, "1111111111111", 13)                              = 0x6ca4b643e108
memcpy(0x6ca4b643e120, "111111111111111111111111111", 27)                = 0x6ca4b643e120
memcpy(0x6ca4b643e148, "syscall 14 - memlimit exceeded, "..., 49)        = 0x6ca4b643e148
memcpy(0x6ca4b643ed60, "11111111111111111111111111111111"..., 43)        = 0x6ca4b643ed60
memcpy(0x6ca4b643eed8, "W00t W00t!", 10)                                 = 0x6ca4b643eed8
memcpy(0x6ca4b643eef0, "Epic Fail", 9)                                   = 0x6ca4b643eef0
memcpy(0x6ca4b643ef08, "Epic Fail", 9)                                   = 0x6ca4b643ef08
memcpy(0x6ca4b643ef20, "Epic Fail", 9)                                   = 0x6ca4b643ef20

[...]

rand(0x6ca4b643f898, 0x6ca4b643f8d0, 0x6ca4b64289a9, 0x6ca4b6428478)     = 0x2c47698e
rand(0x6ca4b66c15a0, 0x78459e207834, 0x2c47698c, 0x2c47698e)             = 0xc8b81e0
rand(0x6ca4b66c15a0, 0x78459e207834, 0x6ca4b64289ad, 0)                  = 0x57a40811
rand(0x6ca4b66c15a0, 0x78459e207834, 0x6ca4b64289b1, 0x57a40811)         = 0x303efacc
rand(0x6ca4b66c15a0, 0x78459e207834, 0x6ca4b64289b5, 0x303efacc)         = 0x27344776
rand(0x6ca4b66c15a0, 0x78459e207834, 0x27344775, 0x27344776)             = 0x421deed
rand(0x6ca4b66c15a0, 0x78459e207834, 0x6ca4b64289bc, 24)                 = 0x43276989
rand(0x6ca4b66c15a0, 0x78459e207834, 0x6ca4b64289e1, 0x43276989)         = 0x116976b7
rand(0x6ca4b66c15a0, 0x78459e207834, 0x6ca4b64289e5, 0x116976b7)         = 0x517f5dac
rand(0x6ca4b66c15a0, 0x78459e207834, 0x517f5daa, 0x517f5dac)             = 0x40bcf14e
rand(0x6ca4b66c15a0, 0x78459e207834, 0x6ca4b64289e9, 0)                  = 0x506166fd
rand(0x6ca4b66c15a0, 0x78459e207834, 0x506166fc, 0x506166fd)             = 0x21a88e57

[...]

tcsetattr(0, 0, 0x307ceccb00)                                            = 0
+++ exited (status 127) +++
```

This suggest that the binary is packed.

After looking more in-depth, it turns out that the binary contains a blob that
is xored with 0x31. This is then interpreted as the bytecode for a custom
virtual machine.

The multiple calls to `rand` are done while interpreting the instructions in a
loop that looks like the following code :
```c
if (rand() % 3 != 0) {
	int i = rand();

	while (0 < i)
		i--;
}
```

This probably has two uses : it slows down the execution of the binary and makes
the total instruction count of the program to be inaccurate to prevent people
from using side-channel attacks against this VM.

Hooking `rand` to make it always return 0 makes the binary runs significantly
faster:
```
$ time LD_PRELOAD=./norand.so ./lang flag{lorem_ipsum}
Epic Fail

real	0m0.002s
user	0m0.002s
sys	0m0.000s

$ time ./lang flag{lorem_ipsum}
Epic Fail

real	0m0.572s
user	0m0.568s
sys	0m0.004s
```

This means the whole area between `0x51AF` and `0x5206` can be patched. The
patch will be executed once every instruction.

This can be used to count the number of instructions run by the virtual machine,
and infer which path it takes without looking at the implementation.

The patch used to solve this task can be found in the appendices.

```sh
% ./patched aaa | wc
      1       3   10741

% ./patched aaaa | wc
      1       3   11155
```


## Determining the flag length

The flag format for this CTF is `flag{...}` (most of the time. Looking at you,
gremlins).

This information can be used to determine the length of the flag : the virtual
machine probably checks the length of the input before checking each characters.
This means that if the length is correct, `fxxxxxxxx` should take more
instructions than `gxxxxxxxx`.

When the size is too small, the instruction count stays the same :
```
% ./patched aaaa | wc
      1       3   11155

% ./patched flag | wc
      1       3   11155
```


However, once we pass 63 characters, the instruction count starts to change :
```
% ./patched f$(printf '%061d') | wc
      1       3   35167
% ./patched a$(printf '%061d') | wc
      1       3   35167

% ./patched a$(printf '%062d') | wc
      1       3   42941
% ./patched f$(printf '%062d') | wc
      1       3   43015
```

It is safe to assume that the flag has a length of 63 characters.


## Finding the flag

Based on the same idea, it is possible to bruteforce the flag, character by
character. The number of instructions (or rather, instructions + outputted
characters) is : `42941 + 74 * k`.


```
% php ./pwn.php
f______________________________________________________________
fl_____________________________________________________________
fla____________________________________________________________
flag___________________________________________________________
flag{__________________________________________________________
[...]
flag{only_if_I_h4d_mor3_tim3_this_chall_would_hav3_b333n_gr3___
flag{only_if_I_h4d_mor3_tim3_this_chall_would_hav3_b333n_gr34__
flag{only_if_I_h4d_mor3_tim3_this_chall_would_hav3_b333n_gr34t_
flag{only_if_I_h4d_mor3_tim3_this_chall_would_hav3_b333n_gr34t}
```

**Flag**: `flag{only_if_I_h4d_mor3_tim3_this_chall_would_hav3_b333n_gr34t}`

## Appendices

### norand.c
```c
int rand() { return 0; }
```

### patch.S
```asm
push rax
push rdi
push rsi
push rdx

push 0x2e
mov  rdi, 2
mov  rsi, rsp
mov  rdx, 1
mov  rax, SYS_write
syscall

add rsp, 8
pop rdx
pop rsi
pop rdi
pop rax
```

### patch.php
```php
<?php
const START = 0x51AF;
const END   = 0x5206;

$file  = file_get_contents("lang");
$patch = file_get_contents("patch");
$patch = str_pad($patch, END - START, "\x90");

echo substr($file, 0, START) . $patch . substr($file, END);
```

### pwn.php
```php
<?php
const CMDLINE = "./patched %s";
const SIZE    = 63;

function flag($str)
{
        $cmdline = sprintf(CMDLINE, escapeshellarg($str));
        $ret = shell_exec($cmdline);
        return strlen($ret);
}

$flag = "";

$charset  = "_";
$charset .= "abcdefghijklmnopqrstuvwxyz";
$charset .= strtoupper($charset);
$charset .= "0123456789";
$charset .= "{}";

while(strlen($flag) < SIZE) {
        foreach(str_split($charset) as $c) {
                $try = str_pad($flag . $c, SIZE, "_");
                printf("\r%s", $try);

                $count = flag($try);
                if($count != 42941 + 74 * strlen($flag)) {
                        printf("\n");
                        $flag .= $c;
                        break;
                }
        }
}
```