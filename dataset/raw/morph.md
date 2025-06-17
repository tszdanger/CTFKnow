This Write-Up is about solving the `m0rph` challenge from
[34C3CTF](https://34c3ctf.ccc.ac/) using [IDA Pro](https://www.hex-
rays.com/products/ida/) and [radare2](https://github.com/radare/radare2).  
I chose this to start on, because it looked easy to me and was marked *easy*.  
So I planned on doing a detailed step-by-step guide.

## Getting to know the target

Get and unpack
[m0rph](https://34c3ctf.ccc.ac/uploads/m0rph-9d6440cf8e1e4c6825b2efa16b3f993d.tar.gz).

```  
$ wget
https://34c3ctf.ccc.ac/uploads/m0rph-9d6440cf8e1e4c6825b2efa16b3f993d.tar.gz  
$ tar -xzvf m0rph-9d6440cf8e1e4c6825b2efa16b3f993d.tar.gz  
$ cp m0rph/morph .  
$ sha256sum morph  
426070d85dd517363f328690d39c5399b833b5f2d7057980915f9012967774bc  morph  
```

First thing we notice is that the target is quite small.

```  
$ ls -lhS morph  
-rwxr-xr-x 1 koyaan koyaan 10K Dez 27 17:52 morph  
$ file morph  
morph: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically
linked,  
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32,  
BuildID[sha1]=1c81eb4bc8b981ed39ef79801d6fef03d4d81056, stripped  
```

So, `file` output suggest we got a stripped 64-bit ELF executable.  
Starting it with various inputs gives us nothing but a non-zero exit-code.

```  
$ ./morph  
koyaan@meld: ~/ccc/rev3/m0rph 1  
$ ./morph `python -c 'print("A"*1024)'`  
koyaan@meld: ~/ccc/rev3/m0rph 1  
$  
```

`strings` reveals one interesting string:

```  
$ strings morph  
/lib64/ld-linux-x86-64.so.2  
libc.so.6  
exit  
srand  
puts  
[...]  
What are you waiting for, go submit that flag!  
[...]  
.comment  
```

It looks like `morph` might just check a flag we submit for validity! Next, we
are going to load it up in `radare2`.

## Getting layout  
First we disable ASLR to make our life easier:

```  
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space  
```

Then we start `morph` in `radare2` and print the entrypoint with `ie`.

```  
$ radare2 -d ./morph  
Process with PID 21623 started...  
= attach 21623 21623  
bin.baddr 0x555555554000  
Using 0x5455555554000  
asm.bits 64  
[0x7ffff7dd7c30]> ie  
[Entrypoints]  
vaddr=0x5555555547a0 paddr=0x000007a0 baddr=0x555555554000 laddr=0x00000000  
haddr=0x00000018 type=program

1 entrypoints

[0x7ffff7dd7c30]>  
```

We see, that the base address of our executable is at `0x555555554000` and the
entrypoint is at `0x5555555547a0`.  
Next step is to disassemble `morph` with IDA Pro.

## Disassemble `morph`

First thing we do after letting the auto-analysis finish, is rebasing the
program, such that all addresses correspond with the ones observed in the
debugger.  
To do this we use _Edit | Segments | Rebase program..._ and entered the base address we observed in `radare2`, `0x555555554000`.

After rebasing, we start examining the `main` function and can immediately see
two checks that look a  
lot like checking `argc` and the length of `argv[1]` - and which get assigned
at the very beginning (see Figure 1).  
So we can rename `var_24` to `argc` and `var_30` to `argv`. Now we can assume
that `morph` takes one argument and it has to be 23  
characters long.

![Use of `argv` coming from `rsi` getting stored into
`var_30`](https://www.sigflag.at/assets/posts/m0rph/main-2.png "Figure 1: Use
of `argv` coming from `rsi` getting stored into `var_30`")

**Figure 1 -** Use of `argv` coming from `rsi` getting stored into `var_30

The function `sub_5555555541B0` allocates and sets up some structure with 23
elements at the location `qword_555555755900`. We rename this location to
`struct`, call this function `setupstruct` and also change its type to
`__fastcall` (see Figure 2).

![Function `setupstruct`](https://www.sigflag.at/assets/posts/m0rph/ida-
struct.png "Figure 2: Function `setupstruct`")

**Figure 2 -** Function `setupstruct`

We could now immediately start creating a proper structure in IDA Pro, but
let's try to get an overview of the program first.

Examining `sub_555555554267`, we see that it just shuffles the elements of
`struct` randomly.

```c  
void shufflestruct()  
{  
   unsigned int v0; // eax@1  
   int rand1; // ST10_4@2  
   int rand2_pre; // eax@2  
   __int64 temp; // ST18_8@2  
   signed __int64 rand2; // rcx@2  
   signed int i; // [sp+Ch] [bp-14h]@1

   v0 = time(0LL);  
   srand(v0);  
   for ( i = 0; i <= 255; ++i )  
   {  
       rand1 = rand() % 22 + 1;  
       rand2_pre = rand();  
       temp = *(_QWORD *)(8LL * rand1 + struct);  
       rand2 = 8LL * (rand2_pre % 22 + 1);  
       *(_QWORD *)(struct + 8LL * rand1) = *(_QWORD *)(rand2 + struct);  
       *(_QWORD *)(struct + rand2) = temp;  
   }  
}  
```

In the the lower part of `main`, we can see a loop and rename the loop
variable `loop_i`.

![Checking loop in `main`](https://www.sigflag.at/assets/posts/m0rph/main-
lower-edit.png "Figure 3: Checking loop in `main`")

**Figure 3 -** Checking loop in `main`

What we cannot follow here are the two `call eax` we see in Figure 3. Let's
figure out what happens there with `radare2`.  
From the normal view in IDA Pro we can see they happen at `0x0000555555554B95`
and `0x0000555555554BC6`.

## Debugging with `radare2`

We start `morph` with an initial guess based on the known flag format, set
breakpoints on the `call eax` instructions with `db` and continue the program
with `dc`.

```  
$ radare2 -d ./morph 34C3_AAAAAAAAAAAAAAAAAA  
Process with PID 2544 started...  
= attach 2544 2544  
bin.baddr 0x555555554000  
Using 0x555555554000  
asm.bits 64  
[0x7ffff7dd7c30]> db 0x0000555555554B95  
[0x7ffff7dd7c30]> db 0x0000555555554BC6  
[0x7ffff7dd7c30]> dc  
hit breakpoint at: 555555554b95  
[0x555555554b95]>  
```

We then use `V` to go to visual mode and `p` two times to cycle to debugger
view (`P` cycles backwards).  
This leaves us at the view of Figure 4.

![At the call](https://www.sigflag.at/assets/posts/m0rph/radare.png "Figure 4:
At the call")

**Figure 4 -** At the call

We now step into the call with `F7` and step more times until we reach the
`cmp` instruction (see Figure 5).

![Passing check](https://www.sigflag.at/assets/posts/m0rph/radare-2.png
"Figure 5: Passing check")

**Figure 5 -** Passing check

We hit `:` to get into command mode and enter `px 23 @ rdi` to dump 23 bytes
in hex-format starting from the  
address stored in `rdi`. We can confirm this is our flag under scrutiny!

```  
:> px 23 @ rdi  
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  0123456789ABCD  
0x7fffffffe09b  3334 4333 5f41 4141 4141 4141 4141  34C3_AAAAAAAAA  
0x7fffffffe0a9  4141 4141 4141 4141 41              AAAAAAAAA  
```  
Since this check is fine, let's continue with `dc`, step 4 times (`4ds`), seek
to `rip` (`s rip`) and hit enter then to go back to visual mode (see Figure
6).  
We see one of the 'A's is getting compared to 'h' (`cmp al, 0x68`). We see
which one by printing `px 23 @ rdi` again.  
Subtracting this from the known start address gives us the numerical offset
into the flag with the evaluate command `?`.

```  
:> dc  
child stopped with signal 28  
[+] SIGNAL 28 errno=0 addr=0x00000000 code=128 ret=0  
hit breakpoint at: 555555554b95  
:> 4ds  
:> s rip  
:> dr al  
0x00000041  
:> px 23 @ rdi  
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  0123456789ABCD  
0x7fffffffe0ab  4141 4141 4141 4100 5844 475f 5654  AAAAAAA.XDG_VT  
0x7fffffffe0b9  4e52 3d37 004c 435f 50              NR=7.LC_P  
:> ? rdi-0x7fffffffe09b  
16 0x10 020 16 0000:0010 16 "\x10" 0b00010000 16.0 16.000000f 16.000000 0t121  
:>  
```  
This shows that the 17th character of the flag should be an `h`

![Failing check](https://www.sigflag.at/assets/posts/m0rph/radare-3.png
"Figure 6: Failing check")

**Figure 6 -** Failing check

## Iterate  
No we can just restart the process with our new guess `ood
34C3_AAAAAAAAAAAhAAAAAA`, skip over the first break and repeat these steps:

- Step 4 times `4ds`  
- Print the `cmp` instruction that is next `pd 1 @ rip`  
- Print the character being compared `dr al`  
- Print the offset into the flag (`? rdi-0x7fffffffe09b~[:2]` using the "mini grep" `~` with python-like indexing for the result to just get the integer value)

```  
:> ood 34C3_AAAAAAAAAAAhAAAAAA  
[0x7ffff7dd7c30]> dc  
hit breakpoint at: 555555554b95  
[0x555555554b95]> dc  
hit breakpoint at: 555555554b95  
[0x555555554b95]> 4ds  
[0x7ffff7ff5176]> pd 1 @ rip  
;-- rip:  
0x7ffff7ff517a 00:0000      3c30           cmp al, 0x30    ; '0' ; 48  
[0x7ffff7ff5176]> dr al  
0x00000041  
[0x7ffff7ff5176]> ? rdi-0x7fffffffe09b~[:2]  
22  
[0x7ffff7ff5176]>  
```

We see that  the 23rd character should be a `0`, so we restart with `ood
34C3_AAAAAAAAAAAhAAAAA0` and so on, reconstructing the flag character by
character.

```  
$ ./morph  34C3_M1GHTY_M0RPh1nG_g0  
What are you waiting for, go submit that flag!  
```  

Original writeup (https://www.sigflag.at/blog/2017/writeup-34c3ctf-m0rph/).