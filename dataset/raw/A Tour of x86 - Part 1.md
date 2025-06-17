* **Category:** reversing  
* **Points:** 50  
* **Description:**

> ## Part 1:  
>  
> Newbs only!  
>  
> ```sh  
> nc rev.chal.csaw.io 9003  
> ```  
>  
> -Elyk  
>  
>
> [stage-1.asm](https://ctf.csaw.io/files/02721fabb0c817ff88eecba00c8af128/stage-1.asm)  
>
> [Makefile](https://ctf.csaw.io/files/dc249873b66ed653d7db4572ce6ef07a/Makefile)  
>
> [stage-2.bin](https://ctf.csaw.io/files/5e0f7fb0d9229a7f878bc388e9fe1b4f/stage-2.bin)

## Writeup

This is a challenge in multiple stages, each one having its own flag.  
(Note: the original link contains all three stages)

The general theme is low-level x86 code and how it behaves after boot.  
The difficulty is quite low, but it was fun.

### Stage 1

In the first stage we have the assembly source code available, but it is
heavily  
commented. (This actually makes the code LESS readable at times)  
The code is running in 16-bit real-mode, with BIOS interrupts available.

When connecting to the provided address and port, we are asked a series of  
questions about the values of registers in different parts of the program.

#### What is the value of `dh` after line 129 executes? (one byte)

Line 129 is `xor dh, dh`, which always leaves `dh` as 0x00.

#### What is the value of `gs` after line 145 executes? (one byte)

Line 145 is `mov gs, dx`. `dx` is compared to 0 on line 134, so `gx` must
always  
be 0x00.

#### What is the value of `si` after line 151 executes? (two bytes)

Line 151 is `mov si, sp`. `sp` is set on line 149 with `mov sp, cx`. `cx` is
set  
to 0 on line 107, so `si` must always be 0x0000

#### What is the value of ax after line 169 executes? (two bytes)

Line 168 and 169 are `mov al, 't'` and `mov ah, 0x0e`. The hex-value of 't' is  
0x74, so the value is 0x0e74.

#### What is the value of ax after line 199 executes for the first time? (two
bytes)

Lines 197 and 199 are `mov al, [si]` and `mov ah, 0x0e`, which are part of a  
loop.

`si` is initialized as a pointer to the string `"acOS\n\r  by Elyk"`, so  
the first iteration should leave `ax` with 0x0e61 (hex-value of 'a' is 0x61).

After answering all the questions, we get the flag:

```  
flag{rev_up_y0ur_3ng1nes_reeeeeeeeeeeeecruit5!}  
```

Original writeup (https://losfuzzys.github.io/writeup/2018/09/20/csawctfquals-
tour-of-x86/).