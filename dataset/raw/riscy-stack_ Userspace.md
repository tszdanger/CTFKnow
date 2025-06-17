# riscy-stack: Userspace (pwn)  
Writeup by: [xlr8or](https://ctftime.org/team/235001)

As part of this challenge we get a lot of things, mainly files that provide
the means to run the operating system and the provided userspace program we
are attacking.

The readme provides useful details:  
* Table of syscalls (to win we need to issue syscall 0x1337)  
* the binary is loaded at `0x08000000`, the entire page is RWX!!  
* nothing other than the userspace binary is strictly needed for the challenge (we don't need to look into how the kernel and firmware work)

Next let's see what the binary does on the remote.  
We have 5 options to choose from  
* create  
   - this will create a note taking a number  
   - we have a max limit on notes, can't put more than 16  
* show  
   - this will display an existing note  
   - and we can't get a higher index than the current count of notes - 1  
* edit  
   - this will edit an existing note, allowing us to put a new number  
   - again we can't get a location higher than the last note we have added  
* delete  
   - this will delete the last added note always  
   - won't allow us to delete when there are no notes  
* exit  
   - this just quits the application

That's all I got from trying the binary on the remote, next up I loaded it
into ghidra.  
Here I chose a risc-v 64-bit architecture, although it could be the case that
it was a 32-bit architecture all along, I'm not too familiar with the
architecture to be able to tell.  
I also manually specified the binary base address, as specified in the readme
file.

Looking at the entry, the decompile view is not that helpful again, but we can
deduce what happens from the assembly.

```asm  
c.li       a7,0x3  
lui        a0,0x7ffe0  
c.lui      a1,0x10  
c.li       a2,0x3  
; map(0x7ffe00000, 0x10, 0x3) rw-  
ecall  
lui        sp,0x7fff0  
j          main  
```

As you can see I have already added a comment, because this makes a syscall to
the `map` function to allocate some memory. This will be used for the stack,
since we see right before `main` is called an address is moved into the stack
pointer that resides in the area we have just allocated.

In main we see that several message pointers are placed on the stack:  
```c  
 pcStack_d0 = s_invalid_choice_080003b7;  
 pcStack_e0 = s_no_space_08000412;  
 pcStack_e8 = s_created_08000384;  
 pcStack_f0 = s__0800041c;  
 pcStack_f8 = s_edited_0800041e;  
 local_100 = s_empty_08000390;  
 pcStack_d8 = s_deleted_0800039f;  
```

Each of these is a pointer to a string that holds messages that the remote
sends us in response to our actions.

Next up we see the loop that potentially looks for the first user input,
selecting a choice from the menu:  
```c  
 while( true ) {  
                   /* print prompt */  
   ecall();  
   lVar5 = read_number_from_user(s_>_0800038d,2,2);  
   if (lVar5 - 1U < 5) break;  
                   /* invalid choice */  
   ecall();  
 }  
```

Here I have added some comments, because those syscalls are used to print
messages to stdout.  
I have also named the function the read number from user function. It takes no
parameters, however the decompiler is a bit confused around syscalls, that's
why you see some arguments going into it.

I won't analyse the read function in details, but here are some of the
important observations:  
1. We can read signed numbers (either an optional `+` sign or a `-` sign is allowed to be specified)  
2. Input is read until a `\r` or `\n` is encountered  
3. Space and some low value bytes are ignored at the start of the input  
4. Input is processed until valid digits are encountered, any non-digit characters stops the parsing

The `create` handler is not too interesting, it performs good input
sanitization.  
The `show` handler on the other hand is more interesting to us:

```c  
   ecall();  
   lVar5 = read_number_from_user(s_index:_0800042b,7,2);  
   if (lVar5 < lVar14) {  
     ecall();  
     uVar2 = *(uint *)(local_c8 + lVar5 * 4);  
     // ... Convert uVar2 to string a print it; omitted for clarity  
```

Although `lVar5` is checked against an upper bound, a lower bound is never
enforced. This means that we are able to provide a negative offset and read
out of bounds, as long as we don't need to read in the other direction, which
the upper bound of the amount of notes would prevent.

The same issue exists in the `edit` function, let's take a look:

```c  
   ecall();  
   lVar5 = read_number_from_user(s_index:_0800042b,7,2);  
   if (lVar5 < lVar14) {  
     ecall();  
     uVar4 = read_number_from_user(s_value:_08000397,7,2);  
     *(undefined4 *)(local_c8 + lVar5 * 4) = uVar4;  
     ecall();  
   }  
```

Again, `lVar5` is only checked against an upper bound therefore we can
**overwrite** any 4 byte value as long as it lies before the `local_c8` array.

And to our luck, the stack is allocated **after** the address at which the
binary is loaded, therefore all we need to do is to calculate the offset we
need to get to the start of the binary, and from there we can overwrite
arbitrary 4 bytes. Let's remember this is possible because the page the binary
is loaded into is writeable.

Since `sp` is set to `0x7fff0000` before main is called, and then in the first
instruction of main it is decremented by `0x100`, and we know that the
`local_c8` array will be at offset `+0x38`, the address we are starting from
is going to be: `0x7ffeff38`.

The difference between this value, and the base of the binary is `0x77feff38`.
Then we divide this value by 4, since that's how the indexing is done by the
userspace program into the notes array.

Therefore we need to pass `-503300046` as an offset to get to the base of the
binary.

From here the plan of attack is as follows:  
1. Inject shellcode using the out of bounds write we found in place of the exit option  
2. Call the exit option

The `exit` option starts at offset `0x28c` from the binary base, so that's
where we will start writing our shellcode. The shellcode just needs to issue
syscall `0x1337` and then we will get the flag.

The shellcode will be:  
```asm  
li a7, 0x1337 ; load syscall number to a7  
ecall ; issue the syscall  
```

I have used the [this online risc-v
assembler](https://riscvasm.lucasteske.dev/#) to get the bytecode of that we
need to put.

And that's it now we just need to perform the overwrite and call `exit`. I
didn't make an automated solver for this challenge, because my script had some
problems with reading messages from the remote, but here is a python script
generating the values:  
```python  
num = -503300046  
off_load_syscall_num = num + (0x28c//4)

print(off_load_syscall_num)  
print(0x000018b7)  
print(off_load_syscall_num + 1)  
print(0x3378889b)  
print(off_load_syscall_num + 2)  
print(0x73)  
```

It prints pairs of offset, instruction. Each of these should be provided to
the `edit` option, first the offset, after that the instruction bytes for the
value.