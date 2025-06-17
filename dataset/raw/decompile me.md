# decompile me (rev)  
Writeup by: [xlr8or](https://ctftime.org/team/235001)

As part of this challenge we get a single x86 ELF binary `chall`.  
As there is nothing better to do, let's load this into ghidra, and see what
happens:  
```c  
// ...  
 local_208[0] = 0x80;  
 write(1,"FLAG: ",0xe);  
 read(0,local_208,0x80);  
 RC4_setkey(&key,sbox);  
 RC4_encrypt(local_208,local_188,sbox);  
 iVar1 = memcmp(local_188,&enc,0x80);  
// ...  
```

Okay quite simple, right? The flag is requested from, then used as plaintext
for RC4 encryption, with a hardcoded key in `key`.  
Then the encrypted result gets compared to some hardcoded blob, `enc`.

The solution is straight forward, we use the key and the encrypted blob in the
binary to recover the flag.  
However upon performing the RC4 decrypt, something isn't right... Where is the
flag?  
Well, the challenge does hint at the problem, by saying reversing is too easy
because of the decompiler, so let's inspect the binary closer.

Looking at the `RC4_setkey` function, which initializes the s-box based on the
key, we see that although we pass some parameters to it in `main`, actually
none of them seem to be used in the decompile view.  
Instead, something suspicious is `unaff_R13`, which usually indicates that
`r13` is used from the previous function's frame, but is not explicitly marked
as a parameter to the function:  
```c  
 do {  
   *(char *)(unaff_R13 + uVar3) = (char)uVar3;  
   uVar2 = (int)uVar3 + 1;  
   uVar3 = (ulong)uVar2;  
 } while (uVar2 < 0x100);  
```

We see that `r13` and `r12` are being used in this function.  
From studying RC4, we know that `r13` is used as the sbox, and that `r12` is
used as the key.  
We can make the decompiler play along, by using a custom calling convention
for this function (check `Edit function signature > Use Custom Storage`).  
We add the first parameter to be `r13` and the second to be `r12`.

After making these changes we can see an important change in `main`:  
```c  
RC4_setkey(local_108,&val;;  
```

So in actuality the key, used for the encryption is in `val` and **not**
`key`.  
We can do the same, with the `RC4_encrypt` function, however nothing
additional is revealed, the sbox, from the key setup is used, on the user
input and the result is stored on the stack.  
We can try to do the RC4 decryption again, with the new knowledge about the
key, but still it won't succeed.

Let's look into `memcmp`, since although on first sight it looks like it could
be the libc function, but in reality it isn't:  
```c  
 bVar1 = 0;  
 uVar3 = 0;  
 do {  
   bVar1 = bVar1 | *(byte *)(unaff_R14 + uVar3) ^ *(byte *)((long)&dat + uVar3);  
   uVar2 = (int)uVar3 + 1;  
   uVar3 = (ulong)uVar2;  
 } while (uVar2 < (uint)__n);  
```

Note: you see `unaff_R14`, so we could also fix the calling convention here,
but I didn't do so, since from the assembly we know that `r14` holds the
output of the encryption.

More importantly, we see that `dat` is checked against our encrypted result,
regardless of what is passed as a parameter to the function.  
With this new knowledge, finally we need to RC4 decrypt `dat` using `val` as a
key.

`solve.py` performs the required decryption to recover the flag.  

Original writeup
(https://github.com/sbencoding/zer0pts_ctf_2023_writeups/tree/main/rev/decompile_me).