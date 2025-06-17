# Encryption Service - Pwn (1200 points)

Writeup by poortho

## Problem Description

[Libc](./libc-2.23.so)

`nc stack.overflow.fail 9004`

_by jitterbug_gang_

[pwnable](./encryption_service)

## Initial Analysis

First things first - let's run `file` on the binary to make sure the
organizers aren't tricking us:

```  
$ file encryption_service  
encryption_service: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux
2.6.32, BuildID[sha1]=c5bf6830cd72da005669a9aa8a37bda2075b3136, not stripped  
```

Alright, it looks normal enough. Now, let's open it up with our fancy new tool
- GHIDRA, and start reversing.

When we first run the binary, it asks us for a user id - this is a bit useful
a bit later in the challenge.

Afterwards, it appears we have 5 options:  
```  
1. Encrypt a message  
2. Remove a message  
3. View all messages  
4. Edit a message  
5. Exit  
```

Let's take a look at each of those:

First, we can create a new message:  
```c

void encrypt_string(void)

{  
 long in_FS_OFFSET;  
 int local_30;  
 uint local_2c;  
 char **local_28;  
 char *local_20;  
 char *local_18;  
 long local_10;  
  
 local_10 = *(long *)(in_FS_OFFSET + 0x28);  
 print_encryption_menu();  
 __isoc99_scanf("%d%*c",&local_30);  
 local_28 = (char **)create_info();  
 if (local_28 != (char **)0x0) {  
   if (local_30 == 1) {  
     *(code **)(local_28 + 2) = key_encrypt;  
     *(code **)(local_28 + 3) = print_key;  
   }  
   else {  
     if (local_30 != 2) {  
       puts("Not a valid choice");  
       goto LAB_00400e12;  
     }  
     *(code **)(local_28 + 2) = xor_encrypt;  
     *(code **)(local_28 + 3) = print_xor;  
   }  
   printf("How long is your message?\n>");  
   __isoc99_scanf("%d%*c");  
   local_2c = local_2c + 1;  
   *(uint *)((long)local_28 + 0x24) = local_2c;  
   local_20 = (char *)malloc((ulong)local_2c);  
   printf("Please enter your message: ");  
   fgets(local_20,local_2c,stdin);  
   *local_28 = local_20;  
   local_18 = (char *)malloc((ulong)local_2c);  
   local_28[1] = local_18;  
   (*(code *)local_28[2])(local_20,local_18,local_20,local_18);  
   printf("Your encrypted message is: %s\n",local_18);  
 }  
LAB_00400e12:  
 if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
                   /* WARNING: Subroutine does not return */  
   __stack_chk_fail();  
 }  
 return;  
}  
```

So, it looks like it's allocating some sort of struct, then reading our input
and allocating memory for our input.  
Interestingly enough, it also has function pointers based on whether we chose
"OTP" or "XOR" as our type of encryption. It stores each of these structs into
a global array.

Looking at the functions, none of them are really interesting, except for the
fact that the OTP key is constant and that our XOR key is our user id - we can
set our user id to 0 to avoid any messy xor operations.

More importantly, however, the fact that function pointers are in the struct
means that there are easy overwrite targets if we can control chunk allocation
in the future.

One thing to note, however, is that the `create_info()` function _only_
allocates new memory if the index found is 0. Though it doesn't seem too
important, it will come up later and make our lives miserable.

Now, the remove function:  
```c

void remove_encrypted_string(void)

{  
 long in_FS_OFFSET;  
 int local_14;  
 long local_10;  
  
 local_10 = *(long *)(in_FS_OFFSET + 0x28);  
 printf("Enter the index of the message that you want to remove: ");  
 __isoc99_scanf("%d%*c",&local_14);  
 if ((((local_14 < 0) || (0x13 < local_14)) || (*(long *)(information +
(long)local_14 * 8) ==0))  
    || (*(int *)(*(long *)(information + (long)local_14 * 8) + 0x20) == 1)) {  
   puts("Not a valid index.");  
 }  
 else {  
   *(undefined4 *)(*(long *)(information + (long)local_14 * 8) + 0x20) = 1;  
   free(**(void ***)(information + (long)local_14 * 8));  
   free(*(void **)(*(long *)(information + (long)local_14 * 8) + 8));  
 }  
 if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
                   /* WARNING: Subroutine does not return */  
   __stack_chk_fail();  
 }  
 return;  
}  
```

It simply asks for an index and frees the string and the struct itself. It
also sets some variable to 1 - this is used in the program to check if an
element in the array has been "freed". Importantly, however, we see that this
function never sets the actual pointer in the array to zero, thus creating a
use-after-free vulnerability.

View:  
```c

void view_messages(void)

{  
 uint local_c;  
  
 local_c = 0;  
 while ((int)local_c < 0x14) {  
   if ((*(long *)(information + (long)(int)local_c * 8) != 0) &&  
      (*(int *)(*(long *)(information + (long)(int)local_c * 8) + 0x20) == 0)) {  
     printf("Message #%d\n",(ulong)local_c);  
     (**(code **)(*(long *)(information + (long)(int)local_c * 8) + 0x18))();  
     printf("Plaintext: %s\n",**(undefined8 **)(information + (long)(int)local_c * 8));  
     printf("Ciphertext: %s\n");  
   }  
   local_c = local_c + 1;  
 }  
 return;  
}  
```

This code is pretty simple as well - it simply prints out all the data of the
struct. Interestingly, this code checks the "freed" flag in the struct - so we
can't obtain leaks this way.

And finally, our godsend, edit:  
```c

void edit_encrypted_message(void)

{  
 long lVar1;  
 char *__s;  
 undefined8 uVar2;  
 long in_FS_OFFSET;  
 int local_24;  
  
 lVar1 = *(long *)(in_FS_OFFSET + 0x28);  
 puts("Enter the index of the message that you wish to edit");  
 __isoc99_scanf("%d%*c");  
 if (((local_24 < 0) || (0x13 < local_24)) || (*(long *)(information +
(long)local_24 * 8) ==0)) {  
   puts("Invalid index");  
 }  
 else {  
   __s = **(char ***)(information + (long)local_24 * 8);  
   uVar2 = *(undefined8 *)(*(long *)(information + (long)local_24 * 8) + 8);  
   puts("Enter the new message");  
   fgets(__s,*(int *)(*(long *)(information + (long)local_24 * 8) +
0x24),stdin);  
   (**(code **)(*(long *)(information + (long)local_24 * 8) +
0x10))(__s,uVar2,__s,uVar2);  
 }  
 if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {  
                   /* WARNING: Subroutine does not return */  
   __stack_chk_fail();  
 }  
 return;  
}  
```  
This simply lets us edit a given message. However, unlike view, this does NOT
check if a chunk has been freed or not, thus letting us pop a shell
eventually.

To solve this, we'll use a fastbin attack to overlap a string chunk with a
message chunk, which will allow us to control the pointers in the message and
thus allow us to perform leaks and hijack the control flow of the program.

Essentially, when we free a chunk, it first frees our plaintext, and then the
ciphertext.

Initially, my idea was to overwrite `fd` of the freed chunk to the `bss`
segment using the `stdin` pointer to pass the size check of `malloc()`. This
would let us corrupt the `information` array with our arbitrary pointers.
However, this failed from a combination of three reasons:

1. The free list is `old encrypted -> faked chunk`, meaning our new encrypted string will be the faked chunk.  
2. Although it's easy to calculate what our string will be after the encryption, both encrypt functions use the `strlen` of the newly allocated chunk instead of the new plaintext like it should. Thus, `strlen` will almost always return 0, with a few exceptions such as when we corrupt `fd` of the free list.  
3. When creating new messages, the program will only allocate new memory if the address at the index is null. Thus, we cannot use the message struct to get our plaintext to be the our arbitrary chunk without losing the use-after-free vulnerability, making our attack useless.

Because our use-after-free has no leaks, we instead turn to our best friend:
partial overwrites!

However, `fgets` automatically null terminates our input, and their code does
_not_ remove the newline `fgets` reads, which means our last two bytes will
always be `0a00`, which is too much, as our new plaintext is directly written
to the `fd` of the free list!

At this point, I got somewhat stuck - how do we get it so that we only write a
single null byte and not the newline?

The answer: through the use of smallbins instead of fastbins.

If we allocate chunks of size `0x90` or greater, we'll have smallbins instead
of fastbins. This means that when we free them, a large unsorted bin will be
created, and any new allocations with empty free lists will use the unsorted
bin to allocate memory. On top of that, because smallbins coalesce, the
unsorted bin will be larger than the length stored in the message chunk that
has a pointer to the struct, so we can successfully perform a null byte
overwrite.

Thus, we set up our heap like so:  
```  
0x6031c0:       0x0000000000000000      0x0000000000000031 <- chunk with use-
after-free pointer  
0x6031d0:       0x0000000000603200      0x00000000006032c0  
0x6031e0:       0x000000000040093c      0x0000000000400887  
0x6031f0:       0x000000b100000001      0x0000000000000041 <- newly allocated
chunks  
0x603200:       0x0000000a66666666      0x00007ffff7dd1ce8  
0x603210:       0x0000000000000000      0x0000000000000000  
0x603220:       0x0000000000000000      0x0000000000000000  
0x603230:       0x0000000000000000      0x0000000000000041  
0x603240:       0x0000000a66666666      0x00007ffff7dd1b78  
0x603250:       0x0000000000000000      0x0000000000000000  
0x603260:       0x0000000000000000      0x0000000000000000  
0x603270:       0x0000000000000000      0x0000000000000031  
0x603280:       0x0000000000000000      0x00007ffff7dd1b78  
0x603290:       0x0000000000000000      0x0000000000000000  
0x6032a0:       0x0000000000000000      0x0000000000000031  
0x6032b0:       0x0000000000603270      0x00007ffff7dd1b78 <- null byte
overwrite here  
0x6032c0:       0x0000000000000000      0x0000000000000000  
0x6032d0:       0x0000000000000000      0x00000000000000a1  
0x6032e0:       0x00007ffff7dd1b78      0x00007ffff7dd1b78  
0x6032f0:       0x0000000000000000      0x0000000000000000  
```  
Now, we can perform a null byte overwrite on `fd` on the chunk at `0x6032b0`,
corrupting the free list and giving us overlapping chunks.

Thus, we perform our null byte overwrite, and obtain our overlapping chunks:  
```  
0x6031c0:       0x0000000000000000      0x0000000000000031  
0x6031d0:       0x0000000000603060      0x0000000000603040  
0x6031e0:       0x000000000040093c      0x0000000000400887  
0x6031f0:       0x0000001100000000      0x0000000000000041 <- new string that
we control  
0x603200:       0x0000000000000000      0x0000000000000031 <- message chunk
that we can control  
0x603210:       0x0000000000603320      0x0000000000603340  
0x603220:       0x000000000040093c      0x0000000000400887  
0x603230:       0x0000001100000000      0x0000000000000041  
0x603240:       0x0000000000000000      0x0000000000000000  
0x603250:       0x0000000000000000      0x0000000000000000  
0x603260:       0x0000000000000000      0x0000000000000000  
0x603270:       0x0000000000000000      0x0000000000000031  
0x603280:       0x0000000000000000      0x0000000000000000  
0x603290:       0x0000000000000000      0x0000000000000000  
0x6032a0:       0x0000000000000000      0x0000000000000031  
0x6032b0:       0x00000000006032e0      0x0000000000603300  
0x6032c0:       0x000000000040093c      0x0000000000400887  
0x6032d0:       0x0000001100000000      0x0000000000000021  
0x6032e0:       0x0000000a6c6c6c6c      0x00007ffff7dd1b78  
0x6032f0:       0x0000000000000000      0x0000000000000021  
```

Now, after doing this, exploitation is relatively trivial.

First, we use the edit function to set the string pointers of our message
chunk to a GOT address and obtain a libc address. Using the given libc, we can
calculate the libc base address and thus magic gadgets.

Then, we perform edit again on the same string and set print_func to a magic
gadget to obtain a shell.

Here's what the memory region looks like after we set up everything:  
```  
0x6031f0:       0x0000001100000000      0x0000000000000041 <- string chunk  
0x603200:       0x0000000000000000      0x0000000000000031 <- message chunk  
0x603210:       0x0000000000602028      0x0000000000602028 <- pointer to the
GOT to obtain libc leak  
0x603220:       0x00007ffff7a52216      0x00007ffff7a52216 <- magic gadget
address  
0x603230:       0x0000001100000000      0x0000000000000041  
```

Now, to pop a shell, we simply view the chunks and it will call the magic
gadget for us!

The final exploit can be found [here](./solve.py)

Original writeup (https://github.com/poortho/ctf-
writeups/tree/master/2019/utctf/encryption_service).