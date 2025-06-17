# Reverse / x0rr3al?!!

## Clue

Are you being x0rr3al with me right now?!

## My solution

Expected a lot of xor string obfuscation based on the title of the challenge.  
I opened up the Binary Ninja, and this is what greeted me when I opened up one  
of the functions that looked interesting...

```  
0000156a  int64_t sub_156a()

0000156a  {  
00001576      void* fsbase;  
00001576      int64_t rax = *(int64_t*)((char*)fsbase + 0x28);  
00001599      int64_t var_38 = 0x71267032217f2271;  
0000159d      int64_t var_30 = 0x6b327c217a653279;  
000015b5      int64_t var_28 = 0x357c216073326722;  
000015b9      int64_t var_20 = 0x2666322323733266;  
000015bd      int16_t var_18 = 0x797e;  
000015c3      char var_16 = 0x33;  
000015f1      for (int32_t var_3c = 0; var_3c <= 0x22; var_3c = (var_3c + 1))  
000015e7      {  
000015e2          putchar(((int32_t)(*(int8_t*)(&var_38 + ((int64_t)var_3c)) ^
0x12)));  
000015da      }  
000015f8      putchar(0xa);  
00001602      int64_t rax_8 = (rax ^ *(int64_t*)((char*)fsbase + 0x28));  
0000160b      if (rax_8 == 0)  
00001602      {  
00001613          return rax_8;  
00001613      }  
0000160d      __stack_chk_fail();  
0000160d      /* no return */  
0000160d  }  
```

It looks like it is obviously putting some data into a giant memory buffer,  
and then xor-ing it all, and then printing it out 1 character at a time.  
I tried to just cut-and-paste the pseudo-c from Binary Ninja into a little  
standalone C application, and when I ran it I got the following output:

```  
ck0t{   {R  
```

I decided to try to take a swag at manually cleaning it up and tweaking the
code  
a little, and tried again to execute the function.

Code that was a little cleaned up:

```  
nt main(int argc, char** argv)  
{  
       char buf[0x50];  
       memset(buf, 0, 0x50);

       uint64_t* ptr = (uint64_t*) buf;

       *ptr = 0x71267032217f2271;  
       ptr++;  
       *ptr = 0x6b327c217a653279;  
       ptr++;  
       *ptr = 0x357c216073326722;  
       ptr++;  
       *ptr = 0x2666322323733266;  
       ptr++;

       uint16_t* ptr2 = (uint16_t*) ptr;  
       *ptr2 = 0x797e;  
       ptr2++;

       uint8_t* ptr3 = (uint8_t*) ptr2;  
       *ptr3 = 0x33;  
      for(int i = 0; i < strlen(buf); i++)  
       {  
               buf[i] ^= 0x12;  
       }

       printf("Buf %s\n", buf);

       return 0;  
}  
```

When I ran this version:

```  
$ gcc sub156a.c -o sub156a  
$ ./sub156a  
Buf c0m3 b4ck wh3n y0u ar3n't a11 t4lk!  
```

Cool now we are getting somewhere.  I also tried to deobfuscate what sub1614
was  
printing, and got the following out of it:

```  
$ ./sub1614  
Buf w00t w00t! y0u g0t th3 fl4g!  
```

Cool, so if I get sub1614 to execute, I'm should have the flag.

The area of code that was checking my password looked like the following:

```  
00001a82      printf("p4ss m3 th3 fl4g: ", 0x200);  
00001a9a      void var_48;  
00001a9a      __isoc99_scanf("%53s", &var_48);  
00001aaf      if (strlen(&var_48) != 0x35)  
00001aab      {  
00001ab6          sub_156a();  
00001ab6      }  
00001ac5      else  
00001ac5      {  
00001ac5          int32_t var_58_1 = 0;  
00001b57          while (true)  
00001b57          {  
00001b57              if (var_58_1 > 0x34)  
00001b53              {  
00001b62                  sub_1614();  
00001b67                  break;  
00001b67              }  
00001b12              if (sub_14f7(((int32_t)sub_150a(*(int8_t*)(&var_48 +
((int64_t)var_58_1)), 0))) != *(int32_t*)((((int64_t)var_58_1) << 2) +
&data_40a0))  
00001b0d              {  
00001b19                  sub_156a();  
00001b23                  break;  
00001b23              }  
00001b39              if (rax_7 != sub_1483(main, 0x200))  
00001b29              {  
00001b40                  sub_16ad();  
00001b4a                  exit(1);  
00001b4a                  /* no return */  
00001b4a              }  
00001b4f              var_58_1 = (var_58_1 + 1);  
00001b4f          }  
00001b4f      }  
```

I briefly looked at reversing some of the flag obfuscation stuff, and just  
decided no, I want this to be a password oracle.  If I can see / print
var_58_1,  
which is a loop index, I can see how many correct password characters I have.  
I can then brute force the flag 1 character at a time, until I have the entire  
flag revealed.

So how did I accomplish this non-sense?

## Disable debugging and trace prevention code

The main function called ptrace to detect if I was debugging the binary, Binja  
makes it trivial to invert a branch, so I created a new copy of the binary  
with that patched that REQUIRED me to be debugging it to continue.

The main function also called sub_17a4, which was obviously checking something  
about the execution environment. It was calling strstr to check on something,
so  
I decided to LD_PRELOAD my own copy of strstr to determine what it was
checking  
and then make that check work into may favor / bypass the anti-debugging.

```  
char* strstr(const char* haystack, const char* needle)  
{  
	printf("haystack=%s and needle=%s\n", haystack, needle);  
	return 0;  
}  
```

To build the library we are going to inject:

```  
gcc -shared -o injector.so -fPIC injector.c  
```

I eventually combined the building of the injector and executing the binary  
into a [script](inject.sh)

Executing that:  
```  
$ export LD_PRELOAD=./injector.so  
$ ./x0rr3al  
haystack=-bash and needle=gdb  
haystack=-bash and needle=ollydbg  
haystack=-bash and needle=strace  
haystack=-bash and needle=ltrace  
p4ss m3 th3 fl4g: ^C  
```

So at this point I was free to debug it and poke around in it.  I decided that
I  
replaced the call sub_156a which normally signals a failure, with a call to my  
own function, I could easily inspect the stack and see how many password  
characters I had correctly.

I looked at how another part of the code called close() function.  I'm not
very  
proficient in x86 assembly, so I had to take apart the opcode a little myself,  
because I tried to get Binary Ninja to let me patch in a direct call to
close,,  
but I couldn't get it to work.

But I soon discovered that the call instruction on x86 is simply 0xe8 followed  
by a 4 byte signed offset from PC.  PC already pointing to the instruction
after  
the call, and the offset to close function in the plt.  So I was able to
manually  
in the hex editor patch the call to sub_156a to call close instead.

And then I provided my own custom close function.  Close gets called once
already  
before this code, so it just keeps track using a static counter how many times  
it has been called, and on the second call can do some stack inspection.

This was code to inspect the stack:

```  
void dumpFrozenStack(int* stackAddr)  
{  
       printf("Stack Pointer near %p\n", stackAddr);                                                                                                           
  
       for(int i = 0; i < 0x30; i+= 4)                                                                                                                         
       {                                                                                                                                                       
               printf("0x%04x %08x %08x %08x %08x\n", i, stackAddr[i], stackAddr[i+1], stackAddr[i+2], stackAddr[i+3]);                                        
       }                                                                                                                                                       
}  

int close(int fd)  
{  
       static int closeCallTracker = 0;                                                                                                                        
       closeCallTracker++;                                                                                                                                     
       printf("close called %d times on fd = %d\n", closeCallTracker, fd);                                                                                     
  
       int dumbVar = 0;                                                                                                                                        
       if (closeCallTracker == 2)                                                                                                                              
       {                                                                                                                                                       
               dumpFrozenStack(&dumbVar);                                                                                                                      
       }                                                                                                                                                       
  
       return 0;                                                                                                                                               
}  
```

Close creates a single stack variable, and passes the stack variable to a new  
function. That new function can create as many local variables as it wants,
and  
it won't shift the location of dumbVar on the stack, which should be on top of  
the stack frame for the main function.

I know the flag format is vsctf, so I can try to verify the offset of the
stack  
variable that is tracking how many correct characters of the password have
been  
found so far.  I'm easily able to pick out that stack variable, and then
replace  
the dump function with a shorter version that just prints out how many correct  
password characters we have:

```  
void dumpFrozenStack(int* stackAddr)  
{  
	printf("Num flag bytes correct = %d\n", stackAddr[11]);                                                                                                 
}  
```

I then created a python script to repeatedly call the program with my custom  
functions and guess a password.  It just keeps guessing 1 character at a time  
until the whole flag is revealed.

That script is [oracle_solve.py](oracle_solve.py)

The final [injector.c source](injector.c).

The python script will eventually crash after guessing 5 or 6 letters running  
out of file descriptors, so I would just keep adding charcters to the initial  
flag and letting it brute force the missing characters.

Final Flag:

```  
vsctf{w34k_4nt1_d3bugg3rs_4r3_n0_m4tch_f0r_th3_31337}  
```  

Original writeup
(https://github.com/mwales/security/blob/master/ctf/viewsource/23/reverse/xorr3al/writeup.md).