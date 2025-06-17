The first task to any reversing problem with only the executable is to attempt
at decompiling the executable. We will use Ghidra for this.

We stumble across some interesting functions:  
```  
void FUN_00100f0b(void)

{  
 puts("Welcome to 3kCTF 2020");  
 printf("FLAG:");  
 return;  
}  
```  
```  
void FUN_00100ef1(void)

{  
 operator>><char,std--char_traits<char>,std--allocator<char>>  
           ((basic_istream *)cin,(basic_string *)&DAT_00302300);  
 return;  
}  
```  
```  
void FUN_00100e93(void)

{  
 basic_ostream *this;  
  
 this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"Well
Done!");  
 operator<<((basic_ostream<char,std--char_traits<char>>*)this,endl<char,std--
char_traits<char>>);  
 return;  
}  
```  
```  
void FUN_00100ec2(void)

{  
 basic_ostream *this;  
  
 this = operator<<<std--char_traits<char>>((basic_ostream *)cout,":(");  
 operator<<((basic_ostream<char,std--char_traits<char>>*)this,endl<char,std--
char_traits<char>>);  
 return;  
}  
```  
```c  
void FUN_00100e04(void)

{  
 int local_10;  
 int local_c;  
  
 local_10 = 0;  
 while (local_10 < 0x27) {  
   printf("%d,",(ulong)*(uint *)(&DAT_00302320 + (long)local_10 * 4));  
   local_10 = local_10 + 1;  
 }  
 putchar(10);  
 local_c = 0;  
 while (local_c < 0x27) {  
   printf("%d,",(ulong)*(uint *)(&DAT_00302020 + (long)local_c * 4));  
   local_c = local_c + 1;  
 }  
 return;  
}  
```  
```  
/* WARNING: Globals starting with '_' overlap smaller symbols at the same
address */

void FUN_00100f2f(void)

{  
 _DAT_003024c0 = FUN_00100f0b;  
 _DAT_003024c8 = FUN_00100ef1;  
 _DAT_003024e8 = FUN_00100e93;  
 _DAT_003024f0 = FUN_00100ec2;  
 _DAT_00302508 = FUN_00100e04;  
 return;  
}  
```  
```c  
void FUN_00100f7c(uint param_1)

{  
 bool bVar1;  
 char *pcVar2;  
 long lVar3;  
 undefined8 *puVar4;  
 long in_FS_OFFSET;  
 undefined8 local_3a8 [10];  
 ulong local_358;  
 undefined8 local_348;  
 undefined8 local_340;  
 undefined8 local_338;  
 long local_328;  
 char local_12;  
 char local_11;  
 long local_10;  
  
 local_10 = *(long *)(in_FS_OFFSET + 0x28);  
 bVar1 = false;  
 lVar3 = 0x72;  
 puVar4 = local_3a8;  
 while( true ) {  
   if (lVar3 == 0) break;  
   lVar3 = lVar3 + -1;  
   *puVar4 = 0;  
   puVar4 = puVar4 + 1;  
 }  
 ptrace(PTRACE_GETREGS,(ulong)param_1,0,local_3a8);  
 lVar3 = ptrace(PTRACE_PEEKDATA,(ulong)param_1,local_328);  
 local_12 = (char)lVar3;  
 local_11 = (char)((ulong)lVar3 >> 8);  
 if ((local_12 == '\x0f') && (local_11 == '\v')) {  
   lVar3 = (long)(int)local_358;  
   if (lVar3 == 2) {  
     local_348 = size();  
     bVar1 = true;  
   }  
   else {  
     if (lVar3 == 3) {  
       pcVar2 = (char *)operator[]((basic_string<char,std--char_traits<char>,std--allocator<char>>  
                                    *)&DAT_00302300,(long)(int)local_338);  
       *(uint *)(&DAT_00302320 + (long)(int)local_338 * 4) =  
            ((int)*pcVar2 ^ (uint)local_340) + (int)local_338;  
       bVar1 = true;  
     }  
     else {  
       if (lVar3 == 4) {  
         local_358 = (ulong)(*(int *)(&DAT_00302320 + (long)(int)local_338 * 4) !=  
                            *(int *)(&DAT_00302020 + (long)(int)local_338 * 4));  
         bVar1 = true;  
       }  
     }  
   }  
   if (!bVar1) {  
     (**(code **)(&DAT_003024c0 + lVar3 * 8))();  
   }  
   local_328 = local_328 + 2;  
   ptrace(PTRACE_SETREGS,(ulong)param_1,0,local_3a8);  
 }  
 if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
                   /* WARNING: Subroutine does not return */  
   __stack_chk_fail();  
 }  
 return;  
}  
```  
```c  
undefined8 FUN_001011d9(void)

{  
 bool bVar1;  
 undefined8 uVar2;  
 long in_FS_OFFSET;  
 uint local_24;  
 uint local_20;  
 __pid_t local_1c;  
 uint local_18;  
 uint local_14;  
 long local_10;  
  
 local_10 = *(long *)(in_FS_OFFSET + 0x28);  
 FUN_00100f2f();  
 local_20 = fork();  
 if (local_20 == 0) {  
   ptrace(PTRACE_TRACEME,0,0,0);  
   uVar2 = FUN_001013e6();  
 }  
 else {  
   bVar1 = false;  
   while (!bVar1) {  
     local_24 = 0;  
     local_1c = waitpid(local_20,(int *)&local_24,0);  
     if ((local_24 & 0x7f) == 0) {  
       bVar1 = true;  
     }  
     else {  
       if ((char)(((byte)local_24 & 0x7f) + 1) >> 1 < '\x01') {  
         if (((local_24 & 0xff) == 0x7f) && (local_18 = (int)local_24 >> 8 & 0xff, local_18 ==4))  
         {  
           FUN_00100f7c((ulong)local_20);  
         }  
       }  
       else {  
         local_14 = local_24 & 0x7f;  
         bVar1 = true;  
       }  
     }  
     ptrace(PTRACE_CONT,(ulong)local_20,0,0);  
   }  
   uVar2 = 0;  
 }  
 if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
                   /* WARNING: Subroutine does not return */  
   __stack_chk_fail();  
 }  
 return uVar2;  
}  
```  
------  
The first very important thing to notice is `FUN_00100f2f`. This is the *only*
place where the first five functions are used. The pointer to these functions
are put onto the stack, which means they are dynamically called. This is
confirmed in `FUN_00100f7c`, where we see  
```c  
     (**(code **)(&DAT_003024c0 + lVar3 * 8))();  
```

The second thing to notice is the `ptrace`. It turns out, this `ptrace` does
absolutely nothing that is important to us (except make it harder to reverse).

The next thing to notice is `FUN_00100e04`. This prints some random integers
on the stack, but on a normal run, it is never called (we can confirm this
with a debugger).  
Let's see what happens when we run this executable in a debugger. We will use
`radare2`.

```  
r2 -d ./micro  
> aaa  
[x] Analyze all flags starting with sym. and entry0 (aa)  
[x] Analyze function calls (aac)  
[x] Analyze len bytes of instructions for references (aar)  
[x] Check for objc references  
[x] Check for vtables  
[x] Type matching analysis for all functions (aaft)  
[x] Propagate noreturn information  
[x] Use -AA or aaaa to perform additional experimental analysis.  
> afl  
0x56208685fcc0    1 42           entry0  
0x562086a60fe0    1 140          reloc.__libc_start_main  
0x56208685fbc0    1 6            sym.imp.printf  
0x56208685fbd0    1 6            sym.imp.fork  
0x56208685f000    3 209  -> 202  map.tmp_micro.r_x  
0x56208685fbe0    1 6
sym.imp.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::size___const  
0x56208685fbf0    1 6            sym.imp.waitpid  
0x56208685fc00    1 6            sym.imp.ptrace  
0x56208685fc10    1 6            sym.imp.__cxa_atexit  
0x56208685fc20    1 6
sym.imp.std::basic_ostream_char__std::char_traits_char_____std::operator____std::char_traits_char____std::basic_ostream_char__std::char_traits_char______char_const  
0x56208685fc30    1 6
sym.imp.std::ostream::operator___std::ostream______std::ostream  
0x56208685fc40    1 6            sym.imp.__stack_chk_fail  
0x56208685fc50    1 6
sym.imp.std::basic_istream_char__std::char_traits_char_____std::operator___char__std::char_traits_char___std::allocator_char____std::basic_istream_char__std::char_traits_char______std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char  
0x56208685fc60    1 6
sym.imp.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::basic_string  
0x56208685fc70    1 6            sym.imp.putchar  
0x56208685fc80    1 6            sym.imp.std::ios_base::Init::Init  
0x56208685fc90    1 6            sym.imp.puts  
0x56208685fca0    1 6
sym.imp.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::operator___unsigned_long  
0x56208685fdca    1 11           main  
0x56208685fdc0    5 154  -> 67   entry.init0  
0x562086860363    1 21           entry.init1  
0x5620868602f1    4 114          fcn.5620868602f1  
0x56208685fd80    5 58   -> 51   entry.fini0  
0x56208685fcb0    1 6            fcn.56208685fcb0  
0x56208685fcf0    4 50   -> 40   fcn.56208685fcf0  
0x5620868601d9   16 280          fcn.5620868601d9  
> s fcn.558d6357c1d9  
> dcu.  
Continue until 0x5620868601d9 using 1 bpsize  
hit breakpoint at: 5620868601d9  
```  
Note that your addresses will be different if you run this again. We are now
in `FUN_001011d9`. Let's get into `FUN_00100f7c`:  
```  
> s 0x56208685ff7c  
> dcu.  
> s 0x56208685ff7c  
> dcu.  
> s 0x56208685ff7c  
> dcu.  
```  
Let's step a bit (stepping over `call`). We can do this by going in visual
mode (`Vp`) and pressing F7/F8 to step/step over respectively.

There is a few interesting lines:  
```  
       │   0x56208686016e      488b8558fcff.  mov rax, qword [rbp - 0x3a8]                                                                                                
       │   0x562086860175      488d14c50000.  lea rdx, [rax*8]                                                                                                            
       │   0x56208686017d      488d053c1320.  lea rax, [0x562086a614c0]                                                                                                   
       │   0x562086860184      488b0402       mov rax, qword [rdx + rax]                                                                                                  
       │   0x562086860188      ffd0           call rax                                                                                                                    
```  
This is the dynamic call in the decompiled C code. We can see the
`&DAT_003024c0` is `0x562086a614c0`, and `lVar3 * 8` is in `rbp-0x3a8`. Let's
see what the value of at `rbp-0x3a8` is...  
```  
[0x562086860125]> px @ rbp-0x3a8  
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF  
0x7ffe89ce5018  0000 0000 0000 0000 0000 0000 0000 0000  ................  
```  
It is a `0`.  This corresponds to calling the first function (printing the
welcome message). This makes sense, as if we continue running the program
until we hit the top of this function again, we get a message:  
```  
> s 0x56208686018a  
> dcu.  
Continue until 0x56208686018a using 1 bpsize  
Welcome to 3kCTF 2020  
FLAG:  
```  
The address of `0x56208686018a` corresponds to after the `call rax`.  
If we check the value at `rbp-0x3a8`, we should see a `01`. This corresponds
to the second function (prompting for input). Let's continue execution...  
```  
> s 0x56208686018a  
> dcu.  
```  
Now, we are prompted for input. Let's enter a random value for now, e.g `aa`.

Let's continue running, printing `rbp-0x3a8`.  
```  
02  
03  
03  
03  
01  
06  
```  
Looking at `FUN_00100f7c`, these are no longer corresponding to dynamically
calling functions, but now hitting:  
```c  
   if (lVar3 == 2) {  
     local_348 = size();  
     bVar1 = true;  
   }  
   else {  
     if (lVar3 == 3) {  
       pcVar2 = (char *)operator[]((basic_string<char,std--char_traits<char>,std--allocator<char>>  
                                    *)&DAT_00302300,(long)(int)local_338);  
       *(uint *)(&DAT_00302320 + (long)(int)local_338 * 4) =  
            ((int)*pcVar2 ^ (uint)local_340) + (int)local_338;  
       bVar1 = true;  
     }  
     else {  
       if (lVar3 == 4) {  
         local_358 = (ulong)(*(int *)(&DAT_00302320 + (long)(int)local_338 * 4) !=  
                            *(int *)(&DAT_00302020 + (long)(int)local_338 * 4));  
         bVar1 = true;  
       }  
     }  
```  
The first branch (`lVar3 == 2`) calls `size()`, which means it is finding the
size of the C++ string. The second branch (`lVar3 == 3`) does some weird
operation on `DAT_00302320`. It gets the `local_338`th element, XORs it with
`local_340`, and adds `local_338` (adding the index). In the last branch
(`lVar3 == 4`), it checks if the bytes at `DAT_00302320 + local_338 * 4` and
`DAT_00302020 + local_338 * 4`.

Some very interesting things to note is that `FUN_00100e04` prints the strings
at `DAT_00302320` and `DAT_00302020`, while `FUN_00100ef1` reads in user input
into `DAT_00302320`. Given this, we can see that the the program does some
operation on `DAT_00302320`, and then compares them to see if they are equal.
We can only assume that if they are equal, `FUN_00100e93` is called and `Well
done!` is printed, otherwise `:(` is printed from `FUN_00100ec2`.

It's very nice that there is a function to print `DAT_00302020`... let's try
jumping there and seeing what happens. We will need to first get to `main` so
that the `libc` contents are run (otherwise we will get a segmentation fault).
Next, we need to figure out the offset for the function (we can do this with
Ghidra). It is `0x00100e04 - 0x100000 = 0xe04`.  
```  
r2 -d ./micro  
> aaa  
> s main  
> dm  
0x000055a45de38000 - 0x000055a45de3a000 * usr     8K s r-x /tmp/micro
/tmp/micro ; map.tmp_micro.r_x  
0x000055a45e039000 - 0x000055a45e03b000 - usr     8K s rw- /tmp/micro
/tmp/micro ; map.tmp_micro.rw  
0x00007f932bade000 - 0x00007f932bae0000 - usr     8K s r-- /usr/lib/ld-2.31.so
/usr/lib/ld-2.31.so  
0x00007f932bae0000 - 0x00007f932bb00000 - usr   128K s r-x /usr/lib/ld-2.31.so
/usr/lib/ld-2.31.so ; map.usr_lib_ld_2.31.so.r_x  
0x00007f932bb00000 - 0x00007f932bb08000 - usr    32K s r-- /usr/lib/ld-2.31.so
/usr/lib/ld-2.31.so ; map.usr_lib_ld_2.31.so.r  
0x00007f932bb09000 - 0x00007f932bb0b000 - usr     8K s rw- /usr/lib/ld-2.31.so
/usr/lib/ld-2.31.so ; map.usr_lib_ld_2.31.so.rw  
0x00007f932bb0b000 - 0x00007f932bb0c000 - usr     4K s rw- unk0 unk0 ;
map.unk0.rw  
0x00007ffdb10ac000 - 0x00007ffdb10cd000 - usr   132K s rw- [stack] [stack] ;
map.stack_.rw  
0x00007ffdb1172000 - 0x00007ffdb1176000 - usr    16K s r-- [vvar] [vvar] ;
map.vvar_.r  
0x00007ffdb1176000 - 0x00007ffdb1178000 - usr     8K s r-x [vdso] [vdso] ;
map.vdso_.r_x  
0xffffffffff600000 - 0xffffffffff601000 - usr     4K s --x [vsyscall]
[vsyscall] ; map.vsyscall_.__x  
```  
We will need to calculate the location of the function we want to call using
its offset: `0xe04 + 0x000055a45de38000 = 0x55a45de38e04`. Let's jump there
and check we are in the correct location.  
```  
> s 0x55a45de38e04  
> pd  
           0x55a45de38e04      55             push rbp  
           0x55a45de38e05      4889e5         mov rbp, rsp  
           0x55a45de38e08      4883ec10       sub rsp, 0x10  
           0x55a45de38e0c      c745f8000000.  mov dword [rbp - 8], 0  
       ┌─> 0x55a45de38e13      837df826       cmp dword [rbp - 8], 0x26  
      ┌──< 0x55a45de38e17      7f30           jg 0x55a45de38e49  
      │╎   0x55a45de38e19      8b45f8         mov eax, dword [rbp - 8]  
      │╎   0x55a45de38e1c      4898           cdqe  
      │╎   0x55a45de38e1e      488d14850000.  lea rdx, [rax*4]  
      │╎   0x55a45de38e26      488d05f31420.  lea rax, [0x55a45e03a320]  
      │╎   0x55a45de38e2d      8b0402         mov eax, dword [rdx + rax]  
      │╎   0x55a45de38e30      89c6           mov esi, eax  
      │╎   0x55a45de38e32      488d3d540600.  lea rdi, [0x55a45de3948d] ; "%d,"  
      │╎   0x55a45de38e39      b800000000     mov eax, 0  
      │╎   0x55a45de38e3e      e87dfdffff     call sym.imp.printf     ; int printf(const char *format)  
      │╎   0x55a45de38e43      8345f801       add dword [rbp - 8], 1  
      │└─< 0x55a45de38e47      ebca           jmp 0x55a45de38e13  
      └──> 0x55a45de38e49      bf0a000000     mov edi, 0xa  
           0x55a45de38e4e      e81dfeffff     call sym.imp.putchar    ; int putchar(int c)  
           0x55a45de38e53      c745fc000000.  mov dword [rbp - 4], 0  
       ┌─> 0x55a45de38e5a      837dfc26       cmp dword [rbp - 4], 0x26  
      ┌──< 0x55a45de38e5e      7f30           jg 0x55a45de38e90  
      │╎   0x55a45de38e60      8b45fc         mov eax, dword [rbp - 4]  
      │╎   0x55a45de38e63      4898           cdqe  
      │╎   0x55a45de38e65      488d14850000.  lea rdx, [rax*4]  
      │╎   0x55a45de38e6d      488d05ac1120.  lea rax, [0x55a45e03a020]  
      │╎   0x55a45de38e74      8b0402         mov eax, dword [rdx + rax]  
      │╎   0x55a45de38e77      89c6           mov esi, eax  
      │╎   0x55a45de38e79      488d3d0d0600.  lea rdi, [0x55a45de3948d] ; "%d,"  
      │╎   0x55a45de38e80      b800000000     mov eax, 0  
      │╎   0x55a45de38e85      e836fdffff     call sym.imp.printf     ; int printf(const char *format)  
      │╎   0x55a45de38e8a      8345fc01       add dword [rbp - 4], 1  
      │└─< 0x55a45de38e8e      ebca           jmp 0x55a45de38e5a  
      └──> 0x55a45de38e90      90             nop  
           0x55a45de38e91      c9             leave  
           0x55a45de38e92      c3             ret  
```  
Looks correct. Let's move `rip` there:  
```  
> dr rip=0x55a45de38e04  
0x55a45de38dca ->0x55a45de38e04  
```  
Let's continue program execution to see what it prints. Note that we don't
care if it segmentation faults or not, as long as we get the output.  
```  
> dc  
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  
child stopped with signal 17  
[+] SIGNAL 17 errno=0 addr=0x3e800002ade code=4 ret=0  
[+] signal 17 aka SIGCHLD received 0  
> dc  
20,77,94,76,74,78,29,81,86,92,76,95,132,79,95,81,101,111,98,98,86,106,88,143,90,106,92,112,122,112,108,105,98,153,99,118,116,43,128,  
child stopped with signal 17  
[+] SIGNAL 17 errno=0 addr=0x3e800002ade code=1 ret=0  
[+] signal 17 aka SIGCHLD received 0  
```

Very nice! Note that this makes sense. We never inputted any values, so the
first array is empty. The second array is very interesting.

Let's jump back to `FUN_00100f7c`. In particular,  
```c  
     if (lVar3 == 3) {  
       pcVar2 = (char *)operator[]((basic_string<char,std--char_traits<char>,std--allocator<char>>  
                                    *)&DAT_00302300,(long)(int)local_338);  
       *(uint *)(&DAT_00302320 + (long)(int)local_338 * 4) =  
            ((int)*pcVar2 ^ (uint)local_340) + (int)local_338;  
       bVar1 = true;  
     }  
```

Since `DAT_00302020` and `DAT_00302320` are checked if they are equal, let's
try to reverse `DAT_00302020` to get the correct input for `DAT_00302320`.
Note that this should also be the flag, so we can use that to our advantage.
We know `local_338` (the index in the string), however we don't know
`local_340` except that it is constant. Since it is constant, there are really
only 256 options, we can check all of them.

We wrote the following Python program to check all values of `local_340` where
all characters were printable ASCII.  
```py  
import string

a =
[20,77,94,76,74,78,29,81,86,92,76,95,132,79,95,81,101,111,98,98,86,106,88,143,90,106,92,112,122,112,108,105,98,153,99,118,116,43,128]

for i in range(len(a)):  
   a[i] -= i

for x in range(256):  
   b = list(a)  
   for i in range(len(b)):  
       b[i] ^= x  
   if all(chr(x) in string.printable[:-5] for x in b):  
       print(''.join(map(chr, b)))  
```  
```  
$ python3 solver.py  
4l|ifi7jnsbtXbqbu~pobubXbqbu~snjbXasp&z  
6n~kdk5hlq`vZ`s`w|rm`w`Z`s`w|qlh`Zcqr$x  
0hxmbm3njwfp\fufqztkfqf\fufqzwjnf\ewt"~  
2jzo`o1lhudr^dwdsxvidsd^dwdsxuhld^guv |  
3k{nan0mites_everywhere_everytime_ftw!}  
<dtana?bf{j|Pjyj}vxgj}jPjyj}v{fbjPi{x.r  
=eu`o`>cgzk}Qkxk|wyfk|kQkxk|wzgckQhzy/s  
9aqdkd:gc~oyUo|oxs}boxoUo|oxs~cgoUl~}+w  
&~n{t{%x|apfJpcpglb}pgpJpcpgla|xpJsab4h  
xh}r}#~zgv`Lvevajd{vavLvevajgz~vLugd2n  
#{k~q~ }yducOufubigxubuOufubidy}uOvdg1m  
,tdq~q/rvkzl@zizmfhwzmz@zizmfkvrz@ykh>b  
.vfs|s-ptixnBxkxodjuxoxBxkxoditpxB{ij<`  
/wgr}r,quhyoCyjynektynyCyjynehuqyCzhk=a  
(p`uzu+vro~hD~m~ibls~i~D~m~iborv~D}ol:f  
+scvyv(uql}kG}n}jaop}j}G}n}jalqu}G~lo9e  
```

Wow, the flag is right there! `3k{nan0mites_everywhere_everytime_ftw!}` Let's
double check with `micro`  
```  
$ ./micro  
Welcome to 3kCTF 2020  
FLAG:3k{nan0mites_everywhere_everytime_ftw!}  
Well Done!  
```

It works.

**Flag:** `3k{nan0mites_everywhere_everytime_ftw!}`