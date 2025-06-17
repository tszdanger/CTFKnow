# IR 1  
https://github.com/daffainfo/ctf-
writeup/blob/main/NahamCon%20CTF%202023/IR%20%231  
# IR 2  
https://github.com/daffainfo/ctf-
writeup/blob/main/NahamCon%20CTF%202023/IR%20%232  
# IR 3  
https://github.com/daffainfo/ctf-
writeup/blob/main/NahamCon%20CTF%202023/IR%20%233  
# IR 4  
https://github.com/daffainfo/ctf-
writeup/blob/main/NahamCon%20CTF%202023/IR%20%234  
# IR 5  
https://github.com/daffainfo/ctf-
writeup/blob/main/NahamCon%20CTF%202023/IR%20%235

Original writeup (https://github.com/daffainfo/ctf-
writeup/blob/main/NahamCon%20CTF%202023/IR%20%231).# IR (49 solves)

Description:

>  We found this snippet of code on our employee's laptop. It looks really
> scary.  
>  
> Can you figure out what it does?  
>  
> Written by `hk`

We are given a program source code in  **llvm** language.

```

@check = dso_local global [64 x i8]
c"\03\12\1A\17\0A\EC\F2\14\0E\05\03\1D\19\0E\02\0A\1F\07\0C\01\17\06\0C\0A\19\13\0A\16\1C\18\08\07\1A\03\1D\1C\11\0B\F3\87\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\05",
align 16, !dbg !0  
@MAX_SIZE = dso_local global i32 64, align 4, !dbg !8

define dso_local i32 @_Z7reversePc(i8*) #0 !dbg !19 {  
 %2 = alloca i32, align 4  
 %3 = alloca i8*, align 8  
 %4 = alloca i32, align 4  
 %5 = alloca i32, align 4  
 %6 = alloca i32, align 4  
 store i8* %0, i8** %3, align 8  
 call void @llvm.dbg.declare(metadata i8** %3, metadata !24, metadata
!DIExpression()), !dbg !25  
 call void @llvm.dbg.declare(metadata i32* %4, metadata !26, metadata
!DIExpression()), !dbg !28  
 store i32 0, i32* %4, align 4, !dbg !28  
 br label %7, !dbg !29  
 ...  
 ...  
 ...  
```

I tried compiling it back using clang but no luck. Author probably wanted us
to do it by hand.

So, you go here https://llvm.org/docs/LangRef.html. You learn what every
instruction does. You come back and write it back to C code.

After some time I came up with this code:

```c++  
#define MAX_SIZE 64  
char password[64] = {};  
const char flag[MAX_SIZE] =
"\x03\x12\x1A\x17\x0A\xEC\xF2\x14\x0E\x05\x03\x1D\x19\x0E\x02\x0A\x1F\x07\x0C\x01\x17\x06\x0C\x0A\x19\x13\x0A\x16\x1C\x18\x08\x07\x1A\x03\x1D\x1C\x11\x0B\xF3\x87\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05";  
int main()  
{  
 for (int i = 0; i < MAX_SIZE; i++)  
   password[i] = password[i] + 5;

 for (int i = 0; i < MAX_SIZE - 1; i++)  
 {  
   char c_1 = password[i + 1];  
   char c_0 = password[i];  
   password[i] = c_0 ^ c_1;  
 }  
 return 0;  
}  
```

Solution:

```python  
import sys

def main():  
   flag =
"\x03\x12\x1A\x17\x0A\xEC\xF2\x14\x0E\x05\x03\x1D\x19\x0E\x02\x0A\x1F\x07\x0C\x01\x17\x06\x0C\x0A\x19\x13\x0A\x16\x1C\x18\x08\x07\x1A\x03\x1D\x1C\x11\x0B\xF3\x87"  
   out = ""  
   last = 0 # null  
   for j in range(len(flag) - 1, -1, -1):  
       for i in range(32, 127):  
           if ((i + 5) ^ (last + 5)) == ord(flag[j]):  
               out += chr(i)  
               last = i  
               break  
   print(out[::-1])  
  
if __name__ == "__main__":  
   sys.exit(main())  
```

Since we know that the last byte in out input is NULL (string terminator)

We Iterate from end to beginning and get one byte at the time.

```  
utflag{machine_agnostic_ir_is_wonderful}  
```

Original writeup (https://github.com/archercreat/CTF-
Writeups/blob/master/utctf/rev/IR/README.md).