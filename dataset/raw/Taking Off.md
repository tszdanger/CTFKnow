# Taking Off (433 solves)

> So you started revving up, but is it enough to take off? Find the problem in
> `/problems/2020/taking_off/` in the shell server.  
>  
> Author: aplet123

main:

```c++  
void __fastcall main(int argc, const char **argv, const char **envp)  
{  
 int v3;  
 int v4;  
 int v5;  
 int i;  
 int v7;  
 char *v8;  
 char s[136];  
 unsigned __int64 v10;

 v10 = __readfsqword(0x28u);  
 puts("So you figured out how to provide input and command line arguments.");  
 puts("But can you figure out what input to provide?");  
 if ( argc == 5 )  
 {  
   string_to_int(argv[1], (__int64)&v3;;  
   string_to_int(argv[2], (__int64)&v4;;  
   string_to_int(argv[3], (__int64)&v5;;  
   if ( is_invalid(v3)  
     || is_invalid(v4)  
     || is_invalid(v5)  
     || 100 * v4 + 10 * v3 + v5 != 932  
     || strcmp(argv[4], "chicken") )  
   {  
     puts("Don't try to guess the arguments, it won't work.");  
   }  
   else  
   {  
     puts("Well, you found the arguments, but what's the password?");  
     fgets(s, 128, stdin);  
     v8 = strchr(s, 10);  
     if ( v8 )  
       *v8 = 0;  
     v7 = strlen(s);  
     for ( i = 0; i <= v7; ++i )  
     {  
       if ( ((unsigned __int8)s[i] ^ 0x2A) != desired[i] )  
       {  
         puts("I'm sure it's just a typo. Try again.");  
         return;  
       }  
     }  
     puts("Good job! You're ready to move on to bigger and badder rev!");  
     print_flag();  
   }  
 }  
 else  
 {  
   puts("Make sure you have the correct amount of command line arguments!");  
 }  
}  
```

Solution:

```python  
import angr  
import claripy  
import sys  
from z3 import *

def main():

   proj = angr.Project('taking_off')  
  
   arg1 = claripy.BVS('arg1', 8)  
   arg2 = claripy.BVS('arg2', 8)  
   arg3 = claripy.BVS('arg3', 8)

   argv = [  
       proj.filename,  
       arg1,  
       arg2,  
       arg3,  
       'chicken'  
   ]

   state = proj.factory.entry_state(args=argv)

   simgr = proj.factory.simgr(state)

   simgr.explore(  
       find=0x400bb3,  
       avoid=[0x400ACA, 0x400b84, 0x4009d6]  
   )

   print(simgr)  
   if len(simgr.found) > 0:  
	    f = simgr.found[-1]  
       print(f.posix.dumps(0))  
       print(f.solver.eval(arg1, cast_to=bytes))  
       print(f.solver.eval(arg2, cast_to=bytes))  
       print(f.solver.eval(arg3, cast_to=bytes))

if __name__ == "__main__":  
   solve()  
   sys.exit(main())  
```

```bash  
<SimulationManager with 1 found, 18 avoid>  
b'please give flag\x00\x00\x00\x00\x10\x01\x08\x02\x02\x02 \x01\x01\x01\x08
\x00\x00\x00\x00\x02 \x80  \x80\x10 \x02
\x80@\x08\x02\x04\x10\x02\x80\x80@\x04
\x80\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  
b'3'  
b'9'  
b'2'  
```

```bash  
$ ./taking_off 3 9 2 chicken  
So you figured out how to provide input and command line arguments.  
But can you figure out what input to provide?  
Well, you found the arguments, but what's the password?  
please give flag  
Good job! You're ready to move on to bigger and badder rev!  
actf{th3y_gr0w_up_s0_f4st}  
```

Original writeup (https://github.com/archercreat/CTF-
Writeups/blob/master/angstromctf/rev/Taking%20Off/README.md).