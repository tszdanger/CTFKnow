# Signal of Hope (42 solves)

> Find it on the shell server at /problems/2020/signal_of_hope/ or over tcp at
> nc shell.actf.co 20202.  
>  
> Author: aplet123

hint: GDB does some special things to signals that can trip you up.

In this task we have to deal with virtual machine based on signals. Signal
handler executes specified function based on signal code.

main:

```c++  
void main()  
{  
 int *v3;  
 __gid_t v4;

 v3 = signal_codes;  
 setvbuf(stdout, 0LL, 2, 0LL);  
 v4 = getegid();  
 setresgid(v4, v4, v4);  
 new.it_value.tv_sec = 0LL;  
 new.it_value.tv_usec = 1000LL;  
 new.it_interval.tv_sec = 0LL;  
 new.it_interval.tv_usec = 1000LL;  
 puts("It's a rainy night and you're lost in the forest.");  
 puts("Your house is nowhere to be seen and you're quite discouraged.");  
 puts("But alas, in the distance, a fading beacon!");  
 puts("You fill with hope, but it'll soon weaken.");  
 puts("But can you make it before you collapse?");  
 puts("Through thick and thin, and past the traps.");  
 while ( signal(*v3, handler) != 1 )  
 {  
   ++v3;  
   if ( v3 == &signal_codes[7] )  
   {  
     setitimer(ITIMER_REAL, &new, 0LL);  
     while ( 1 )  
       _IO_getc(stdin);  
   }  
 }  
 puts("Something feels off, you can't go longer.");  
 puts("A bear emerges, and he is stronger.");  
 exit(1);  
}  
```

We have 7 signal codes and 7 functions related to them:

|         Signal codes          |     Function     |       Description        |        opcodes         |  
| :---------------------------: | :--------------: | :----------------------: | :--------------------: |  
|           IOT Trap            |    print_flag    |      prints flag :)      |                        |  
|          Alarm clock          | signal generator |  generates next signal   | 0x69, 0x1b, 0x76, 0x4f |  
|      Illegal instruction      |      inc_i       |      adds var1 to i      |    0x86, 0x87, 0x8e    |  
|   Floating point exception    |   get_input_i    |      gets input[i]       |       0x77, 0x6a       |  
| Invalid memory segment access |    get_input     | gets input (called once) |          0x62          |  
|          Trace trap           |   get_bytecode   |    sets var2 = opcode    |          0xCC          |  
|      Terminal interrupt       |        vm        |      process opcode      |      0xF0 - 0xFD       |

Before we continue, because of trace trap (int 3), we could not debug
properly. So I changed Trace trap to 15 (SIGTERM). I also patched **signal
generator** function to call **raise** with code 15 when it finds 0xCC opcode.

After that, everything went smooth :)

The signal handler looks like this:

```c++  
void handler(int code)  
{  
 int v1 = 0, i;  
  
 while ( 1 )  
 {  
   i = v1;  
   if (code == signal_codes[v1] )  
     break;  
   if ( ++v1 == 7 )  
   {  
     i = -1LL;  
     break;  
   }  
 }  
 handlers[i]();  
}  
```

vm function:

```c++  
void vm()  
{  
 __int64 v0;  
 __int64 v1;  
 char v2;

 switch ( opcode )  
 {  
   case 0xF0u:  
     var1 = input[i] - input_byte;  
     break;  
   case 0xF1u:  
     var1 += var2;  
     break;  
   case 0xF2u:  
     var1 -= var2;  
     break;  
   case 0xF3u:  
     var1 *= var2;  
     break;  
   case 0xF4u:  
     var1 ^= var2;  
     break;  
   case 0xF5u:  
     var2 = var1;  
     break;  
   case 0xF6u:  
     var1 = var2;  
     break;  
   case 0xF7u:  
     v1 = j++;  
     buffer[v1] = var1;  
     break;  
   case 0xF8u:  
     var1 = buffer[--j];  
     break;  
   case 0xF9u:  
     if ( var1 != var2 )  
     {  
       puts("The trap is not approving of your trip.");  
       puts("It blocks your passage with its whip.");  
       exit(1);  
     }  
     return;  
   case 0xFAu:  
     var1 = input[i];  
     break;  
   case 0xFBu:  
     v2 = var2;  
     var2 = var1;  
     var1 = v2;  
     break;  
   case 0xFCu:  
     v0 = k++;  
     byte_602280[v0] = var1;  
     break;  
   case 0xFDu:  
     var1 = byte_602280[--k];  
     break;  
   default:  
     puts("The trap shorts out and sparks like crazy.");  
     puts("But a spark hits you and you become hazy.");  
     exit(1);  
     return;  
 }  
}  
```

Solution:

Since bytecode is small and linear (no conditional jumps). We can easily trace
it.

I know that flag length has to be 10, it is easily found by reversing
**get_input** function.

I did set bp on every handler, and watched what happens to my input.

First, the program checks:

> **key[0] + key[4] + key[4 + key[4]] == 6**

after that, it checks:

> **key[0] * key[4] * key[4 + key[4]] == 6**

and in the end:

> **key[(4 + key[4] + 0xfb) & 0xff] == 0x1b**

After reversing, I wrote simple keygen :)

```python  
from z3 import *

def find_all_possible(s, key):  
   while s.check() == sat:  
       model = s.model()  
       block = []  
       out = ''  
       for i in range(10):  
           c = key[i]  
           out += chr(model[c].as_long())  
           block.append(c != model[c])  
       s.add(Or(block))  
       print(out)

def main():  
   s = Solver()  
   key = list()

   for i in range(10):  
       key.append(BitVec('b%d' % i, 8))  
       s.add(key[i] > 32, key[i] < 127)  
   c0 = key[0] - 0x46  
   c1 = key[1] - 0x46  
   c4 = key[4] - 0x46  
   c6 = key[6] - 0x46  
   s.add(c4 == 2)  
   s.add(c6 + c4 + c0 == 6)  
   s.add(c6 * c4 * c0 == 6)  
   s.add(c1 == 0x1b)

   find_all_possible(s, key)

if __name__ == "__main__":  
   sys.exit(main())  
```

Giving **Ga&SHhIH4Q** to the program yields the flag:

```  
actf{h0p3_c4nn0t_m3nd_th3_p41n_th4t_y0uv3_c4us3d_m3}  
```

Original writeup (https://github.com/archercreat/CTF-
Writeups/blob/master/angstromctf/rev/Signal%20of%20Hope/README.md).