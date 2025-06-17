# Fast calculator (rev)  
Writeup by: [xlr8or](https://ctftime.org/team/235001)

As part of this challenge we only get a single ELF binary `calc`. Thankfully
it is not stripped therefore we get some function names.  
The binary is a calculator (the description suggests that it is fast), and it
allows us to perform some operations: add, subtract, multiply, divide,
exponentiation, modulo.  
All the operations result in floating point numbers and accept floating point
numbers as their argument.

Let's decompile the binary in ghidra now. `main` looks a bit odd, since ghidra
struggles a bit with the caling convention. Essentially before each call, the
decompiler shows, that the return address is placed on the stack. Let's look
at the interesting part:  
```c  
   dVar10 = calculate(*(ulong *)((long)puVar7 + -0xba0),*(double
*)((long)puVar7 + -0xb98),  
                      *(double *)((long)puVar7 + -0xb90));  
   calculation_result = SUB168((float16)dVar10,0);  
   *(undefined8 *)((long)puVar7 + -0xb88) = 0x401f5d;  
   printf("Result: %lf\n",SUB168((float16)dVar10,0));  
   if (calculation_result == 8573.8567) {  
		      *(undefined8 *)((long)puVar7 + -0xb88) = 0x401f88;  
     puts("\nCorrect! Attempting to decrypt the flag...");  
```

(a bit different from the first decompile, since I have already renamed some
stuff, and set the calling convention for `calculate`). We see that if the
result of the calculation is  exactly 8573.8567, then the program will attempt
to decrypt the flag. Since the decryption process does not depend on any
calculation history or result, my first idea was to bypass the check using a
debugger, and to print the flag.  
```  
Correct! Attempting to decrypt the flag...  
I calculated 368 operations, tested each result in the gauntlet, and flipped
119 bits in the encrypted flag!  
Here is your decrypted flag:

uiuctf{This is a fake flag. You are too fast!}  
```

Okay, it clearly would have been too easy to do this, let's take a look at the
decrypt mechanism:  
```c  
 memcpy(local_22f8,&DAT_004b8240,0x2280);  
 local_78 = 0x10eeb90001e1c34b;  
 local_70 = 0xcb382178a4f04bee;  
 local_68 = 0xe84683ce6b212aea;  
 local_60 = 0xa0f5cf092c8ca741;  
 local_58 = 0x20a92860082772a1;  
 local_50 = 0x35abb366;  
 local_4c = 0xe9a4;  
 local_2360 = 0x2e;  
 local_235c = 0x170;  
	// ...  
     __n = (size_t)local_2360;  
     *(undefined8 *)(puVar8 + lVar1 + -8) = 0x402051;  
     memcpy(puVar8 + lVar1,&local_78,__n);  
     local_2368 = 0;  
     for (local_2364 = 0; local_2364 < (int)local_235c; local_2364 = local_2364 + 1) {  
       lVar6 = (long)local_2364;  
       *(undefined8 *)(puVar8 + lVar1 + -0x10) = local_22f8[lVar6 * 3 + 2];  
       *(undefined8 *)(puVar8 + lVar1 + -0x18) = local_22f8[lVar6 * 3 + 1];  
       *(undefined8 *)(puVar8 + lVar1 + -0x20) = local_22f8[lVar6 * 3];  
       *(undefined8 *)(puVar8 + lVar1 + -0x28) = 0x40209e;  
       dVar10 = calculate(*(ulong *)(puVar8 + lVar1 + -0x20),*(double *)(puVar8 + lVar1 + -0x18),  
                          *(double *)(puVar8 + lVar1 + -0x10));  
       *(undefined8 *)(puVar8 + lVar1 + -8) = 0x4020b1;  
       cVar3 = gauntlet(SUB168((float16)dVar10,0));  
       if (cVar3 != '\0') {  
         local_2358 = local_2364;  
         if (local_2364 < 0) {  
           local_2358 = local_2364 + 7;  
         }  
         local_2358 = local_2358 >> 3;  
         local_2354 = local_2364 % 8;  
         flag[local_2358] = flag[local_2358] ^ (byte)(1 << (7U - (char)(local_2364 % 8) & 0x1f));  
         local_2368 = local_2368 + 1;  
       }  
     }  
```  
First an array is put on the stack from `local_78`, then this is copied to
another stack location (46 bytes are copied to be exact). After this we loop
over `local_22f8` an array of 368 elements, and perform a calculation based on
items of it. The result is then passed to the `gauntlet` based on which we
either flip a bit in the flag or not. Each operation will either cause a bit
of the flag to flip or not.

We can think of `local_22f8` as an array of the following struct:  
```c  
typedef struct {  
   long op;  
   double a;  
   double b;  
} calculation;  
```

Now let's inspect the `gauntlet`:  
```c  
 char cVar1;  
  
 cVar1 = isNegative(param_1);  
 if (((cVar1 == '\0') && (cVar1 = isNotNumber(param_1), cVar1 == '\0')) &&  
    (cVar1 = isInfinity(param_1), cVar1 == '\0')) {  
   return 0;  
 }  
 return 1;  
```

If the result is negative, not a number, or infinity (positive or negative)
then 1 will be returned and a bit will be flipped, otherwise 0 is returned and
the flag bit is left alone.  
Let's take a moment to discuss doubles here, more specifically [IEEE-754
special values](https://en.wikipedia.org/wiki/IEEE_754#Special_values).  
1. We have 2 kinds of zeroes, a positive and a negative one. This can be problematic for the `isNegative` check, since we need to take care to handle `-0.0`  
2. We have infinity values (positive and negative) for example `1/0` or `-1/0`  
3. We have NaN (not a a number) values, for example `sqrt(-1)` or `0/0`

Let's tackle these one by one

```c  
bool isNegative(double param_1)  
{  
 return param_1 < 0.0;  
}  
```

This is problematic, as it doesn't take into account `-0.0`, which is negative
but not smaller than positive zero. Therefore the gauntlet will not flip some
bits that it should.

```c  
undefined8 isNotNumber(void)

{  
 return 0;  
}

undefined8 isInfinity(void)

{  
 return 0;  
}  
```

This is even more of a problem, these checks are not even done, 0 is returned
all the time. Now the fake flag makes some sense *You are too fast!*, probably
the compiler optimized out these checks. For example `a != a` is often used to
check if a value is NaN, since according to the standard NaN is never equal to
anything.

So we need to fix these by either patching the binary or writing a new one. I
chose to do the latter.

```c  
#include <stdio.h>  
#include <stdlib.h>  
#include <math.h>

typedef struct {  
   long op;  
   double a;  
   double b;  
} calculation;

double do_op(calculation calc) {  
   if (calc.op == '%') {  
       return fmod(calc.a, calc.b);  
   } else if (calc.op == '+') {  
       return calc.a + calc.b;  
   } else if (calc.op == '-') {  
       return calc.a - calc.b;  
   } else if (calc.op == '*') {  
       return calc.a * calc.b;  
   } else if (calc.op == '/') {  
       return calc.a / calc.b;  
   } else if (calc.op == '^') {  
       return pow(calc.a, calc.b);  
   } else {  
       printf("oops %ld\n", calc.op);  
       return -1.0;  
   }  
}

int will_flip(double input) {  
   if (signbit(input)) return 1;  
   if (isnan(input)) return 1;  
   if (isinf(input)) return 1;  
   return 0;  
}

int main() {  
   unsigned char flag[47];  
   *((unsigned long*)&flag[0]) = 0x10eeb90001e1c34b;  
   *((unsigned long*)&flag[8]) = 0xcb382178a4f04bee;  
   *((unsigned long*)&flag[16]) = 0xe84683ce6b212aea;  
   *((unsigned long*)&flag[24]) = 0xa0f5cf092c8ca741;  
   *((unsigned long*)&flag[32]) = 0x20a92860082772a1;  
   *((unsigned int*)&flag[40]) = 0x35abb366;  
   *((unsigned short*)&flag[44]) = 0xe9a4;  
   flag[46] = 0;  
  
   void* mem = malloc(0x2280);  
   FILE* blob = fopen("./ops.bin", "r");  
   fread(mem, 0x2280, 1, blob);  
   fclose(blob);  
   int op_count = 0x2280 / sizeof(calculation);  
   calculation* ops = (calculation* )mem;  
   int flips = 0;  
   for (int i = 0; i < op_count; ++i) {  
       double ans = do_op(ops[i]);  
       int wf = will_flip(ans);  
       if (wf) {  
           flag[i >> 3] ^= (1 << (7 - i % 8));  
       }  
       flips += wf;  
   }  
   printf("flips: %d\n", flips);  
   printf("flag: %s\n", flag);  
   return 0;  
}  
```

* `flag` is a copy of the array starting at `local_47` in the decompiled code  
* `blob` is a pointer to `ops.bin` the raw bytes extracted from `local_22f8`  
* `do_op` is `calculate` in the original binary  
* `will_flip` is `gauntlet` in the original binary

The gauntlet checks are done with macros from libc, and the binary is compiled
without optimizations.  
```  
flips: 244  
flag: uiuctf{n0t_So_f45t_w1th_0bscur3_b1ts_of_MaThs}  
```