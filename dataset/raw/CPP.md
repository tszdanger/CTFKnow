# CPP

**Category**: rev \  
**Points**: 75 (155 solves)

We have this program's source code, but it uses a strange DRM solution. Can
you  
crack it?

Attachments: `cpp.c`

## Overview

We're given an enormous C file (around 6000 lines) filled with preprocessor  
statements. Trying to compile it gives:

```  
$ gcc cpp.c  
cpp.c:110:2: warning: #warning "Please wait a few seconds while your flag is
validated." [-Wcpp]  
 110 | #warning "Please wait a few seconds while your flag is validated."  
     |  ^~~~~~~  
In file included from cpp.c:6221,  
                from cpp.c:6218,  
                from cpp.c:6218,  
                from cpp.c:6221,  
                from cpp.c:6218,  
                from cpp.c:6221,  
                from cpp.c:6218,  
                from cpp.c:6218,  
                from cpp.c:6221,  
                from cpp.c:6218,  
                from cpp.c:6218,  
                from cpp.c:6218,  
                from cpp.c:6218:  
cpp.c:6208: error: #error "INVALID_FLAG"  
6208 | #error "INVALID_FLAG"  
     |  
```

Opening the file, it starts with:  
```c  
#if __INCLUDE_LEVEL__ == 0  
// Please type the flag:  
#define FLAG_0 CHAR_C  
#define FLAG_1 CHAR_T  
#define FLAG_2 CHAR_F  
#define FLAG_3 CHAR_LBRACE  
#define FLAG_4 CHAR_w  
#define FLAG_5 CHAR_r  
#define FLAG_6 CHAR_i  
#define FLAG_7 CHAR_t  
#define FLAG_8 CHAR_e  
#define FLAG_9 CHAR_UNDERSCORE  
#define FLAG_10 CHAR_f  
#define FLAG_11 CHAR_l  
#define FLAG_12 CHAR_a  
#define FLAG_13 CHAR_g  
#define FLAG_14 CHAR_UNDERSCORE  
#define FLAG_15 CHAR_h  
#define FLAG_16 CHAR_e  
#define FLAG_17 CHAR_r  
#define FLAG_18 CHAR_e  
#define FLAG_19 CHAR_UNDERSCORE  
#define FLAG_20 CHAR_p  
#define FLAG_21 CHAR_l  
#define FLAG_22 CHAR_e  
#define FLAG_23 CHAR_a  
#define FLAG_24 CHAR_s  
#define FLAG_25 CHAR_e  
#define FLAG_26 CHAR_RBRACE  
```

Then we see  
```c  
// No need to change anything below this line  
#define CHAR_a 97  
#define CHAR_b 98  
#define CHAR_c 99  
...  
#warning "Please wait a few seconds while your flag is validated."  
#define S 0  
#define ROM_00000000_0 1  
#define ROM_00000000_1 1  
#define ROM_00000000_2 0  
// ...  
#define ROM_01011010_5 0  
#define ROM_01011010_6 0  
#define ROM_01011010_7 0  
```

So we have a few constants defined, as well as a ROM. Next we see the flag  
getting loaded into the ROM bit-by-bit:  
```c  
#if FLAG_0 & (1<<0)  
#define ROM_10000000_0 1  
#else  
#define ROM_10000000_0 0  
#endif  
#if FLAG_0 & (1<<1)  
#define ROM_10000000_1 1  
#else  
#define ROM_10000000_1 0  
#endif  
...  
```

Now we get to the hard part:  
```c  
#define _LD(x, y) ROM_ ## x ## _ ## y  
#define LD(x, y) _LD(x, y)  
#define _MA(l0, l1, l2, l3, l4, l5, l6, l7) l7 ## l6 ## l5 ## l4 ## l3 ## l2
## l1 ## l0  
#define MA(l0, l1, l2, l3, l4, l5, l6, l7) _MA(l0, l1, l2, l3, l4, l5, l6, l7)  
#define l MA(l0, l1, l2, l3, l4, l5, l6, l7)  
#endif  
#if __INCLUDE_LEVEL__ > 12  
#if S == 0  
#undef S  
#define S 1  
#undef S  
#define S 24  
#endif

// ... (around 4000 lines)

#endif  
#if S == 57  
#undef S  
#define S 58  
#error "INVALID_FLAG"  
#endif  
#if S == 58  
#undef S  
#define S 59  
#undef S  
#define S -1  
#endif  
#else  
#if S != -1  
#include "cpp.c"  
#endif  
#if S != -1  
#include "cpp.c"  
#endif  
#endif  
#if __INCLUDE_LEVEL__ == 0  
#if S != -1  
#error "Failed to execute program"  
#endif  
#include <stdio.h>  
int main() {  
printf("Key valid. Enjoy your program!\n");  
printf("2+2 = %d\n", 2+2);  
}  
#endif  
```

So the goal is just to get the program to compile.

## Solution

> Solved with a0su

First let's indent the blocks properly to make things more readable. I wrote  
a recursive descent parser in `parse.py` that will format it nicely (output  
shown in `indented.txt`).

Here's a high-level overview of the program:

```c  
#if __INCLUDE_LEVEL__ == 0  
   // Preliminary stuff:  
   // - Define flag characters  
   // - Define constants and ROM  
   // - Define `LD` macros, used to load values from ROM  
   // - Set variable S = 0  
#endif

#if __INCLUDE_LEVEL__ > 12  
   // Flag checking logic

   #if S == 0  
       // ...  
   #endif  
   #if S == 1  
       // ...  
   #endif  
   #if S == 2  
       // ...  
   #endif  
   // ... (more cases)  
   #if S == 57  
       #undef S  
       #define S 58  
       #error "INVALID_FLAG"  
   #endif

   #if S == 58  
       // Correct flag  
       #undef S  
       #define S -1  
   #endif

#else  
   // The program includes itself twice in each recursive include, and  
   // 604 times in total  
   #if S != -1  
       #include "cpp.c"  
   #endif  
   #if S != -1  
       #include "cpp.c"  
   #endif  
#endif

#if __INCLUDE_LEVEL__ == 0  
   #if S != -1  
       #error "Failed to execute program"  
   #endif

   #include <stdio.h>  
   int main() {  
       printf("Key valid. Enjoy your program!\n");  
       printf("2+2 = %d\n", 2+2);  
   }  
#endif  
```

Looks like the bulk of the reversing will be in the series of `if` statments
on  
`S`.

```c  
   #if S == 0  
       #undef S  
       #define S 1  
       #undef S  
       #define S 24  
   #endif  
```

So case 0 just jumps to case 24.

```c  
   #if S == 1  
       #undef S  
       #define S 2  
       #ifdef R0  
           #undef R0  
       #else  
           #define R0  
       #endif  
       #ifdef R1  
           #undef R1  
       #else  
           #define R1  
       #endif  
       // ...  
       #ifdef R7  
           #undef R7  
       #else  
           #define R7  
       #endif  
   #endif  
```

Case 1 just inverts `R0` through `R7`. If we consider `R0 - R7` as one byte,  
then it just does `R = R ^ 0b11111111`.

```c  
   #if S == 2  
       #undef S  
       #define S 3  
       #define Z0  
       #undef Z1  
       #undef Z2  
       #undef Z3  
       #undef Z4  
       #undef Z5  
       #undef Z6  
       #undef Z7  
   #endif  
```

Case 2 sets `Z = 0`.

```c  
   #if S == 3  
       #undef S  
       #define S 4  
       #undef c  
       #ifndef R0  
           #ifndef Z0  
               #ifdef c  
                   #define R0  
                   #undef c  
               #endif  
           #else  
               #ifndef c  
                   #define R0  
                   #undef c  
               #endif  
           #endif  
       #else  
           #ifndef Z0  
               #ifdef c  
                   #undef R0  
                   #define c  
               #endif  
           #else  
               #ifndef c  
                   #undef R0  
                   #define c  
               #endif  
           #endif  
       #endif  
       // Same thing for R1 - R7  
```

This case is a little more complicated, but it actually just does `R = R + Z`.  
Here `c` is the carry bit.

After manually reversing a few more cases, we get to case 34:

```c  
   #if S == 34  
       #undef S  
       #define S 35  
       #undef l0  
       #ifdef B0  
           #define l0 1  
       #else  
           #define l0 0  
       #endif  
       // Same thing for B1 - B7  
       #if LD(l, 0)  
           #define A0  
       #else  
           #undef A0  
       #endif  
       // Same thing for A1 - A7  
```

Looking at the macros defined earlier,

```c  
#define _LD(x, y) ROM_ ## x ## _ ## y  
#define LD(x, y) _LD(x, y)  
#define _MA(l0, l1, l2, l3, l4, l5, l6, l7) l7 ## l6 ## l5 ## l4 ## l3 ## l2
## l1 ## l0  
#define MA(l0, l1, l2, l3, l4, l5, l6, l7) _MA(l0, l1, l2, l3, l4, l5, l6, l7)  
#define l MA(l0, l1, l2, l3, l4, l5, l6, l7)  
```

we can see that case 34 just does `A = ROM[B]`.

After reversing the rest of the cases, we reach case 56, which checks if `Q ==  
0`. If so, then the flag is correct.

Now that we've simplified the program, it's much easier to rewrite it in
Python  
to solve with Z3. Solve script in `solve.py`:

```  
$ python3 solve.py  
............................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................  
Win  
sat  
CTF{pr3pr0cess0r_pr0fe5sor}  
```

And now we can finally compile the program  
```  
$ gcc cpp.c  
cpp.c:110:2: warning: #warning "Please wait a few seconds while your flag is
validated." [-Wcpp]  
 110 | #warning "Please wait a few seconds while your flag is validated."  
     |  ^~~~~~~

$ ./a.out  
Key valid. Enjoy your program!  
2+2 = 4  
```

## Timeline

### Friday

- `09:45 PM - 10:15 PM`  
 - Start challenge, start writing flag and ROM logic in Python.

- `10:15 PM - 11:30 PM`  
 - Start looking at flag checking logic but not making progress.  
 - Decide to write recursive descent parser and interpreter to attempt symbolic  
   execution.

- `11:30 PM - 12:30 AM`  
 - Finish recursive descent parser, start interpreter.

## Saturday

- `12:30 AM - 01:00 AM`  
 - Finish interpreter, but realize that `cpp.c` actually includes itself  
   making the control flow more complicated than I anticipated.  
 - Decide to manually reverse flag checking logic.

- `01:00 AM - 02:30 AM`  
 - Finish manually reversing all the `S` cases.  
 - Verified that some cases are indeed implementing addition properly.

- `02:30 AM - 04:00 AM`  
 - Rewriting flag checker in Python.  
 - Attempt solving with Z3, but unsure how to apply to apply constraints.

- `04:00 AM - 12:00 PM`  
 - Sleep

- `12:00 PM - 01:15 PM`  
 - Finish flag checking logic and applied constraints, but Z3 model is unsat.

- `01:15 PM - 03:00 PM`  
 - Cooking lunch

- `03:00 PM - 03:45 PM`  
 - Try connecting `S` cases to understand logic better.

- `03:45 PM - 03:47 PM`  
 - Find bug in case 15: Wrote `Z = X` instead of `Z = R`.  
 - Re-running the script magically prints the flag :tada:  

Original writeup (https://github.com/cscosu/ctf-
writeups/tree/master/2021/google_ctf/cpp).