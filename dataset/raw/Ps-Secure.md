Ps-secure  
---------

### Description  
The program was about to generate the flag when something went wrong. We have
a coredump of the process.

### Pwn tutorial  
Process crashed on: `0x555555554e9a    inc    dword ptr [rax]` with `RAX
0x555555554e9a ◂— inc    dword ptr [rax]`, thus trying to write in a text
segment caused segfault. We noticed that the original program had 4 args:
`integer, integer, input file, output file`

#### By reversing program we understood that...  
The first two integers, namely `num1` and `num2`, in `argv` are used to seed 2
independent LCG.  
Unfortunately `argv` was partially overwritten with *xxxx* by the program, so
the original LCG states are lost.

The first function `sub_B3B` opens the input file, generates a random offset
(using state num1) and seeks at this offset.  
Then 128 bytes are read and stored in a heap buffer at address
`0x5555557588b0`.

The program then calls `sub_B0A` which gets 1 byte offset from rand  
to modify the caller stack frame by adding this offset to the stored RIP. As
such a function that calls `sub_B0A` does not return where it was called, but
somewhere after that point.

Since the program flow depends on the output of `rand` and the initial state
is unknown, we can't recreate the correct execution flow.  
So we tried to recover `num1` and `num2` from the stack when the process
crashed, specifically at addresses `0x7fffffffec90` and `0x7fffffffec94`,
respectively. We also noticed that the state `num2` is only used by `sub_B0A`,
while `num1` is used for all the remaining rand calls (*i.e.*, seek offset,
aligner, flag gen).

Knowing the last state of `num2` we calculated both the previous states and
the corresponding rand output. In order to identify the inital `num2` state,
we tried to identify which value would make sense for the first `sub_B0A`
call.

The function `noise_loader` (called from main `@0x1159`) has saved return
address `0x115E`, so we assumed that the modified RIP would point to
`0x0118D`. As a result the random offset must be `0x0118D - 0x115E = 47`. Now
we have calculated the list of `num2` states starting from the last and back
to the (found to be) initial one:  
```  
state_num2[0] -> 2031993358

state_num2[-1] -> 1480659687  
rand() -> 29 # offset of third sub_B0A

state_num2[-2] -> 2318365684  
rand() -> 65 # offset of second sub_B0A

state_num2[-3]: 10821 # i.e. initial arvg[2]  
rand() -> 47 # offset of first sub_B0A  
```

#### At this stage we can reconstruct the real flow of the program:

```c  
void main(int argc, char **argv)  
{  
   char *func_ptr;  
   int i, j;  
   char filename[32];  
   int num1 = 0;  
   int num2 = 0;

   printf("Thanks for choosing Ps Security\n");  
   if ( argc <= 4 )  
   {  
       printf("Not enough parameters\n");  
       exit(1);  
   }  
   if ( strlen(argv[4]) > 0x1F )  
   {  
       printf("Filename too long\n");  
       exit(1);  
   }  
   num1 = atoi(argv[1]);  
   num2 = atoi(argv[2]);  
   for (i = 0; i < strlen(argv[1]); ++i)  
       argv[1][i] = 'x';  
   for (j = 0; j < strlen(argv[2]); ++j)  
       argv[2][j] = 'x';  
   sub_B3B(argv[3], &num1, &num2;;  
   sub_E51(&num1, (unsigned int *)&num2;;  
   strcpy(filename, argv[4]);  
   strcat(filename, ".tXt");  
   func_ptr = (char *)sub_E51 + (signed int)rand_((unsigned int *)&num1) % 65
+ 0x1C;  
   printf("Hold your breath..\n");  
  
   ((void (__fastcall *)(char *, int *, int *))func_ptr)(filename, &num1,
&num2;;  
   // which actually corresponds to sub_E9F(filename, &num1, &num2;;  
}

int64_t sub_E51(int *num1, unsigned int *num2)  
{  
   sub_B0A(num2);  
   sub_BD2(num1, num2);  
}  
```

At end of main there is a function call that uses `sub_E51` as base address,
adding a random offset computed from `rand(num1)`.  
We noticed that `strcat(filename, ".tXt")` caused an overflow that overwrites
the value of `num1` with `"tXt\x00"`: this makes the subsequent rand call to
produce a bad offset which then made the program crash.

Here we started to make educated guesses on the offset that would produce the
correct call: the allowed address range is `[0xE51+0x1C, 0xE51+0x1C+0x40]`.
Probably the most correct address in this range is the beginning of `sub_E9F`
that, guess what, computes and prints the flag! However, `sub_E9F` uses
`rand(num1)` to compute the flag so we still needed to recover the correct
`num1` state. We identified a set of constraints to calculate this value:

* The first rand value is equal to the seek position (fseek value recovered from the FILE struct in the heap)  
* In function `sub_BD2` rand rand is repeatedly called until `rand(num1) == 0`.  
   This function prints a dot every 50 iterations and `"\n   "` every 50 dots.  
   We know that this functions gets called since, looking at the printf heap
buffer `@0x555555757260`, we can tell that at least one full line of dots has
been printed and the last line had 30 dots.  
* So the number of iterations of the while is `2500 + 2500*k + 1500 + [0,49]`  
* The last rand call is used to calculate `func_ptr` so `rand(num1) % 65 == 50`

Using these constraints we tested every possible num1 state value and we have
identified about 30 candidates.  
As a final step we implemented the code that generates the flag in C and...
the first generated flag was correct /o\

#### Followed a proper Italian-style celebration!

Original writeup
(https://mhackeroni.it/archive/2018/05/20/defconctfquals-2018-all-
writeups.html#ps-secure).