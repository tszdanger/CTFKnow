# Zeh (solved, 100p)

## Description  
In the task we get a classic 64bit ELF linux binary where we have to give it
two numbers for it to print out the flag. We are also given the C source code
that created the binary.

## Static Analysis  
Since we are given the source code we don't have to use a disassembler and can
just open the source code in your favorite editor.

```C  
#include <stdio.h>  
#include <stdlib.h>  
#include "fahne.h"

#define Hauptroutine main  
#define nichts void  
#define Ganzzahl int  
#define schleife(n) for (Ganzzahl i = n; i--;)  
#define bitrverschieb(n, m) (n) >> (m)  
#define diskreteAddition(n, m) (n) ^ (m)  
#define wenn if  
#define ansonsten else  
#define Zeichen char  
#define Zeiger *  
#define Referenz &  
#define Ausgabe(s) puts(s)  
#define FormatAusgabe printf  
#define FormatEingabe scanf  
#define Zufall rand()  
#define istgleich =  
#define gleichbedeutend ==

nichts Hauptroutine(nichts) {  
   Ganzzahl i istgleich Zufall;  
   Ganzzahl k istgleich 13;  
   Ganzzahl e;  
   Ganzzahl Zeiger p istgleich Referenz i;

   FormatAusgabe("%d\n", i);  
   fflush(stdout);  
   FormatEingabe("%d %d", Referenz k, Referenz e);

   schleife(7)  
       k istgleich bitrverschieb(Zeiger p, k % 3);

   k istgleich diskreteAddition(k, e);

   wenn(k gleichbedeutend 53225)  
       Ausgabe(Fahne);  
   ansonsten  
       Ausgabe("War wohl nichts!");  
}  
```  
First things first, we have to translate it out of German.  
```C  
#include <stdio.h>  
#include <stdlib.h>  
#include "fahne.h"

void main(void) {  
   int i = rand();  
   int k = 13;  
   int e;  
   int *p = &i;

   printf("%d\n", i);  
   fflush(stdout);  
   scanf("%d %d", &k, &e);

   for(int i = 7; i--;)  
       k = (*p) >> (k%3);

   k = (k)^(e);

   if(k == 53225)  
       puts(Fahne);  
   else  
       puts("War wohl void!");  
}

```  
The code is a lot cleaner now and we can get some basic information:  
- They are not setting a random seed so we know `rand()` will return 1804289383 everytime  
- We need k to equal 53225 after all is said and done  
- Our input is being bitshifted and XOR'ed

I thought this would be a good way to use angr since the loop will only ever
go 7 times. This ensures that there wont be too many states for angr to go
through.

## Disassembly

Lets open our binary in Ghidra to get the address we need to solve to.  
```assembly  
       0010124c 48 8d 3d        LEA        RDI,[DAT_00102019]  
                c6 0d 00 00  
       00101253 e8 d8 fd        CALL       puts

       00101258 eb 0c           JMP        LAB_00101266

```  
We need to get to `CALL puts`(0x00101253) to consider this problem solved. We
also know that the solution will have to be 4 bytes long because it's a C int.

## Solution  
We have everything we need to code our solution:  
```python  
import angr  
import claripy  
import subprocess  
import sys

program_name      = "a.out"  
find_address      = 0x00001253  
num_bytes_of_flag = 0x04

import logging  
logging.getLogger('angr').setLevel(logging.INFO)

# num_keys = get_arg()

proj = angr.Project(program_name,  
                   main_opts = {"base_addr": 0}, # PIE binary  
)

# create an array of bitvectors so that the value of each can easily be  
# constrained to the range of printable ASCII characters  
key_bytes = [claripy.BVS("byte_%d" % i, 8) for i in
range(num_bytes_of_flag*8)]  
key_bytes_AST = claripy.Concat(*key_bytes)

# we want to generate valid keys, so a symbolic variable is passed to  
# the state rather than a concrete value  
state = proj.factory.full_init_state(args = ["./"+program_name],
add_options=angr.options.unicorn)

# impose constraints on bitvectors the symbolic key is composed of  
for byte in key_bytes:  
   state.solver.add(byte >= 0x21, byte <= 0x7e)

sm = proj.factory.simulation_manager(state)

# find path to message indicating key was correct  
sm.explore(find = find_address)

if len(sm.found) > 0:  
   print("[ + ]  %s" % (sm.found[0].posix.dumps(0)))  
else:  
   print("[ x ] No solution found")  
```  
After about ~3 seconds Angr came up with two numbers that satisfy the program.
Angr gave me "3578031137 1804307086" as a solution. Once given to the program
it will print out the flag.

flag = CSR{RUECKWARTSINGENEUREN}

Original writeup
(https://github.com/tHoMaStHeThErMoNuClEaRbOmB/ctfwriteups/blob/master/CyberSecurityRumblectf/reverse/Zeh/README.md).