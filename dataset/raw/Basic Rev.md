# Basic Rev

## Challenge

How well do you know assembly? Do you know of any tools that can help you?
(Hint, they both start with the letter G)

[basic_rev](https://github.com/tj-oconnor/ctf-
writeups/blob/main/byuctf/basic_rev/basic_rev)

## Solution

The binary is fairly simply to reverse. It requests a number as input and then
constructs a flag (which it never prints.) Simply looking at the assembly, you
could determine the correct input is 289

```  
000023e9  81bddcfeffff2101…cmp     dword [rbp-0x124 {var_12c}], 0x121  
```

However, this felt like an easiest enough problem that I could spend some time
learning more about [angr](https://angr.io) to solve the correct input and
then print the contents of the flag from memory.

We can start the symbolic execution at the beginning of the
``constructFlag()`` function and define a 64-bit symbolic bit vector (``BVS``)
for the first parameter, ``RDI``

```python  
START = 0X2399+BASE  
'''  
00002399  int64_t constructFlag(int32_t arg1)  
'''  
password = claripy.BVS('', 64)  
initial_state.regs.rdi = password  
```

Then we can determine the correct ``GOOD`` and ``BAD`` paths that we would
like to explore()

```python  
'''  
0000270b  488d053a090000     lea     rax, [rel data_304c]  {"Wrong number!"}  
'''  
BAD = 0x270b+BASE

'''  
000026d3  4889c7             mov     rdi, rax {var_128}  
000026d6  e855faffff         call    std::__cxx11::basic_stri...>,
std::allocator<char> >::operator+=  
000026db  488d054e090000     lea     rax, [rel data_3030]  {"Finished
processing flag!"}  
000026e2  4889c6             mov     rsi, rax  {data_3030, "Finished
processing flag!"}  
'''  
GOOD = 0x26e2+BASE  
```

Upon determing a ``solution_state``, we'd like to print the contents of the
flag, which is heeld in ``RDI``. So we'll need to get a pointer held in RDI,
then load the symbolic bit vector of that address, and subsequently cast that
to bytes.

```  
flag_ptr = solution_state.solver.eval(solution_state.regs.rdi)  
flag_bvs = solution_state.memory.load(flag_ptr, 256)  
flag_bytes = solution_state.solver.eval(flag_bvs, cast_to=bytes)  
```

Putting it all together, our solution follows:

```python

import angr  
import claripy  
import sys

BASE = 0x400000

'''  
00002399  int64_t constructFlag(int32_t arg1)  
'''  
START = 0X2399+BASE

'''  
0000270b  488d053a090000     lea     rax, [rel data_304c]  {"Wrong number!"}  
'''  
BAD = 0x270b+BASE

'''  
000026d3  4889c7             mov     rdi, rax {var_128}  
000026d6  e855faffff         call    std::__cxx11::basic_stri...>,
std::allocator<char> >::operator+=  
000026db  488d054e090000     lea     rax, [rel data_3030]  {"Finished
processing flag!"}  
000026e2  4889c6             mov     rsi, rax  {data_3030, "Finished
processing flag!"}  
'''  
GOOD = 0x26e2+BASE

def main(argv):  
   path_to_binary = argv[1]  
   project = angr.Project(path_to_binary, main_opts={"base_addr": BASE})

   start_address = START  
   initial_state = project.factory.blank_state(  
       addr=start_address,  
       add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,  
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}  
   )

   password = claripy.BVS('', 64)

   initial_state.regs.rdi = password

   simulation = project.factory.simgr(initial_state)  
   simulation.explore(find=GOOD, avoid=BAD)

   if simulation.found:

       solution_state = simulation.found[0]  
       solution = solution_state.solver.eval(password)  
       print("Correct Input: [ %s ]" % solution)

       flag_ptr = solution_state.solver.eval(solution_state.regs.rdi)  
       flag_bvs = solution_state.memory.load(flag_ptr, 256)  
       flag_bytes = solution_state.solver.eval(flag_bvs, cast_to=bytes)  
       print("Flag: [ %s ]" % flag_bytes.decode())

if __name__ == '__main__':  
   main(sys.argv)  
```

Running yields the flag:

```  
Correct Input: [ 289 ]  
Flag: [ byuctf{t35t_fl4g_pl3453_ign0r3} ]  
```

Original writeup (https://github.com/tj-oconnor/ctf-
writeups/tree/main/byuctf/basic_rev).