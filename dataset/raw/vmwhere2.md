## Challenge Description

Usage: `./chal program`

Author: richard

## Intuition

As the name suggests, this is a rather classic VM challenge. We're given the  
cpu code and a program and have to reverse it. Opening `chal` in ghidra leads  
to the implementation of each instruction, which enables us to write a  
disassembler for the program. Most of the opcodes have pretty easy  
implementations, aside from a few more interesting ones:

* opcode `0x10` -> reverses the stack in a range  
* opcode `0x11` -> pops the top of the stack and pushes 8 bits corresponding to the popped value base 2 representation  
* opcode 0x12 -> pops 8 values of the stack (expected bits), interprets them as the bits of a base 2 number, and pushed the corresponding number on the stack

## Solution

Looking at the disassembled code we pieced everything together. The program
takes  
the flag as input. For each ASCII value imputed, it constructs a base-3-like
number  
from the base-2 interpretation of the value. The result of the transformation
is  
compared to a hard-coded value at the end, by xoring the two values together
and expecting 0.

Formally, if the input number was $$x_{(2)}=100101 = 37_{(10)}$$ it would be
transformed to $$y_{(3)} = 1001010_{(3)} = 759_{(10)} = 247_{(10)}\text{ (mod
256)}$$

Notice that $y_{(3)}$ has the looks the same as $x_{(2)}$ **shifted to the
left by one**.

To get the flag, we can just iterate over the printable characters and compute
a reverse dictionary with the corresponding base-3-like transformation. Then
just iterate over the hard-coded values and print the value in the dictionary,
indexed by the with each value as a key.

## Snippet from the decompilation

```  
2976: push 0 (prog);  
2978: push 10 (prog);  
2980: push 33 (prog); !  
2982: push 116 (prog); t  
2984: push 99 (prog); c  
2986: push 101 (prog); e  
2988: push 114 (prog); r  
2990: push 114 (prog); r  
2992: push 111 (prog); o  
2994: push 67 (prog); C  
2996: cc = 0 || 4; if stack[-1] == 0 then jump to 3003  
2999: print(pop())  
3000: cc = 255 || 249; jump to 2996  
```

The above snippets will be executed if we input the correct flag and will
print _"Correct"_.

You can check the full code of the disassembler
[here](https://gist.github.com/Stefan-Radu/d6ddaa06e3fdc25ed2c779743f167778)

### Flag

`uiuctf{b4s3_3_1s_b4s3d_just_l1k3_vm_r3v3rs1ng}`

#### Note

The easier challenge `vmware1` can be solved using the exact same disassembler  
and the same techniques. However, looking at it's code we notice that the code
breaks after each incorrect input character. This means we can use a timing-
attack style attack using `valgrind --tool=callgrind` and choosing at each
point the letter that leads to the most `calls` reported in `callgrind`. Find
such a script [here](https://github.com/dothidden/tools/blob/main/rev/call-
count-attack/highest_value.sh).

Original writeup (https://dothidden.xyz/uiuctf_2023/vmware2/).