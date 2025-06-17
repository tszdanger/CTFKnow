# VM log (re, 213p, 68 solved)

In the task we get a [simple vm
code](https://raw.githubusercontent.com/TFNS/writeups/master/2020-03-07-zer0ptsCTF/vmlog/vm.py)
and [execution
trace](https://raw.githubusercontent.com/TFNS/writeups/master/2020-03-07-zer0ptsCTF/vmlog/log.txt).

The VM looks like some brainfuck, but we didn't even try to understand it.  
Once we run it a couple of times it becomes clear that there is some internal
loop which reads a character from stdin and then dumps memory state.

This suggests we can brute-force the flag byte by byte, by checking after
which character the memory state matches the one in the trace log.  
We pretty much run the VM sending `a`, `b`, `c`... and check when the output
match.  
Then we send two characters, then three etc.

We modified the vm code a bit, to it reads input from predefined array and
yields the memory state, so we can easily intrument the run:

```python  
def vm_run(program, io):  
   io_idx = 0  
   reg = 0  
   mem = [0 for _ in range(10)]  
   p = 0  
   pc = 0  
   buf = ""  
   while pc < len(program):  
       op = program[pc]  
       if op == "+":  
           reg += 1  
       elif op == "-":  
           reg -= 1  
       elif op == "*":  
           reg *= mem[p]  
       elif op == "%":  
           reg = mem[p] % reg  
       elif op == "l":  
           reg = mem[p]  
       elif op == "s":  
           mem[p] = reg  
       elif op == ">":  
           p = (p + 1) % 10  
       elif op == "<":  
           p = (p - 1) % 10  
       elif op == ",":  
           a = io[io_idx]  
           io_idx += 1  
           if not a:  
               reg = 0  
           else:  
               reg += ord(a)  
       elif op == "p":  
           buf += str(reg)  
       elif op == "[":  
           if reg == 0:  
               cnt = 1  
               while cnt != 0:  
                   pc += 1  
                   if program[pc] == "[":  
                       cnt += 1  
                   if program[pc] == "]":  
                       cnt -= 1  
       elif op == "]":  
           if reg != 0:  
               cnt = 1  
               while cnt != 0:  
                   pc -= 1  
                   if program[pc] == "[":  
                       cnt -= 1  
                   if program[pc] == "]":  
                       cnt += 1  
       elif op == "M":  
           # print(mem)  
           yield mem  
       pc += 1  
   print(buf)

def main():  
   # cut from memory dumps  
   expected = [  
       4588277794174371330,  
       4557362566608270193,  
       4597225827500493308,  
       4399455111035409631,  
       3664679811648746944,  
       1822527803964528750,  
       2107290073593614393,  
       103104307719214561,  
       3773217954610171964,  
       1852072839260827083,  
       3465871536121230779,  
       223194874355517702,  
       1454204952931951837,  
       3030456872916287478,  
       426011771323652532,  
       1276028785627724173,  
       1962653697352394735,  
       1600956848133034570,  
       2045579747554458289,  
       4248193240456187641,  
       4478689482975263576,  
       1235692576284114044,  
       2579703272274331094,  
       1394874119223018380,  
       4275420194958799226,  
       2401030954359721279,  
       1313700932660640339,  
       2401701271938149070,  
       4217153612451355368,  
       2389747163516760623,  
       3483955087661197897,  
       4522489230881850831,  
   ]  
   program =
"M+s+>s>++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[s<<l>*~~>
l-]<<l-s>l*-s*-s*-s*-s*-s*-s>l*+++++s*-----s****s>>l+s[Ml-s<<l>,[<<*>>s<<<l>>>%~~>
l~~l+s <l]>l]<~~~~~~

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-03-07-zer0ptsCTF/vmlog/README.md).