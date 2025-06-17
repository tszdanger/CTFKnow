originally posted @ http://klatz.co/ctf-blog/asisctf-silkroad

I spent a disproportionately large amount of time solving the first portion  
of this binary, because I was having a lot of fun learning things via it. I  
did not solve anything past the first function.

We are given a pwn binary that asks for a magic value and runs through six  
obfuscated constraints. It reads from stdin, stores the ASCII, `strtol`s  
(str to long int) it, and `strlen`s it.

I ultimately made a Python script that finds the value efficiently, and a C  
harness that instruments a function from the binary and iterates through  
all possible inputs.

Interestingly, I tried a case that the designer may not have considered:  
leading 0s on the input change the `strlen` result in such a way that it's  
possible to cause the remote binary to run into a divide by 0 exception.

Here's [my code in a GitHub gist][2] for easy viewing. All of the  
files I created / used are [here][1].

---

### Process

After a little reversing (Ghidra + Binja), I noticed there's 6 constraints
(roughly  
six basic blocks. I modeled these in Python, first sampling randomly, then  
iterating from 0 to 2^32-1. I split this into four workers, and it takes  
around 80m.

I poked around at Z3 and angr to see if I could model the constraints with  
them, but my hello-world-y attempts at both weren't fruitful. Z3 ran  
forever, and angr didn't return anything. Also, parens in lisp suck. See  
those attemps in [the gist][2].

Spending some more time with the Python, I rewrote the loop to cut down  
the runtime by a factor of about 100x (4 workers on 4 cores in 80m to about  
2m). I simplified some of the constraints into the loop, avoiding a lot of  
iterations. I had bugs, so the script didn't return any valid values.

At this point I was really tired and really confused by indexing, and I had  
the idea of trying to instrument just the one C function. I used Binja to  
patch it — looping on a failed check, printing the string on all passed.

I used r2 to extract all of the contiguous assembly and write it to a file,  
`bin`. I `mmap`d the file into memory, set that page as executable, and  
wrote some inline ASM to `jmp` to it.

This revealed a problem — none of the library functions would work, since  
the offsets were incorrect, and this mmapped blob didn't have any  
compile-time information. However, the calls all tried passing control flow  
to somewhere slightly above the code blob. So, I padded the blob with nops,  
and then wrote jmps of the form  
```asm  
mov rax, 0x40xxxx  
jmp rax  
```  
as a replacement PLT. I had to manually patch these every time the offsets  
changed in the harness binary (`iterate`). I did this a lot. It wasn't fun.  
There's probably a good way to do this with a Python library to read the  
ELF and ask for the address of those functions, then construct & assemble  
the `jmp` instruction and write it to an offset in `bin`.

I had a really weird issues where I'd `jmp` to the loaded code, hit `ni`,  
and gdb would run until a segfault. I asked a few friends and they helped  
me realize that I was running into some difference between `ni` and `si` —  
doing `ni` would continue out of the function until segfaulting later,  
unless I stepped in a few instructions first. I'm not sure what the reason  
is, but my guess is that GDB has some heuristic for determining if you're  
in a function or not, and that landing on the first instruction after a  
call in my weird mmappy situation didn't set up those heuristics correctly.  
If you have any idea why, @ me on twitter or something.

After a lot of tedious debugging, I ended up with a statically compiled  
binary `iterate` that pretty quickly (<1m) finds the value. I used this to  
find the bugs in my Python code, which were due to not really understanding  
how the binary chopped up the int representation of the input. I rewrote  
the Python code to make it work.

I had fun! I learned a lot. Like, I'm going to reach for DynamoRIO /  
PINTools / QEMU process emulation next time.

[1]: https://www.dropbox.com/sh/gi8v4am90va5ra1/AABL8cAj2ClPAyi58QJG5vSfa?dl=0  
[2]: https://gist.github.com/ianklatzco/5b1e6589371ff29852f0737749139fcc  

Original writeup (http://klatz.co/ctf-blog/asisctf-silkroad).