"This weird binary" is x86_64 ELF. Strings of the binary show that there is
another ELF inside, this time for ARM, as well as the word "Installing..."

Stage 1: a look into what the host does.

main() occupies about 6 kilobytes which is quite large. Fortunately, most of
it can be ignored, and important things are:  
* there are several branches, but all converge to call to a function at `403E30` with `argv[1]`; also, this is the only usage of `argv`;  
* the first branch occurs if there is an environment variable `DEBUG` and md5 of its value equals `a35aa59d0666b443148dcbf17ddf16c9`, it does nothing besides that call;  
* the second branch occurs if there is a HID device with particular id and if a function at `4040F0` when called with 4, some zeroes and some pointers, returns 0x9000 and fills one of these pointers with "nanovm";  
* the last branch occurs if neither of two conditions above is met. It contains a long chain of OpenSSL calls and calls to `4040F0`, involving a reference to "Installing..." and a section inside the nested ELF.

https://crackstation.net reveals that `a35aa59d0666b443148dcbf17ddf16c9`
corresponds to the string `speculos`. This reveal is not required (after all,
it is always possible to just hijack control flow), but the string itself is a
hint.

The function at `4040F0` has two branches depending on whether the HID device
has been opened, either sending data through `hid_write`/`hid_read` or through
TCP connection to `127.0.0.1:9999`. The data start with byte 0xE0. Two of
arguments to the function form a pair pointer+length, the content is copied
starting with byte 5 and byte 4 stores the length. Since I have solved
Braincool before this task, this (plus the expected return value 0x9000) makes
obvious that the entire function sends APDU to the device. To summarize how
the function uses its arguments: a possible prototype is `unsigned short
send_apdu(hid_device* device, unsigned char ins, unsigned char p1, const
unsigned char* input, unsigned char inputlen, unsigned char** output_ptr,
unsigned short* output_len);`.

The function at `403E30` allocates 0x100000-byte buffer, copies 0x24FC bytes
starting from offset 0x1000 from a constant byte array at 0x419150 (seems that
is the VM that was promised in the title), runs two nested loops, the outer
loop runs through 8-byte blocks of `argv[1]`, sends APDU with command 7,
enters the inner loop that repeatedly sends APDU with command 8. After the
inner loop exits, the function saves some 8-byte block from the buffer. After
the outer loop exits, the function compares total processed length with 24 and
three saved blocks with some fixed values and prints "OK!" on match and
"Invalid password" otherwise.

The outer loop looks exactly like CBC-mode encrypting with zero IV, every
8-byte block is XORed with the output of the previous encryption. The inner
loop seems to encrypt one block with some code running on the device. Undoing
CBC mode requires a decryptor, not only an encryptor.

Stage 2: time to look into the device code in the nested ELF. One possible way
to find the code that processes APDU is to look for references to "nanovm",
since this is what the second branch in main() checks. The code does not
process anything except commands 4, 7 and 8, the handler of command 4 just
returns a fixed string, the handler of command 7 expects 72 bytes of data and
copies them into a global variable.

The handler for command 8 at 0xC0D00878 contains all the logic. It is a
typical VM dispatcher, big switch in a loop. Memory access is ultimately done
by the function at 0xC0D011FC; there is some cache in device memory; when an
address not in cache is requested, the function completes the APDU with the
address in output data and expects the host to start a new one with the
requested data. Same happens if an address needs to be evicted and has
modified data, with the address and modified data in output. So the inner loop
at the host handles all these memory accesses. Other than that, there isn't
much interesting going on, just a significant amount of code to analyze.

...pause to analyze the big switch...

The VM has 16 general-purpose 32-bit registers, and separate flags and
instruction pointer registers. I have only analyzed the opcodes that are used
by the only program we have, a dumper for those into pseudo-x86 instructions
looks like this:  
```  
import struct  
f = open('nanovm', 'rb')  
f.seek(0x19150)  
vm = f.read(0x24FC)  
pos = 0  
while pos < 0x231A:#len(vm):  
	print("%08X" % (pos+0x1000), end = ': ')  
	cmd, = struct.unpack_from('<H', vm, pos)  
	if (cmd & 0xC000) == 0x8000:  
		opcode2 = (cmd >> 12) & 3  
		op1 = (cmd >> 8) & 0xF  
		op2 = cmd & 0xFF  
		if opcode2 == 0:  
			print("add r%d, 0x%X" % (op1, op2))  
		elif opcode2 == 1:  
			print("sub r%d, 0x%X" % (op1, op2))  
		else:  
			print("unknown instruction: %04X" % cmd)  
			break  
	elif (cmd & 0xC000) == 0xC000:  
		cc = (cmd >> 10) & 0xF  
		delta = cmd & 0x3FF  
		if delta & 0x200:  
			delta -= 0x400  
		print("j%s %08X" % (["z","nz","l","g","b","a","ge","le","ae","be"][cc], 0x1000 + pos + delta * 2 + 2))  
	else:  
		opcode = cmd >> 8  
		op1 = (cmd >> 4) & 0xF  
		op2 = cmd & 0xF  
		if opcode == 1:  
			assert op2 == 0  
			print("mov r%d, 0x%X" % (op1, struct.unpack_from('<I', vm, pos+2)[0]))  
			pos += 4  
		elif opcode == 2:  
			print("mov r%d, r%d" % (op1, op2))  
		elif opcode == 4:  
			assert op1 == op2 == 0  
			print("ret")  
		elif opcode == 5:  
			print("add r%d, r%d" % (op1, op2))  
		elif opcode == 6:  
			print("mov [--r%d], r%d" % (op1, op2))  
		elif opcode == 7:  
			print("mov r%d, [r%d++]" % (op2, op1))  
		elif opcode == 0xA:  
			print("mov r%d, [r%d]" % (op1, op2))  
		elif opcode == 0xC:  
			offs, = struct.unpack_from('<h', vm, pos+2)  
			if offs >= 0:  
				print("mov r%d, [r%d + 0x%X]" % (op1, op2, offs))  
			else:  
				print("mov r%d, [r%d - 0x%X]" % (op1, op2, -offs))  
			pos += 2  
		elif opcode == 0xD:  
			offs, = struct.unpack_from('<h', vm, pos+2)  
			if offs >= 0:  
				print("mov [r%d + 0x%X], r%d" % (op1, offs, op2))  
			else:  
				print("mov [r%d - 0x%X], r%d" % (op1, -offs, op2))  
			pos += 2  
		elif opcode == 0xE:  
			# flags: 1=signed r1>r2, 2=signed r1<r2, 4=r1==r2, 8=unsigned r1>r2, 16=unsigned r1<r2  
			print("cmp r%d, r%d" % (op1, op2))  
		elif opcode == 0xF:  
			assert op1 == op2 == 0  
			print("nop")  
		elif opcode == 0x12:  
			print("movzx r%d, lobyte(r%d)" % (op1, op2))  
		elif opcode == 0x1A:  
			print("jmp %08X" % struct.unpack_from('<I', vm, pos+2)[0])  
			pos += 4  
		elif opcode == 0x1C:  
			print("mov r%d, [r%d]" % (op1, op2))  
		elif opcode == 0x1E:  
			print("mov [r%d], lobyte(r%d)" % (op1, op2))  
		elif opcode == 0x26:  
			print("and r%d, r%d" % (op1, op2))  
		elif opcode == 0x27:  
			print("shr r%d, r%d" % (op1, op2))  
		elif opcode == 0x28:  
			print("shl r%d, r%d" % (op1, op2))  
		elif opcode == 0x29:  
			print("sub r%d, r%d" % (op1, op2))  
		elif opcode == 0x2A:  
			print("neg r%d, r%d" % (op1, op2))  
		elif opcode == 0x2B:  
			print("or r%d, r%d" % (op1, op2))  
		elif opcode == 0x2E:  
			print("xor r%d, r%d" % (op1, op2))  
		elif opcode == 0x36:  
			offs, = struct.unpack_from('<h', vm, pos+2)  
			if offs >= 0:  
				print("movzx r%d, byte [r%d + 0x%X]" % (op1, op2, offs))  
			else:  
				print("movzx r%d, byte [r%d - 0x%X]" % (op1, op2, -offs))  
			pos += 2  
		else:  
			print("unknown instruction: %02X %02X" % (cmd >> 8, cmd & 0xFF))  
			break  
	pos += 2  
```  
It turns out that only a part of VM data contains opcodes, the rest contains
some tables. There is only one function in VM data, no signs of decryptor.

Stage 3: analyze instructions for VM. The dumped program has 2717
instructions, the amount certainly makes me want to find some shortcut :) But
a quick Internet search fails to identify constants or tables, so some digging
is required.  
```  
00001000: mov [--r1], r8  
00001002: mov [--r1], r9  
00001004: mov [--r1], r10  
00001006: mov [--r1], r11  
00001008: mov [--r1], r12  
0000100A: mov [--r1], r13  
0000100C: mov r14, 0x630  
00001012: sub r1, r14  
00001014: mov [r0 + 0xC], r2  
00001018: mov [r0 + 0x10], r3  
0000101C: mov r2, [r0 + 0xC]  
00001020: mov [r0 - 0x1C], r2  
00001024: mov r2, [r0 + 0x10]  
00001028: mov [r0 - 0x20], r2  
0000102C: xor r2, r2  
0000102E: mov [r0 - 0x24], r2  
00001032: mov r2, [r0 - 0x1C]  
00001036: mov [r0 - 0x28], r2  
0000103A: xor r2, r2  
0000103C: mov [r0 - 0x30], r2  
00001040: xor r2, r2  
00001042: mov [r0 - 0x2C], r2  
00001046: xor r2, r2  
00001048: mov [r0 - 0x34], r2  
```

...pause to analyze the first hundred instructions...

The code treats r0 as frame pointer and r1 as stack pointer. r2 and r3 are two
pointer arguments. The code copies r2 and r3 into local variables and sets
another local variable `[r0-0x24]` to zero. Then the code fetches 8 bytes from
r2 into a 64-bit integer (split as two sequential 32-bit local variables).
Then it starts some XORs, depending on whether `[r0-0x24]` is zero, which it
always is. Actually, there is more than one check of the same variable.

Why does the code compares always-zero variable to zero? What would happen if
it would become non-zero? It is used as a boolean; could it be a
decrypt/encrypt switch? Zero is hardcoded, there is no easy way to make the
variable nonzero. Still, continuing with an analysis of remaining 2617
instructions does not look easy either, so let's spend some time on a hard
way. Zero is created by the instruction at 0x102C; mov with immediate constant
takes more than two bytes, but if we replace this with nop, r2 will continue
to hold one of arguments, and it is nonzero, that is sufficient for our goals.
Also, the first block of the expected encryption result is 0x58BAD956F2638A97,
send it as the input.

```  
$ python3 speculos/speculos.py nanovm-nested.elf --display headless &  
$ export DEBUG=speculos  
$ gdb --args nanovm aaaaaaaaaaaaaaaaaaaaaaaa # 24-byte argument  
(gdb) starti  
0x00007ffff7fd3090 in _start () from /lib64/ld-linux-x86-64.so.2  
(gdb) display /3i $rip  
1: x/3i $rip  
=> 0x7ffff7fd3090 <_start>:     mov    %rsp,%rdi  
  0x7ffff7fd3093 <_start+3>:   call   0x7ffff7fd3de0 <_dl_start>  
  0x7ffff7fd3098 <_dl_start_user>:     mov    %rax,%r12  
(gdb) p/x *(unsigned short*)(0x419150+0x2C)  
$1 = 0x2e22 # yep, opcode for xor r2,r2; change it to nop = 0x0f00  
(gdb) set *(unsigned short*)(0x419150+0x2C) = 0x0f00  
(gdb) p/x *(unsigned short*)(0x419150+0x2C)  
$2 = 0xf00 # just to make sure  
(gdb) b *0x403f45  
Breakpoint 1 at 0x403f45 # the password block is written here  
(gdb) c  
Processing...

Breakpoint 1, 0x0000000000403f45 in ?? ()  
1: x/3i $rip  
=> 0x403f45:    mov    %rax,0x20(%rbx)  
  0x403f49:    lea    0x54(%rsp),%rax  
  0x403f4e:    xorps  %xmm0,%xmm0  
(gdb) set $rax = 0x58BAD956F2638A97  
(gdb) b *0x403f29 # the encrypted block is saved here  
Breakpoint 2 at 0x403f29  
(gdb) c  
```  
(several minutes and a lot of speculos output later)  
```  
Breakpoint 2, 0x0000000000403f29 in ?? ()  
1: x/3i $rip  
=> 0x403f29:    mov    %rax,(%rcx,%r12,1)  
  0x403f2d:    add    $0x8,%r12  
  0x403f31:    cmp    0x38(%rsp),%r12  
(gdb) p/x $rax  
$3 = 0x77306c737b465443  
(gdb) p (char*)($rbx+0x40)  
$4 = 0x7ffff78f4040 "CTF{sl0w"  
```  
It worked! No need to analyze further. Just repeat two more times with other
encrypted blocks and don't forget to undo CBC mode to get the flag
`CTF{sl0w_vm_is_sl0w}`.