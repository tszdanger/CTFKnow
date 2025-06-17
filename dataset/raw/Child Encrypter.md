# Child Encrypter - 2020 Defenit CTF (rev/crypto, 598p, 11 solved)
## Introduction

Child Encrypter is a reverse and cryptography task.

A binary, and its output are provided.

The binary expects 3 arguments : the plaintext file, the output file, and a key
file.

Running the binary twice with the same arguments will provide a different
output. When running, it generates and prints a nonce.

## Reverse engineering

The binary is statically linked. libc functions are already visible.

The function at `000014e7` opens and reads a file.

The binary reads the plaintext file and the key file. It then generates 0x10
bytes from `/dev/urandom` which outputs cryptographically secure numbers. These
bytes are the nonce.

The function at `000014a1` prints a hexadecimal dump of its first argument.

The function at `00001586` writes data to a file.

The two functions at `00001304` and `00001408` deal with the encryption.

The first function has reference to an array of 256 bytes. The values of this
array are those found in the [AES S-Box](https://en.wikipedia.org/wiki/AES_s-box#Forward_S-box).

Using the test vector found on [Sam Trehnholme's Rijndael's key schedule
article](http://www.samiam.org/key-schedule.html) shows that this function
expands the key (second argument) to the AES state (first argument). The nonce
is copied after the state.

```c
struct state {
	unsigned char aes_state[0xB0];
	unsigned char nonce[0x10];
};
```

The function at `00001408` is not an AES encryption, but it calls the function
at `00000e24` which is an AES encryption.

`00001408` is :
```c
char block[0x10];
char *end = buffer + size;
int i = 0x10;

while(buffer != end) {
	if(0x10 == i) {
		memcpy(block, nonce, sizeof(block));
		block[0x0F] = rand() % 10;

		aes_encrypt(block, state);
		i = 0;
	}

	*buffer ^= block[i];

	i++;
	buffer++;
}
```

This binary encrypts the plaintext à la CTR mode, except there are 10 possible
counter. The output is large enough to guarantee that every possible nonces are
repeated a few times.

## Cryptography

The first thing to do is to classify each block of 16 bytes and group them
according to the key that was used to xor them.

A good way is to assume that the text is 7-bit ASCII (i.e. that the 8th bit of
every char is always clear). This leaks the 8th bit of every byte of the key
used for each block. This information can be used to fingerprint the key used
for a specific block.

When encrypting a block, the output is `out[i] = block[i] ^ key[rand() % 10]`.

If block `a` and `b` share the same key, then `out[a] ^ out[b] = block[a] ^
block[b]`. This means that any block for a specific key can be decrypted if at
least one block of this group is known.

The flag format is `Defenit{...}`. It is safe to assume that `Defenit{` can be
found in the clear text. This can help perform a known-plaintext attack of 8
bytes.

For every group, xor `block[i]` with `block[0]` (with `i` > 0) and xor it with
`Defenit{\0\0\0\0\0\0\0\0`. Repeat for each block, each group, and for each
rotation of the known plaintext until the xorred part appears readable.

```
74 7b 00 00 00 00 00 00 00 00 44 65 66 65 6e 69  t{........Defeni << key
7a 3a 28 28 61 2a 4f 1a 07 00 70 6f 70 75 6c 61  z:((a*O...popula << block
```

Once a block is identified, continue to guess bytes of the key by looking at the
plaintext.

```
2e 20 46 4c 41 47 20 69 73 20 44 65 66 65 6e 69  . FLAG is Defeni << key
20 61 6e 64 20 6d 6f 73 74 20 70 6f 70 75 6c 61   and most popula << block
```

Once a block has been fully recovered, every block in this group can be
decrypted as explained above.

```
20 61 6e 64 20 6d 6f 73 74 20 70 6f 70 75 6c 61   and most popula
2e 20 46 4c 41 47 20 69 73 20 44 65 66 65 6e 69  . FLAG is Defeni
73 20 6f 6e 65 20 6f 66 20 74 77 6f 20 62 6c 6f  s one of two blo
72 20 6d 6f 64 65 20 74 75 72 6e 73 20 61 20 62  r mode turns a b
6e 6f 77 6e 20 73 79 73 74 65 6d 61 74 69 63 20  nown systematic
6e 70 75 74 2e 20 41 6c 6f 6e 67 20 77 69 74 68  nput. Along with
69 6d 65 2c 20 61 6c 74 68 6f 75 67 68 20 61 6e  ime, although an
```

The full plaintext comes from [Wikipedia's article on Block cipher mode of
operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR))

The rest of the text can be retrieved in a similar way.

The flag is present at the end of the file. Having only a few keys is enough to
retrieve it.


**Flag**: `Defenit{AES_CTR_m0de_i5_g00d!}`

## Appendices

### sort.php

```php
#!/usr/bin/php
<?php
$blocks = str_split(file_get_contents("ciphertext.txt"), 0x10);

$offset = 0;
foreach($blocks as $b) {
	for($i = 0; $i < strlen($b); $i++)
		printf("%d", ord($b[$i]) >> 7);

	printf(" %s\n", bin2hex($b));
	$offset += 0x10;
}
```

### xor.php

```php
<?php
$blocks = [
	[...]
];

$key = " CBC, CTR mode i";
$key ^= hex2bin($blocks[3][0]);
echo $key;

$key = "ck cipher modes ";
$key ^= hex2bin($blocks[4][2]);
echo $key;

$key = ". FLAG is Defeni";
$key ^= hex2bin($blocks[5][1]);
echo $key;

$key = "unter\". The coun";
$key ^= hex2bin($blocks[7][5]);
echo $key;

$key = substr($key, 0, 0x10);
foreach($blocks as $i => $block2) {
	echo str_repeat(" ", 0x10);

	for($j = 0; $j < sizeof($block2); $j++) {
		$x  = $key;
		$x ^= hex2bin($block2[$j]);

		// uncomment for first part of the attack
		// $x ^= hex2bin($block2[0]);

		assert(0x10 === strlen($x));
		printf("%s", $x);
	}
}
```

### flag.php

```php
<?php
$blocks = str_split(file_get_contents("ciphertext.txt"), 0x10);

$keys = [
	0b0111000000001101 => "ab4a6669b16a9209182ff68d05c728a0",
	0b1001011110100110 => "8e2f26e642e5cabbaf1da843349ba65b",
	0b1010010000101110 => "9546f0717a832c426c29a66aa7dfd473",
	0b1100101000000101 => "e9b61c20ac52de1d245373586ff207d7",
	0b1101110101001100 => "8aae71a8bfc123eb07c07014f8923c69",
];

$offset = 0;
foreach($blocks as $b) {
	$index = 0;
	for($i = 0; $i < strlen($b); $i++) {
		$index <<= 1;
		$index  |= ord($b[$i]) >> 7;
	}

	$key = $keys[$index] ?? "054e93b81f572c31f2e3fc9ee995567e";
	$key = hex2bin($key);

	echo $b ^ $key;
}
```