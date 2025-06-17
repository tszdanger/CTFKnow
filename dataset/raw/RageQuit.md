# RageQuit - BalCCon2k20 CTF (rev, 497p, 1 solved)  
## Introduction

RageQuit is a reversing task.

An archive containing a Linux ELF file, its output and an encrypted file is  
provided.

The output contains references to `xchacha20-poly1305` :  
> send the payment reference below to poly1305@cnc-admin.com

> able to afford some x-Cha-Cha-Cha dancing lessons

## Reverse engineering  
### Initialization  
The main function first does a weird dance to call a function while ensuring  
there is only one argument :  
```c  
fptr[argc](0, buffer);  
```

If argc is not 1, the call will crash.

The function does pretty much nothing if the first argument is 0 : it only  
prints a obfuscated message.

Then, the program prepares a regular expression : `^.+\.flag$`. It is used to  
ensure only files ending with `.flag` are encrypted.

The program calls a function that calls 10 other functions... fortunately the  
first one uses assertions and gives away its name : `sodium_crit_enter`.

By looking for cross-references to `sodium_crit_enter` in the source code of  
Libsodium, it becomes clear that this first function is in fact `sodium_init`.

The next function cannot be easily identified (it is  
`crypto_aead_xchacha20poly1305_ietf_keygen`). But the one after is a POSIX  
function : `ftw` (file tree walk). It receives a callback that is called for  
every file in the current directory recursively.

The callback ensures the filename matches the regex and encrypt the file if it  
does.

### Encryption routine

The encryption can be roughly decompiled to :  
```c  
FILE *fp_in  = fopen(filename, "rb+");  
FILE *fp_out = fopen(outname, "wb");  
FILE *fp_rng = fopen("/dev/urandom", "r");  
char buffer[0x1000]

unlink(filename);

while(1) {  
	size = fread(buffer, 1, sizeof(buffer), fp_in);  
	if(feof(fp_in))  
		break;

	/* encrypt and write the output */  
	encrypt(buffer);  
	fwrite(buffer, size, 1, fp_out);

	/* rewind and overwrite with garbage */  
	fseek(fp_in, -size, SEEK_CUR);  
	fread(buffer, size, 1, fp_rng);  
	fwrite(buffer, size, 1, fp_in);

}

/* encrypt and write the output */  
encrypt(buffer);  
fwrite(buffer, size, 1, fp_out);

/* rewind and overwrite with garbage */  
fseek(fp_in, -size, SEEK_CUR);  
fread(buffer, size, 1, fp_rng);  
fwrite(buffer, size, 1, fp_in);  
```

By using a mix of Libsodium source code, documentation and assumption, it is  
possible to identify the exact name of the encryption function.

The ransomware encrypts files using  
`crypto_secretstream_xchacha20poly1305_push`, just like in the  
[Encrypted streams and file encryption](https://doc.libsodium.org/secret-
key_cryptography/secretstream)  
chapter.

It is therefore safe to assume that the key is generated in the `main`
function  
by the `crypto_aead_xchacha20poly1305_ietf_keygen` function and is stored at  
`0x000387c0`.

The nonce (header) is generated randomly and is stored in the first 0x18 bytes  
of the encrypted file :  
```c  
crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);  
fwrite(header, 0x18, 1, fp_oput);  
```

### Reference generation

Once every files matching the regular expression have been encrypted, the  
program calls once again the weird `fptr` function with different arguments :  
`fptr[argc](1, key = buffer)`.

When the first argument is 1, the function does something entirely different.

It first starts by copying the key in a local buffer, and shift every byte
left  
according to a lookup-table :  
```c  
int keyLocal[sizeof(key)];  
int shifts[8] = {...};

for(i = 0; i < sizeof(key); i++) {  
	keyLocal[i] = key[i];  
	keyLocal[i] = keyLocal[i] << (shifts[j % 8] & 0x1f);  
}  
```

It then calls 3 functions in this order, and with these arguments :  
```c  
f_2640(keyLocal, 4);  
f_3d60(keyLocal, 1);

f_2640(keyLocal, 2);  
f_3d60(keyLocal, 6);

f_2640(keyLocal, 5);  
f_3d60(keyLocal, 4);

f_4450(keyLocal);  
```

`f_2640` calls differents functions through trampolines. All of these
functions  
take two arguments : an `int*` (always `keyLocal` and an index. This index  
goes from `0x00` to `0x10`.

All these functions add the `arg2`th number of a look-up table to `arg1[idx]`.  
`idx` increases by one for each function.

The `f_2640` function effectively adds a look-up table to the key.

`f_3d60` is much more straightforward because it does not use trampolines and  
new functions :  
```c  
localKey[0] = localKey[0] * LUT_mul[start + 0 & 0xf];  
localKey[1] = localKey[1] * LUT_mul[start + 1 & 0xf];  
localKey[2] = localKey[2] * LUT_mul[start + 2 & 0xf];  
localKey[3] = localKey[3] * LUT_mul[start + 3 & 0xf];  
// ...  
```

This function does the same action but multiplies instead of adding. The look-
up  
table is different.

`f_4450` is also straightforward : it xors `localKey[0x01..0x1F]` with  
`localKey[0x00..0x1E]`

The full algorithm has been reimplemented in the `check.php` script present in  
the appendices of this writeup.

### Undoing the transformation

The last xor operation can be reverted.

Unfortunately the multiplication operation cannot be reverted because 8 is a  
possible factor because there is no multiplicative inverse of 8 mod 2^32.

The multiplication, addition and shift operations only work on a specific
index.  
This means that once the xor operation has been reverted, it is possible to  
bruteforce each byte of the key (256 possibilities) independently.

The code to recover the key is in `pwn.php`

The encryption key is `AF 51 23 A0 B0 14 C3 CC CF D4 8B 47 6D E9 08 98 54 DB
C8  
8C 49 1E 54 44 35 C4 D5 3B FA 8E FD 3A`

Once the key is recovered, it is possible to decrypt the `ragequit.flag.rgq`  
file. This file contains the flag.

**Flag**: `BCTF{s0m3t1m2s_r4g3_1s_4ll_y0u_n33d}`

## Appendices  
### check.php  
```php  
0; $i--)  
	$key[$i] ^= $key[$i - 1];

// bf  
for($i = 0; $i < 0x100; $i++) {  
	$check = [  
		$i, $i, $i, $i, $i, $i, $i, $i,  
		$i, $i, $i, $i, $i, $i, $i, $i,  
		$i, $i, $i, $i, $i, $i, $i, $i,  
		$i, $i, $i, $i, $i, $i, $i, $i,  
	];

	$check = shl($check);  
	$check = add($check, 4);  
	$check = mul($check, 1);  
	$check = add($check, 2);  
	$check = mul($check, 6);  
	$check = add($check, 5);  
	$check = mul($check, 4);

	for($j = 0; $j < sizeof($check); $j++)  
		if($key[$j] === $check[$j])  
			$result[$j] = $i;  
}

for($i = 0; $i < sizeof($result); $i++)  
	printf("%02X", $result[$i]);

printf("\n");  
```

### crypto.php  
```  

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-09-25-BalCCon/ragequit/README.md).