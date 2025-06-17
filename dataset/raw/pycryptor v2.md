# __Aero CTF 2019__  
## _pycryptor v2_

## Information  
**Category:** | **Points:** | **Writeup Author**  
--- | --- | ---  
Crypto | 500 | 1MiKHalyCH1

**Description:**

> Ещё одна реализация защиты наших чертежей. Опять на Python. На этот раз, нам
> сказали, что всё серьёзно.  
>  
> Another implementation of the protection of our drawings. Again in Python.
> This time, we were told that everything is serious.

## Solution  
This algo [implementation](pycryptor_v2.py) looks really hard. Let's figure it
out.

1) From `Crc` class we only need to know that calculated crc of block is 2
bytes long.

2) `Key` class is simple. It expands Your key to 32 bytes. But our key always
is `md5(input_key)` - 16 bytes - 32 hex symbols.

3) `Cipher` class encrypts file this way:  
- Splits the hole file into blocks 32 bytes long and exapands the last block with zero bytes.  
- Splits each block into 2 subblocks 16 bytes length.   
- For each block calculates 16 bytes long gamma:  
```py  
def getGamma(self, block):  
   gamma = ''

   block_crc = p_16(Crc()(block)) # 2 bytes

   for i in range(16):  
       val = ord(block_crc[i%2])  
       val >>= 1  
       val ^= ord(self.m_key.getKey()[i])  
       val &= 0xff

       gamma += chr(val)

   return gamma  
```  
Than it encrypts each subblock like this:  
```py  
enc_subblock = xor_bytes(subblcok, gamma)  
```  
- So the encrypted block looks like this (where `||` is concatenation of bytes):  
```  
enc_block = enc_subblock_1 || enc_subblock_2 || p_16(crc(block))  
```

### Key recovery  
From `getGamma` function we can understand that we really use just first 16
bytes of the key.

We can unfold gamma like this:  
```py  
bytes_crc = p_16(crc(subblock))  
for i in range(16):  
   enc[i] = subblock[i] ^ key[i] ^ (bytes_crc[i%2] >> 1)  
```  
Beacuse of XOR we can move `key[i]` to the left part of equation and `enc[i]`
to the right.

I assumed that the original image is in jpg format. So we know first 13 bytes
of it. We can brute last 3 bytes to recover key.

```py  
enc = read_file("test_image.enc")  
for tail in generate_tails():  
   jpg_header = ("ffd8ffe000104a464946000101" + tail).decode("hex")

   key = decrypt_key(jpg_header, enc[:16])  
   if all(x in hexdigits for x in key):  
       print "Key:", key  
       print "Tail:", tail  
       print  
```

And now we know that first 16 bytes of key are `"ed40f1e93ab22ea7"`.

Don't forget that last block padding are zeros. So we can recover key faster:  
```py  
with open("test_image.enc", "rb") as f:  
   block = f.read()[-18:-2]  
block.encode("hex")

pt = "\0" * 16 # jpg ends with FF D9. But we are lucky that the hole last
subblock contains in padding  
key = p_16(Crc()(pt))  
key = "".join(chr(ord(x) >> 1) for x in key)  
print xor_bytes(xor_bytes(block, key), pt)  
```

### Gamma calculation  
Now we know the key. We can precalculate all possible gammas because it
depends on `p_16(crc(subblock))` (which is 2 bytes long) and `key`.

And because of right shifting of crc bytes each gamma can be calculated from 4
different crc's.

```py  
def generate_gammas():  
   for x in range(0x80):  
       for y in range(0x80):  
           gamma = ''  
           block_crc = [x, y]

           for i in range(16):  
               val = block_crc[i % 2]  
               val ^= ord(KEY[i])  
               val &= 0xff  
               gamma += chr(val)

           _x = x << 1  
           _y = y << 1

           a = _x << 8 | _y  
           b = _x << 8 | (_y | 1)  
           c = (_x | 1) << 8 | _y  
           d = (_x | 1) << 8 | (_y | 1)  
           crcs = set(map(p_16, {a, b, c, d}))

           yield gamma, crcs  
```

### Full decoding  
Now we can recover all subblocks.  
Let's iterate through all gammas and XOR them with our encrypted subblock. If
`crc(decrypted_subblock)` is one of 4 gamma crc's then our
`decrypted_subblock` is one of possible candidates to be the real subblock.

At this step we have some variants for first and for second subblock of full
block. We can find the right one by calculating `crc(subblock_1 || sublock_2)`
and compare it with `crc(real_block)`.

```py  
def decrypt_block_part(block, gammas):  
   for gamma, gamma_crcs in gammas:  
       decrypt_block = xor_bytes(block, gamma)  
       real_block_crc = p_16(calculate_crc(decrypt_block))

       if real_block_crc in gamma_crcs:  
           yield decrypt_block

def decrypt_block(block, crc, gammas):  
   second_parts = list(decrypt_block_part(block[16:], gammas))

   for first_part in decrypt_block_part(block[:16], gammas):  
       for second_part in second_parts:  
           dec_block = first_part + second_part

           if CRC(dec_block) == crc:  
               return dec_block  
```

My [exploit](solver.py) works for me in about 2 hours. The task was done.

## P.S.  
I'd like to say thanks very much to [author](https://ctftime.org/team/66222)
for the very interesting hard task.

Original writeup (https://github.com/VoidHack/write-
ups/tree/master/Aero%20CTF%202019/crypto/pycryptor%20v2).