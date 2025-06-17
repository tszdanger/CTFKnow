```python  
"""  
1. append the IV after cyphertext  
2. append 2 arbitrary blocks Cr after IV  
3. last block of plaintext  
	= enc(Cr) ^ Cr ^ enc(Cr) ^ prev_out_from_IV  
	= Cr ^ prev_out_from_IV  
4. Therefore we can use padding oracle attack to get prev_out_from_IV  
5. Then we get PIV = prev_out_from_IV ^ IV, which is plaintext for IV block  
6. Then we can construct new_IV(not IV block but true IV) to be IV ^ PIV,  
	in this way the prev come out of IV block will just be original IV,  
	this means we can actually have a decryption oracle from scratch  
7. Therefore, we can append cyphertext after IV block,  
	and they will turns out to be exactly same as decryption of original cyphertext  
8. This time we can remove blocks at the end of cyphertext.  
9. Then we can just use the same padding oracle attack to recover the flag  
"""

from pwn import *  
from base64 import b64encode, b64decode  
from Crypto.Util.strxor import strxor  
context(log_level='debug')

# sh = process(["python3", "problem.py"])  
sh = remote("cerberus.quals.seccon.jp", 8080)

sh.recvuntil(b"I teach you a spell! repeat after me!\n")  
ct = b64decode(sh.recvuntil(b'\n'))  
iv = ct[:16]  
ct = ct[16:]  
assert len(iv) == 16 and len(ct) == 64

def spell(iv, c):  
	assert len(iv) == 0x10 and len(c) % 0x10 == 0  
	sh.sendline(b64encode(iv + c))  
	ret = sh.recvuntil(b'\n')  
	assert not ret.startswith(b"Grrrrrrr!!!!")  
	ret = ret.startswith(b"Great :)") # return true for success decryption  
	sh.recvuntil(b"spell:")  
	return ret

sh.recvuntil(b"spell:")

def padding_oracle(ct_to_break, iv):  
	prev_out = [None] * 16  
	cr = [0x41] * 16  
	for i in range(0, 16):  
		for c in range(0, 0x100):  
			cr[15-i] = c  
			if spell(iv, ct_to_break + bytes(cr) * 2):  
				for j in range(0, i+1):  
					cr[15-j] ^= (i+1) ^ (i+2)  
				prev_out[15-i] = c ^ (i+1)  
				break  
	return prev_out

prev_out_from_IV = padding_oracle(ct + iv, iv)  
print(prev_out_from_IV)  
piv = strxor(bytes(prev_out_from_IV), iv)  
new_iv = strxor(iv, piv)

flag = []  
for i in range(0, 64, 16):  
	flag.append(strxor(bytes(padding_oracle(  
		ct + iv + ct[:len(ct)-i], new_iv)), ct[len(ct)-(i+16):len(ct)-i]))  
print(b''.join(flag[::-1]))  
```

Original writeup
(https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/cerberus.py).