### Problem  
We are given the following encryption code:

```  
from Crypto.Util.number import getRandomInteger  
from secret import flag

class LFSR:  
	def __init__(self, size, salt, invert):  
		assert(size == 17 or size == 25)  
		self.size = size  
		self.register = ((salt >> 3) << 4) + 8 + (salt & 0x7)  
		self.taps = [0, 14]  
		if size == 25:  
			self.taps += [3, 4]  
		self.invert = 1 if invert == True else 0  
	def clock(self):  
		output = reduce(lambda x, y: x ^ y, [(self.register >> i) & 1 for i in self.taps])  
		self.register = (self.register >> 1) + (output << (self.size - 1))

		output ^= self.invert  
		return output

def encryptData(key, data):  
	assert(key < 2**40)  
	data = data.decode("hex")

	lfsr17 = LFSR(17, key >> 24, True)  
	lfsr25 = LFSR(25, key & 0xffffff, False)

	keystream = 0  
	for i in range(len(data) * 8):  
		keystream <<= 1  
		keystream |= lfsr17.clock() ^ lfsr25.clock()

	pt = int(data.encode("hex"), 16)  
	ct = ("%x"%(pt ^ keystream)).rjust(len(data) * 2, "0")

	return ct

def decryptData(key, ct):  
	return encryptData(key, ct)

disc_data = "The flag is: %s"%flag

keylen = 5  
key = getRandomInteger(keylen * 8)

ct = encryptData(key, disc_data.encode("hex"))  
assert(decryptData(key, ct).decode("hex") == disc_data)

with open("enc_data.txt", "w") as f:  
	f.write(ct)  
```  
And ciphertext:  
```  
1b4eb59dce68c7d5173871ff3211a35bc8d089147c0c4c0f7cdf1b9489d4a640ee173557778095d84d0cd344e213100f2923e8ea96  
```  
#### Brief explanation of the code:  
- Key is generated as a random integer (up to 40 bits)  
- First 16 bits is used as salt for a 17-bit LFSR (bit 1 is added at position 4)  
- Last 24 bits is used as salt for a 25-bit LFSR (bit 1 is added at position 4)  
- For each round of clocking, 2 bits from specific positions of LFSR are xored. The output is then prepended to the LFSR register (as MSB) and LSB of register is discarded  
- Encryption is simply done by xoring the output of LFSR with plaintext at bitwise level.  
### Solution  
We know that the plaintext begins with "The flag is: " (104 bits), so we can
do a known plaintext attack (KPA) by bruteforcing the 16-bit salt:  
- From the 16-bit salt, we generate the output of lfsr17  
- Xoring the first 25 bits of the output with the first 25 bits of the plaintext and ciphertext gives us the first 25-bit output of lfsr25  
- The first 25-bit output of lfsr25 is also the bits of the register after 25 rounds of clocking. So we can use this to generate the rest of the output and continue the decryption. If the result matches the rest of the known plaintext then the 16-bit salt is correct and we use this to decrypt the rest of the ciphertext.  
(It might be possible to bruteforce less bits but this is already enough to
solve the challenge)

Solver code:  
```  
from Crypto.Util.number import getRandomInteger, long_to_bytes  
from functools import reduce

enc =
'1b4eb59dce68c7d5173871ff3211a35bc8d089147c0c4c0f7cdf1b9489d4a640ee173557778095d84d0cd344e213100f2923e8ea96'  
enc = bin(int(enc, 16))[2:].zfill(len(enc) * 4)

kpt = 'The flag is: '  
kpt = ''.join(bin(ord(x))[2:].zfill(8) for x in kpt)

class LFSR:  
	def __init__(self, size, salt, invert, register = 0):  
		assert(size == 17 or size == 25)  
		self.size = size  
		if register != 0:  
			self.register = register  
		else:  
			self.register = ((salt >> 3) << 4) + 8 + (salt & 0x7)  
		self.taps = [0, 14]  
		if size == 25:  
			self.taps += [3, 4]  
		self.invert = 1 if invert == True else 0  
	def clock(self):  
		output = reduce(lambda x, y: x ^ y, [(self.register >> i) & 1 for i in self.taps])  
		self.register = (self.register >> 1) + (output << (self.size - 1))

		output ^= self.invert  
		return output

LEN1 = 17  
LEN2 = 25

def find_reg2(lfsr17):  
       reg2 = ''  
       for i in range(LEN2):  
               reg2 += str(lfsr17.clock() ^ int(kpt[i]) ^ int(enc[i]))  
       return int(reg2[::-1], 2)

def brute(salt1):  
       lfsr17 = LFSR(17, salt1, True)  
       reg2 = find_reg2(lfsr17)  
       lfsr25 = LFSR(25, 0, False, reg2)  
       pt = kpt[:25]  
       for i in range(LEN2, len(enc)):  
               x = lfsr17.clock() ^ lfsr25.clock() ^ int(enc[i])  
               if i < len(kpt) and x != int(kpt[i]):  
                       return False, None  
               pt += str(x)  
       return True, pt

for salt1 in range(1 << 16):  
       found, pt = brute(salt1)  
       if found:  
               print('[+] Found: ', pt)  
               print(long_to_bytes(int(pt, 2)))  
```  
Output:  
```  
[+] Found:
0101010001101000011001010010000001100110011011000110000101100111001000000110100101110011001110100010000001010011010000110101010001000110011110110111001000110011011011010011001101101101011000100011001101110010010111110011011101101000001101000011011101011111010011000100011001010011010100100101111100110001001101010101111101110010001100110111011100110001011011100110010000110011011100100011010001100010001100010011001101111101  
b'The flag is: SCTF{r3m3mb3r_7h47_LFSR_15_r3w1nd3r4b13}'  
```  

Original writeup (https://github.com/CTF-STeam/ctf-
writeups/tree/master/2020/Hackers%20Playground/Decrypt%20Vulnerable%20Data%20%231).