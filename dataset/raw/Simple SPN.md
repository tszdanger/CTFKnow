# Simple SPN (crypto, 766p, 6 solved)

In the task we get access to a service running a custom [substitution-
permutation network
encryption](https://raw.githubusercontent.com/TFNS/writeups/master/2020-06-05-DefenitCTF/spn/SPN.py).  
We can send as many payloads we want to the server and the server will return
encrypted ciphertext.  
Our goal is to recover the last XOR key applied to the ciphertext.

## Analysis

We have SPN cipher with 8-bytes blocks and 4 rounds and only ECB mode.  
We don't care about the mode, because we will work only with single blocks.

The encryption is:

```python  
ba_block = self.bytes_to_bitarray(block, self.BLOCK_SIZE*8)

for _round in range(self.ROUNDS-1):  
   ba_block = self.keyXor(ba_block, self.keys[_round])  
   ba_block = self.substitute(ba_block)  
   ba_block = self.permutation(ba_block)  
#last round is not permuted  
ba_block = self.keyXor(ba_block, self.keys[self.ROUNDS-1])  
ba_block = self.substitute(ba_block)

ba_block = self.keyXor(ba_block, last_XOR_key)  
out += '%016x' % b2l(self.bitarray_to_bytes(ba_block, 8))  
```

Substitution is just a static sbox and so is the permutation.  
Round keys are some randoms generated from static seed we don't know.

### Square property

General approach would be to examine how input bits are moved around through
the rounds, however we made an educated guess that low rounds number and setup
of the task might hint at existence of square property there.

Let's modify the encryption function a bit, and remove:  
```python  
ba_block = self.substitute(ba_block)  
ba_block = self.keyXor(ba_block, last_XOR_key)  
```

Now if we run our sanity check:

```python  
def pad(pt, pad_char):  
   missing = 8 - len(pt)  
   return pad_char * missing + pt

def sanity2():  
   spn = SPN()  
   ct = [spn.enc3(pad("\0", "A").encode("hex"))]  
   for i in range(1, 256):  
       ct.append(spn.enc_modified(pad(long_to_bytes(i), "A").encode("hex")))  
   ct = [[ord(c) for c in x.decode("hex")] for x in ct]  
   for pos in range(8):  
       res = 0  
       for c in range(256):  
           res ^= ct[c][pos]  
       assert res == 0  
```

This assertion holds!

The idea is that if we encrypt 256 plaintexts, which all differ only on a
single byte, then given byte position in the output ciphertexsts will loop
over every possible value.

## Solution

Once we established we have the square property, it becomes pretty clear what
we can do here:

1. Generate set of ciphertexsts prepared as mentioned above  
2. Select some byte position `k`  
3. Test every possible value of `k-th` byte in `last_XOR_key`  
4. deXOR the `k-th` byte in every ciphertext we have with the guessed xor byte  
5. Invert the `ba_block = self.substitute(ba_block)`  
6. XOR all bytes we got and check if the sum is 0, if it is, then we might have guessed the `last_XOR_key` byte correctly, and we save this value as candidate

You can think of this as basically trying to invert:  
```python  
ba_block = self.substitute(ba_block)  
ba_block = self.keyXor(ba_block, last_XOR_key)  
```

so that we arrive at the moment where the square property should hold.  
We can do that because the property holds for each byte, so we don't need to
guess whole `last_XOR_key`, we can work on single byte at a time:

```python  
invsbox = []  
for i in range(256):  
   invsbox.append(sbox.index(i))

def integrate(index, ciphertexts):  
   potential = set()  
   for candidateByte in range(256):  
       sum = 0  
       for ct in ciphertexts:  
           t = ct[index] ^ candidateByte # invert xor  
           s = invsbox[t] # invert sbox  
           sum ^= s  
       if sum == 0:  
           potential.add(candidateByte)  
   print("Potential bytes on position %d are %s" % (index, str(potential)))  
   return potential

def integral(ciphertexts):  
   candidates = []  
   for i in range(8):  
       candidates.append(integrate(i, ciphertexts))  
   print('candidates', candidates)  
   return candidates  
```

Now there is one last issue - there may be multiple candidates for a single
byte!  
We have no way of discriminating which candidates are valid and which are not.

Fortunately we are not limited to a single dataset.  
We can create different plaintext sets (eg. padding with different char) and
generate candidates for each set.  
The trick is that each of those candidate sets has to contain the `real` value
we're looking for, but the rest are just random false-positives.  
We can, therefore, gets a few candiate sets, and the intersect them.  
If we have enough inputs, we should be able to get back a single value present
in all sets.

We do that with:

```python  
def worker(pad_char):  
   port = 5959  
   host = "simple-spn.ctf.defenit.kr"  
   s = nc(host, port)  
   x = receive_until(s, "\n")  
   x = receive_until(s, "\n")  
   ct = []  
   payloads = [pad("\0", pad_char).encode("hex")]  
   for i in range(1, 256):  
       payloads.append(pad(long_to_bytes(i), pad_char).encode("hex"))  
   for payload in payloads:  
       send(s, payload)  
       c = receive_until(s, "\n")  
       ct.append(re.findall("ciphertext: (.*)\n", c)[0])  
       x = receive_until(s, "\n")  
   print('cts', ct)  
   ct = [[ord(c) for c in x.decode("hex")] for x in ct]  
   candidates = integral(ct)  
   return candidates

def main():  
   candidates = [set(range(256)) for _ in range(8)]  
   data = ['A', 'B', 'C', 'D', 'E', 'F']  
   results = brute(worker, data_list=data, processes=6)  
   print('results', results)  
   for dataset in results:  
       for byte in range(8):  
           candidates[byte] = candidates[byte].intersection(dataset[byte])  
   print(candidates)  
   print("".join([chr(list(x)[0]) for x in candidates]).encode("hex"))  
```

We run 6 processess in paralell, each with different padding byte, and then
combine candiates and we get back: `dc0ea570d1ffe120` so the flag is
`Defenit{dc0ea570d1ffe120}`

Complete solver
[here](https://raw.githubusercontent.com/TFNS/writeups/master/2020-06-05-DefenitCTF/spn/solver.py)

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-06-05-DefenitCTF/spn/README.md).