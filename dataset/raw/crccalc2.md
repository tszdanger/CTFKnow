For this challenge, and also crccalc1, we are given the output from
[crccalc](https://crccalc.com/) with 9 32-bit CRCs given for some unknown
input. From the amount of dots in the input, and the filename being
"crccalc-24.png", it's fair to assume that the input this time is 24
characters. I solved this challenge in the exact same way as crccalc1, only
changing the target CRCs and expected length.

From Balsn CTF 2019, there was a challenge that very much resembled this
challenge. There, CRC calculation was a tiny step on the way to the final
decryption code, and included CRCs of multiple bit lengths. The challenge is
called [collision](https://ctftime.org/task/9374), and I heavily borrowed code
from [team hxp's solution](https://hxp.io/blog/61/Balsn-CTF-2019-writeups/)
for this one.

The main takeaway, is that CRCs are not cryptographically secure, but actually
affine functions over GF(2). Generally speaking, CRCs are just polynomial
division, but in order to gain certain properties, they have mutated slightly
from that description. This makes it very hard to solve them with a CRT-like
approach, since the input might be XORed with something before and/or after
the division - and sometimes even done in reverse (as that's faster in some
scenarios, especially in embedded).

The most important property, is that `CRC(x⊕y) ⊕ CRC(0) = CRC(x) ⊕ CRC(y)`. We
can use this to set up a system of equations in matrix form, where we
concatenate all the CRCs into a single function. Instead of repeating more of
what's already been said, go check out the previous write-up by hxp, linked
above.

Sage code for solving below. To solve crccalc1, just replace the `l` variable
and the `target` dict to match that challenge. The code finds two solutions,
where one is just gibberish, and the other is the flag:
`ALLES{cycl1c_r3dund4ncy}` The `_crc_definitions_table` is lifted from the
module `crcmod`, which can be found on PyPi.

```python  
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Length of the target input and its CRCs  
l = 24  
target = {\  
   'crc-32':       0xB60C1196,  
   'crc-32-bzip2': 0x540FB6E5,  
   'crc-32c':      0x0472FC19,  
   'crc-32d':      0xCD3BFFA5,  
   'crc-32-mpeg':  0xABF0491A,  
   'posix':        0xAFA3CADF,  
   'crc-32q':      0xC4B409AD,  
   'jamcrc':       0x49F3EE69,  
   'xfer':         0x0B91E517,  
}

REVERSE = True  
NON_REVERSE = False

_crc_definitions_table = [  
   [   'crc-32',           'Crc32',            0x104C11DB7,    REVERSE,
0x00000000,     0xFFFFFFFF, 0xCBF43926, ],  
   [   'crc-32-bzip2',     'Crc32Bzip2',       0x104C11DB7,    NON_REVERSE,
0x00000000,     0xFFFFFFFF, 0xFC891918, ],  
   [   'crc-32c',          'Crc32C',           0x11EDC6F41,    REVERSE,
0x00000000,     0xFFFFFFFF, 0xE3069283, ],  
   [   'crc-32d',          'Crc32D',           0x1A833982B,    REVERSE,
0x00000000,     0xFFFFFFFF, 0x87315576, ],  
   [   'crc-32-mpeg',      'Crc32Mpeg',        0x104C11DB7,    NON_REVERSE,
0xFFFFFFFF,     0x00000000, 0x0376E6E7, ],  
   [   'posix',            'CrcPosix',         0x104C11DB7,    NON_REVERSE,
0xFFFFFFFF,     0xFFFFFFFF, 0x765E7680, ],  
   [   'crc-32q',          'Crc32Q',           0x1814141AB,    NON_REVERSE,
0x00000000,     0x00000000, 0x3010BF7F, ],  
   [   'jamcrc',           'CrcJamCrc',        0x104C11DB7,    REVERSE,
0xFFFFFFFF,     0x00000000, 0x340BC6D9, ],  
   [   'xfer',             'CrcXfer',          0x1000000AF,    NON_REVERSE,
0x00000000,     0x00000000, 0xBD0BE338, ],  
]

R.<x> = GF(2)[]

num2poly = lambda n: sum(((n >> i) & 1) * x**i for i in
range(int(n).bit_length()+5))  
poly2num = lambda f: f.change_ring(ZZ)(2)  
num2vec  = lambda l,n: vector(GF(2), [(n >> i) & 1 for i in range(l)])

crcs = dict()  
for name,_,poly,rev,ixor,oxor,chk in _crc_definitions_table:  
   crcs[name] = {  
           'poly': num2poly(poly),  
           'bits': int(num2poly(poly).degree()),  
           'rev':  rev,  
           'ixor': ZZ(ixor),  
           'oxor': ZZ(oxor),  
           'chk':  chk,  
       }

del name,poly,rev,ixor,oxor,chk

def mycrc(name, bs):  
   data = crcs[name]  
   poly, bits, rev, ixor, oxor = data['poly'], data['bits'], data['rev'],
data['ixor'], data['oxor']  
   if rev:  
       #bs = ''.join(chr(int('{:08b}'.format(ord(x))[::-1],2)) for x in bs)  
       bs = b''.join(bytes([(int('{:08b}'.format(x)[::-1],2))]) for x in bs)  
   res = 0  
   res = num2poly(ixor ^^ oxor)  
   if rev:  
       res = R(x**(bits-1) * res(1/x))  
   res *= x**(8*len(bs))  
   res += x**bits * num2poly(bytes_to_long(bs))  
   res %= poly  
   if rev:  
       res = R(x**(bits-1) * res(1/x))  
   res += num2poly(oxor)  
   return poly2num(res)

names = list(sorted(crcs.keys()))

def allcrcs(bs):  
   v = matrix(GF(2),1,0)  
   for name in names:  
       v = v.augment(num2vec(crcs[name]['bits'], mycrc(name, bs)).row())  
   return v

v0 = allcrcs(b'\0'*l)

t = matrix(GF(2),1,0)  
for name in names:  
   t = t.augment(num2vec(crcs[name]['bits'], target[name]).row())

mat = matrix(GF(2), 0, sum(crcs[name]['bits'] for name in names))  
for i in range(8*l):  
   row = allcrcs(long_to_bytes(2**i).rjust(l,b'\0'))  
   mat = mat.stack(row - v0)

sol = vector(mat.solve_left(t - v0))

for kervec in mat.left_kernel():  
   res = long_to_bytes(sum(ZZ(s) << i for i,s in enumerate((sol +
kervec).list())))  
   print([res])  
```