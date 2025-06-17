# The Challenge

We are given an implementation of a cipher they call `A3S`, and a `help.pdf`
briefly explaining `A3S`. We are also given a single plaintext-ciphertext pair
(`sus.` --> `b'\x06\x0f"\x02\x8e\xd1'`), and the encrypted flag.

`A3S` turns out to be a modified version of `AES`, but instead of working on
bits, it works on _trits_ (base 3). This gives an idea of how one might
approach this problem.

The files are in the [./chal](./chal) folder.

## Metadata

I participated in RARCTF with CTF.SG. Unfortunately I wasn't able to solve
this challenge in time before the CTF ended, as I started this challenge with
only a few hours left. Nevertheless, I loved this challenge too much to simply
let it go so here we are.

## Vulnerability

```python  
# Encryption routine  
def a3s(msg, key):  
   m       = byt_to_int(msg)  
   k       = byt_to_int(key)  
   m       = up(int_to_tyt(m), W_SIZE ** 2, int_to_tyt(0)[0])[-1] # Fixed
block size  
   k       = int_to_tyt(k)  
   keys    = expand(k) # tryte array  
   assert len(keys) == KEYLEN

   ctt = T_xor(m, keys[0])

   for r in range(1, len(keys) - 1):  
       ctt = sub_wrd(ctt)                          # SUB...  
       ctt = tuple([ctt[i] for i in SHIFT_ROWS])   # SHIFT...  
       ctt = mix_columns(ctt)                      # MIX...  
       ctt = T_xor(ctt, keys[r])                   # ADD!

   ctt  = sub_wrd(ctt)  
   ctt  = tuple([ctt[i] for i in SHIFT_ROWS])  
   ctt  = T_xor(ctt, keys[-1])                     # last key

   ctt = tyt_to_int(ctt)  
   return int_to_byt(ctt)  
```

Take a look at the encryption routine above. In `A3S.py` we see that it
encrypts with **26** rounds of A3S. This immediately rules out common attacks
like MITM or finding a differntial as the number of rounds you have to cut
through is just insane. That's probably a cue to look at the `SBOX`. A cursory
test shows that `SBOX[a] + SBOX[b] == SBOX[a+b]`:

```python  
sub_map = {} # x --> y, (xor(i1, i2) --> xor(o1,o2))

for a in range(3**3):  
   for b in range(3**3):  
       sa = SBOX[a]  
       sb = SBOX[b]  
       o = tuple(xor(x,y) for x,y in zip(int_to_tyt(sa)[0],int_to_tyt(sb)[0]))  
       i = tuple(xor(x,y) for x,y in zip(int_to_tyt(a)[0],int_to_tyt(b)[0]))  
       if i not in sub_map:  
           sub_map[i] = set()  
       sub_map[i].add(o)  
  
print([len(i) for i in sub_map.values()])  
# > [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
1, 1, 1]  
```

This means that `SBOX` is simply an affine transform! It's not that hard to
then derive the exact transformation:

```python  
def sbox_affine(i:tuple):  
   "Substitutes a trit with SBOX"  
   return (  
       (0 + i[0]*1 + i[1]*2 + i[2]*1) % 3,  
       (2 + i[0]*0 + i[1]*1 + i[2]*2) % 3,  
       (0 + i[0]*2 + i[1]*1 + i[2]*0) % 3  
   )  
```

This is significant as the other operations in `A3S`, namely `shift`, `mix`
and `add`, are all linear operations. Normally, in `AES`, `SBOX` is an
important factor providing non-linearity to `AES`. Having `SBOX` be an affine
transform means that the **whole encryption is an affine transform of the
plaintext**, which is really easy to analyse algebraically.

## But It's Worse

Let's look at the key schedule:

```python  
def expand(tyt):  
   words   = tyt_to_wrd(tyt)  
   size    = len(words)  
   rnum    = size + 3  
   rcons   = rcon(rnum * 3 // size)

   for i in range(size, rnum * 3):  
       k   = words[i - size]  
       l   = words[i - 1]  
       if i % size == 0:  
           s = sub_wrd(rot_wrd(l))  
           k = T_xor(k, s)  
           k = (t_xor(k[0], rcons[i // size - 1]),) + k[1:]  
       else:  
           k = T_xor(k, l)  
       words = words + (k,)

   return up(down(words[:rnum * 3]), W_SIZE ** 2, int_to_tyt(0)[0])  
```

This routine is used to expand a key into all the 28 round keys that are used
in `a3s`. Just like in regular AES, the `sub_wrd` routine which uses the
`SBOX`, would have made the key expansion non-linear and relatively harder to
analyse. But as we have seen earlier, `SBOX` is affine! That means that the
**key expansion is an affine transformation of the original key** as well!

What these both mean is that, from what we are given: `a3s(b"sus.") ==
b'\x06\x0f"\x02\x8e\xd1'`, we can represent `b'\x06\x0f"\x02\x8e\xd1'` as an
affine transform of the original key, which, theoretically, makes solving for
the original key very very easy.

## Representing the problem

The key is made of `75*3` trits, and so I create `75*3` variables in `GF(3)`:

```python  
F = GF(3)  
FP = PolynomialRing(F, 'k', 25*3*3)  
keyFP = FP.gens()  
```

Now we _can_ reimplement `a3s` in our solve script, but I chose instead to
simply use the `a3s.py` implementation the challenge author has so graciously
provided us. I just have to modify certain functions to make it sage and
`GF(3)` friendly. These are the functions I modified:

```python  
t_xor = lambda a,b: tuple(x+y for x,y in zip(a,b))  
T_xor = lambda a,b: tuple(t_xor(i,j) for i,j in zip(a,b))  
t_uxor = lambda a,b: tuple(x-y for x,y in zip(a,b))  
T_uxor = lambda a,b: tuple(t_uxor(i,j) for i,j in zip(a,b))

def sbox_affine(i:tuple):  
   return (  
       (0 + i[0]*1 + i[1]*2 + i[2]*1),  
       (2 + i[0]*0 + i[1]*1 + i[2]*2),  
       (0 + i[0]*2 + i[1]*1 + i[2]*0)  
   )

def expand(tyt):  
   words   = tyt_to_wrd(tyt)  
   size    = len(words)  
   rnum    = size + 3  
   rcons   = rcon(rnum * 3 // size)

   for i in range(size, rnum * 3):  
       k   = words[i - size]  
       l   = words[i - 1]  
       if i % size == 0:  
           s = tuple(sbox_affine(i) for i in rot_wrd(l))  
           k = T_xor(k, s)  
           k = (t_xor(k[0], rcons[i // size - 1]),) + k[1:]  
       else:  
           k = T_xor(k, l)  
       words = words + (k,)

   return up(down(words[:rnum * 3]), W_SIZE ** 2, int_to_tyt(0)[0])

def tri_mulmod(A, B, mod=POLY):  
   c = [0] * (len(mod) - 1)  
   for a in A[::-1]:  
       c = [0] + c  
       x = tuple(b * a for b in B)  
       c[:len(x)] = t_xor(c, x)  
       n = -c[-1]*mod[-1]  
       c[:] = [x+y*n for x,y in zip(c,mod)]  
       c.pop()  
   return tuple(c)

def tyt_mulmod(A, B, mod=POLY2, mod2=POLY):  
   fil = [(0,) * T_SIZE]  
   C = fil * (len(mod) - 1)  
   for a in A[::-1]:  
       C = fil + C  
       x = tuple(tri_mulmod(b, a, mod2) for b in B)  
       C[:len(x)] = T_xor(C, x)  
       num = modinv(mod[-1], mod2)  
       num2 = tri_mulmod(num, C[-1], mod2)  
       x = tuple(tri_mulmod(m, num2, mod2) for m in mod)  
       C[:len(x)] = T_uxor(C, x)

       C.pop()  
   return C

def add(a,b):  
   return tuple(  
       tuple(x+y for x,y in zip(i,j)) for i,j in zip(a,b)  
   )

def sub(a):  
   return tuple(  
       sbox_affine(x) for x in a  
   )

def shift(a):  
   return [  
       a[i] for i in SHIFT_ROWS  
   ]

def mix(tyt):  
   tyt = list(tyt)  
   for i in range(W_SIZE):  
       tyt[i::W_SIZE] = tyt_mulmod(tyt[i::W_SIZE], CONS)  
   return tuple(tyt)  
```

Now we can simply expand the key and encrypt `sus.` symbolically:

```python

# Expand the key  
xkeyFP = tuple(tuple(keyFP[i*3+j] for j in range(3)) for i in range(25*3))  
exkeyFP = expand(exkeyFP)

# Perform encryption of `sus.` with symbolised key

m = byt_to_int(b'sus.')  
m = up(int_to_tyt(m), W_SIZE ** 2, int_to_tyt(0)[0])[-1]

assert len(exkeyFP) == KEYLEN

ctt = add(m, exkeyFP[0])

for r in range(1, len(exkeyFP) - 1):  
   ctt = sub(ctt)  
   ctt = shift(ctt)  
   ctt = mix(ctt)  
   ctt = add(ctt, exkeyFP[r])

ctt  = sub(ctt)  
ctt  = shift(ctt)  
ctt  = add(ctt, exkeyFP[-1])  
```

What's left is to form the system of linear equations and solve:

```python  
mat = []  
const = []  
for x in ctt:  
   for y in x:  
       s = vector([0]*75*3)  
       c = 0  
       for i,j in y.dict().items():  
           if sum(i) == 0:  
               c += j  
           s += vector(i)*j  
       const.append(c)  
       mat.append(s)  
mat = Matrix(F, mat)

rhs = int_to_tyt(byt_to_int(b'\x06\x0f"\x02\x8e\xd1'))  
rhs = vector(F, [i for j in rhs for i in j])  
rhs -= vector(F, const)

key_rec = mat.solve_right(rhs)  
key_rec = tuple(tuple(key_rec[3*i+j] for j in range(3)) for i in range(75))

print(key_rec)  
# ((2, 1, 1), (1, 1, 1), (1, 1, 2),  
#  (1, 0, 0), (2, 2, 0), (2, 2, 1),  
#  (0, 1, 2), (2, 1, 2), (0, 2, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0),  
#  (0, 0, 0), (0, 0, 0), (0, 0, 0))  
```

You might notice that while we have `3*75` variables, we only have `3*9`
equations. This means that there are many many many keys that give the same
plaintext and ciphertext pair, and this method can solve for all of them.

Eitherways, now that we have the key, we can finally decrypt our flag:

```python  
# Modify d_a3s to use key in tyt form  
def d_a3s(ctt, key):  
   c       = byt_to_int(ctt)  
   c       = up(int_to_tyt(c), W_SIZE ** 2, int_to_tyt(0)[0])[-1] # Fixed
block size  
   keys    = expand(key)[::-1] # tryte array  
   assert len(keys) == KEYLEN

   msg = c  
   msg = T_uxor(msg, keys[0])

   for r in range(1, len(keys) - 1):  
       msg = tuple([msg[i] for i in UN_SHIFT_ROWS])    # UN SHIFT...  
       msg = u_sub_wrd(msg)                            # UN SUB...  
       msg = T_uxor(msg, keys[r])                      # UN ADD...  
       msg = mix_columns(msg, I_CONS)                  # UN MIX!

   msg  = tuple([msg[i] for i in UN_SHIFT_ROWS])  
   msg  = u_sub_wrd(msg)  
   msg  = T_uxor(msg, keys[-1])                     # last key

   msg = tyt_to_int(msg)  
   return int_to_byt(msg)

flag_enc =
b'\x01\x00\xc9\xe9m=\r\x07x\x04\xab\xd3]\xd3\xcd\x1a\x8e\xaa\x87;<\xf1[\xb8\xe0%\xec\xdb*D\xeb\x10\t\xa0\xb9.\x1az\xf0%\xdc\x16z\x12$0\x17\x8d1'

out = []  
for i in chunk(flag_enc):  
   out.append(d_a3s(i, key_rec))  
  
print("Flag:", unchunk(out).decode())

# Flag: rarctf{wh3n_sb0x_1s_4_5u55y_baka_02bdeff124}  
```

Full solve scripts can be found in the [./sol](./sol) folder.  

Original writeup (https://github.com/JuliaPoo/Collection-of-CTF-
Writeups/tree/master/RARCTF-2021/A3S).