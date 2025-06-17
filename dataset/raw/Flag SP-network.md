# Flag SP-network

We are given a file, `sp_network.py`, containing code to encrypt data, along
with the encrypted flag. As always, we'll need to figure out how to get the
flag!

Because the file says the flag is encrypted, it's reasonable to assume we need
to *decrypt* it.  
For decryption, we'll need  
1. the key  
2. the decryption algorithm

## The Key

This is how the key is computed:

```python  
key = [random.randrange(255), random.randrange(255)] * 4  
print(key)  
# [176, 17, 176, 17, 176, 17, 176, 17]  
```

Though at first it might seem like the key consists of 8 random bytes, in
reality it only consists of two random bytes, repeated four times. Once we
have the required decryption algorithm, it should be no problem to iterate
through the whole key space to find the correct key.

## The Encryption Algorithm

Let's look at the encryption function `r`:

```python  
def r(p, k):  
   ## 1.  
   keys = ks(k)  
   ## 2.  
   state = str_split(p)  
   ## 3.  
   for b in range(len(state)):  
       ## 4.  
       for i in range(rounds):  
           ## 5. Core of the encryption  
           rk = kx(to_ord(state[b]), keys[i])  
           state[b] = to_chr(en(to_chr(rk)))  
   return [ord(e) for es in state for e in es]  
```

1. The `ks` function takes the key and generates "round keys". For this, it simple rotates bytes around:

```python  
key = [45, 89, 45, 89, 45, 89, 45, 89]  
ks(key)  
# => [  
#     [45, 89, 45, 89, 45, 89, 45, 89],  
#     [89, 45, 89, 45, 89, 45, 89, 45],  
#     [45, 89, 45, 89, 45, 89, 45, 89],  
#     [89, 45, 89, 45, 89, 45, 89, 45],  
#     [45, 89, 45, 89, 45, 89, 45, 89]  
# ]  
```

2. The input string is split into blocks of size `block_size` (8 in this instance).  
3. Each block is processed separately.  
4. The core of the encryption algorithm (see 5.) is performed `rounds` number of times.  
5. `kx` just XORs the key with the current state variable. This is the actual encryption. The call to `en` looks complicated, but turns out to be rather simple. To see this, observe that the function performs the same operation on all of its input bytes. Extract the core of the function (the loop body) and observe that it yields a different, unique output value for each unique input. This is a straightforward byte substitution.

```python  
def en_core(c):  
   a, b = bin_split(to_bin(ord(c)))  
   sa, sb = s(to_int(a), to_int(b))  
   pe = p(  
       bin_join((to_bin(sa, int(block_size / 2)), to_bin(sb, int(block_size / 2))))  
   )  
   return to_int(pe)

en_lut = {  
   x: en_core(x) for x in range(256)  
}

assert len(set(en_lut.keys())) == 256  
# Using set(), duplicate values are filtered out  
# However, here there are no duplicates.  
# Each value occurs exactly once!  
assert len(set(en_lut.values())) == 256  
```

## The Decryption Algorithm

At this point, we understand the encryption algorithm and want to decrypt the
flag. To do so, we need to invert the encryption algorithm.

```python  
def r(p, k):  
   ## 1.  
   keys = ks(k)  
   ## 2.  
   state = str_split(p)  
   ## 3.  
   for b in range(len(state)):  
       ## 4.  
       for i in range(rounds):  
           ## 5. Core of the encryption  
           rk = kx(to_ord(state[b]), keys[i])  
           state[b] = to_chr(en(to_chr(rk)))  
   return [ord(e) for es in state for e in es]  
```

Looking back at `r`, we only need to invert Step 5. To do this, it might be
helpful to untangle the loop body into something like this:

```python  
input = state[b]  
step1 = kx(to_ord(input), keys[i])  
step2 = to_chr(step1)  
step3 = en(step2)  
output = to_chr(step3)  
```

To invert this, we start from the output and work back to the input:

```python  
step3 = to_ord(output)  
step2 = de(step3)  
step1 = to_ord(step2)  
input = to_chr(kx(step1, keys[i]))  
```

Here, `de` is the inverse function of `en`. It is essentially a simple
dictionary lookup with an inverted `lut` dictionary, as can be seen in the
following listing. All other operations should be straightforward. For your
own testing, it's helpful to set `rounds = 1`.

```python  
# Inverse mapping, for de(cryption) function  
de_lut = {  
   y: chr(x) for (x, y) in en_lut.items()  
}

def de(e):  
   return "".join([de_lut[v] for v in e])  
```

You'll notice that the first line, `step3 = to_ord(output)` is not necessary
because the output is already a list of `int`s. Similarly, the `to_chr`
operation in the last line can be omitted, because the result (`input`) is
used as the `output` variable in the next loop iteration. We'll use an
additional `to_chr` at the very end of decryption.

## Putting It Together

Here's the complete `decrypt` function:

```python  
def decrypt(ciphertext, key):  
   keys = ks(key)  
   state = str_split(ciphertext)  
   for b in range(len(state)):  
       for i in range(rounds):  
           output = state[b]  
           # Step 3 not necessary, because r(p, k) does ord() at the end  
           # => final output is already in desired format  
           # step3 = to_ord(output)  
           step2 = de(output)  
           step1 = to_ord(step2)

           # Iterate through keys in reverse order  
           input = kx(step1, keys[-1 - i])

           state[b] = input

   return "".join([chr(e) for es in state for e in es])  
```

With that, to decrypt the flag, we try every possible key (16-bit keyspace!)

```python  
for x in range(256):  
   for y in range(256):  
       candidate = [x, y] * 4

       plaintext = decrypt(ciphertext, k)  
       if plaintext.startswith("flag"):  
           print(f'Found flag: {plaintext}')  
           break  
```

et voilà: the flag is `flag{i_guess_2_bytes_wasnt_enough_after_all}`

Original writeup (https://github.com/0xbf00/ctf-writeups).