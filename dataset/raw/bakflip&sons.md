#  bakflip&sons  (crypto, 925p, 14 solved)

## Description

In the task we get access to a remote service running some
[code](https://raw.githubusercontent.com/TFNS/writeups/master/2020-07-31-InCTF/backflip/bakflips.py)

## Analysis

The code is basically running weird ECDSA signature oracle.  
We can submit messages to sign and we can provide a bitmask, which is used to
derive public key point.  
There is a `101` bit `secret` private key, and public key point is created as
`secret ^ mask  * G`.

We can interact with the oracle 71 times.

The goal is to sign a special message `please_give_me_the_flag`, which
normally the service rejects.

In general there are 2 approaches in tasks like this:

- Some sort of blinding attack, where you sign N messages and combine signatures to get signature of the target message. This works for homomorphic schemes like textbook RSA.  
- Recover the secret key

In our case ECDSA is definitely not allowing for the fist case, unless we
could find SHA1 collision with the target message.  
This leaves option 2.

## Solution

### Recover public key point

Key thing to notice here is that it's possible to recover public key point
from just the signature and message.  
Ot at least recover a bunch of candidate keys, one of which will be valid.  
It's even in the library they're using:

```python  
keys = VerifyingKey.from_public_key_recovery(signature, message, NIST192p)  
```

This means if we provide `mask = 0` we can get `secret * G`, and `G` is
constant for the curve.  
We can't recover `secret` from that, because this is discrete logarithm over
ECC.

### Flip!

#### LSB case

Notice what happens when we provide `mask = 1`.  
Now if we sign the same message, and recover the public key points, we will
get point `secret^1 * G`.

This can mean only 2 cases:

- If originally LSB of secret was 0, now it was flipped to 1 and thus `secret^1 == secret+1` and therefore `secret^1 * G == secret*G + G`  
- If originally LSB of secret was 1, now it was flipped to 0 and thus `secret^1 == secret-1` and therefore `secret^1 * G == secret*G - G`

Notice that since we know `secret*G` and `G` we can easily verify which case
this is!  
We can just compare `secret^1 * G` with `secret*G + G` and `secret*G - G`, and
one of the has to match.  
This way we can leak the LSB of `secret`.

#### Extension

It's not difficult to see that this method easily extends for more bits.  
We can provide a 2-bit mask and test all possible cases:

- `secret^0b11 == secret + 1`  
- `secret^0b11 == secret - 1`  
- `secret^0b11 == secret + 2`  
- `secret^0b11 == secret - 2`  
- `secret^0b11 == secret + 3`  
- `secret^0b11 == secret - 3`

This works for any number of bits, but we need some computation, so it's
better to limit this to maybe 8 at a time - we have 70 requests to spare
anyway!

Notice we can also extend this to skip some lower bits we already know, by
sending `0` in bitmask for positions we're not interested in, because this
particular bits won't be flipped and there is no reason to test for that:

- `secret^0b110 == secret + 2`  
- `secret^0b110 == secret - 2`  
- `secret^0b110 == secret + 4`  
- `secret^0b110 == secret - 4`  
- `secret^0b110 == secret + 6`  
- `secret^0b110 == secret - 6`

### Solver:

We put the ideas above into code:

```python  
def recover_bits(oracle, bits_to_guess, start_bit):  
   message = "alamakota"  
   signature = oracle(message, 0)  
   reference_keys = VerifyingKey.from_public_key_recovery(signature, message,
NIST192p)  
   reference_points = [ref_key.pubkey.point for ref_key in reference_keys]  
   secret_mask = int('1' * bits_to_guess + '0' * start_bit, 2)  
   signature = oracle(message, secret_mask)  
   flipped_keys = VerifyingKey.from_public_key_recovery(signature, message,
NIST192p)  
   for key in flipped_keys:  
       for reference_point in reference_points:  
           for option in itertools.product([1, -1], repeat=bits_to_guess):  
               mods = [m * 2 ** (i + start_bit) for i, m in enumerate(option)]  
               point_modification = reduce(lambda x, y: x + y, [m * NIST192p.generator for m in mods])  
               if key == VerifyingKey.from_public_point(reference_point + point_modification):  
                   # -1 means we flipped bit from 1 to 0  
                   # 1 means we flipped by from 0 to 1  
                   result = "".join(['1' if k == -1 else '0' for k in option][::-1])  
                   print('recovered chunk ', result)  
                   return result  
```

We can easily verify this with a sanity check:

```python  
secret_multiplier = random.getrandbits(101)

def fake_oracle(message, secret_mask):  
   secret = secret_multiplier ^ secret_mask  
   signingKey = SigningKey.from_secret_exponent(secret)  
   signature = signingKey.sign(message)  
   return signature

def sanity2():  
   bits_step = 8  
   res = ''  
   print(bin(secret_multiplier))  
   for start_bit in range(0, 101, bits_step):  
       recovered = recover_bits(fake_oracle, bits_step, start_bit)  
       res = recovered + res  
   print(res)  
   assert int(res, 2) == secret_multiplier  
```

## Get the flag

Now we can just plug this in:

```python  
def PoW(suffix, digest):  
   for prefix in itertools.product(string.ascii_letters + string.digits,
repeat=4):  
       p = "".join(prefix)  
       if hashlib.sha256(p + suffix).hexdigest() == digest:  
           return p

def real_oracle(s, message, mask):  
   send(s, "1")  
   x = receive_until(s, ":")  
   send(s, message)  
   x = receive_until(s, ":")  
   send(s, str(mask))  
   x = receive_until(s, "\n")  
   signature = re.findall("Signature: (.*)", x)[0].strip()  
   print(signature)  
   x = receive_until(s, "#")  
   return signature.decode("hex")

def main():  
   host = "34.74.30.191"  
   port = 9999  
   s = nc(host, port)  
   task = receive_until(s, ":")  
   task = re.findall("XXXX\+(.*)\) == (.*)", task)[0]  
   print(task)  
   p = PoW(task[0], task[1])  
   print(p)  
   send(s, p)  
   x = receive_until(s, "#")

   bits_step = 8  
   res = ''  
   for start_bit in range(0, 102, bits_step):  
       recovered = recover_bits(lambda msg, mask: real_oracle(s, msg, mask), bits_step, start_bit)  
       print(start_bit, recovered)  
       res = recovered + res  
   print('secret', res)  
   secret = int(res, 2)  
   signingKey = SigningKey.from_secret_exponent(secret)  
   forged = signingKey.sign("please_give_me_the_flag")  
   send(s, "3")  
   send(s, forged.encode("hex"))  
   interactive(s)  
```

And recover: `inctf{i_see_bitflip_i_see_family}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-07-31-InCTF/backflip/README.md).