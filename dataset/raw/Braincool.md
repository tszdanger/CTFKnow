The task contains ELF binary for ARM platform and the following Python script:  
```  
import requests

CHALLENGE_URL = "http://braincool.donjon-ctf.io:3200/apdu"

def get_public_key():  
   req = requests.post(CHALLENGE_URL, data=bytes.fromhex("e005000000"))  
   response = req.content  
   if response[-2:] != b"\x90\x00":  
       return None  
   return response[:-2]

public_key = get_public_key()  
assert public_key ==
bytes.fromhex("0494e92dd2a82e93d90c13322819db091a869c30c03c5a47d7b1f38683ba9bfdf33f44582dbd19e55e319ce5b2929fba6da9705c84df8c209441bcb713cf99c6d5d6e94445bc808e6821b73f3fa7d55b8a")  
```

ELF binary is not self-contained and uses syscalls like 0x60010B06 and same-
privilege-level but external library with entrypoint at 0x120000; these are
provided by Ledger Nano runtime (can be figured out in various ways - Magic
OTP has a source-code example; "Ledger Nano" in UTF-16 is one of strings
inside the binary; looking for products of the company that organizes the CTF;
searching for syscall numbers, these are very specific). Entrypoint at
0x120000 dispatches many different functions by identifier defined in
[https://github.com/LedgerHQ/nanos-secure-
sdk/blob/1c16f9ad50f792c62a948aacb650258660f262cb/include/cx_stubs.h](https://github.com/LedgerHQ/nanos-
secure-sdk/blob/1c16f9ad50f792c62a948aacb650258660f262cb/include/cx_stubs.h);
the binary has corresponding wrappers with `push {r0,r1} // ldr r0,=<id> // b
<helper label that branches to 0x120000>`. The repository also includes
commented prototypes of all these functions.

One more thing besides SDK repository is very useful:
[https://speculos.ledger.com/](https://speculos.ledger.com/) is an emulator
for all this. System calls are handled by Python code, external library is
provided as another binary in Speculos distribution. Speculos successfully
loads binary from the task and serves a web page on http://localhost:5000 that
(among other things) has an input named APDU, same as `CHALLENGE_URL` in the
script above. Sending e005000000 results in something that doesn't exactly
match bytes from the script but looks like the same structure. APDU is not
invented by Ledger, there was a presentation
[https://www.blackhat.com/presentations/bh-
usa-08/Buetler/BH_US_08_Buetler_SmartCard_APDU_Analysis_V1_0_2.pdf](https://www.blackhat.com/presentations/bh-
usa-08/Buetler/BH_US_08_Buetler_SmartCard_APDU_Analysis_V1_0_2.pdf) back in
2008 that describes the basics; APDUs have 5-byte header
(CLA=class)(INS=instruction)(P1=param1)(P2=param2)(Lc=length) followed by Lc
bytes of data; APDU from the script above has class 0xE0, instruction code
0x05, zero parameters and no data.

With this, reversing can finally start. Probably the easiest way to find the
actual worker is to notice a string "CTF" in the binary and look for
references to it. The worker is at 0xC0D00138 and accepts one argument that
points to 5-byte header from APDU followed by 3 bytes of padding and a pointer
to additional data, if any. The only recognized class is 0xE0 (whatever it
means), there are 3 supported commands e005, e006, e007. e005 ignores
parameters and data and returns something generated by the function at
0xC0D00374 (that is also called from e007 code path), which in turn calls the
function at 0xC0D003A8 (that is also called from e006 code path) followed by
`cx_ecfp_generate_pair2_no_throw(CX_CURVE_BrainPoolP320R1, (result), (output
from 0xC0D003A8), 1, 0)`; so 0xC0D003A8 generates elliptic private key,
0xC0D00374 generates elliptic public key, and e005 command returns that public
key.

Let's check bytes from the script with SageMath...  
```  
p =
0xD35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27  
q =
0xD35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311  
E = EllipticCurve(GF(p),
[0x3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4,
0x520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6])  
G =
E(0x43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611,
0x14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1)  
Q =
E(0x94e92dd2a82e93d90c13322819db091a869c30c03c5a47d7b1f38683ba9bfdf33f44582dbd19e55e,
0x319ce5b2929fba6da9705c84df8c209441bcb713cf99c6d5d6e94445bc808e6821b73f3fa7d55b8a)  
```  
...yep, no exception, this is a point on the curve.

e006 command requires 40 bytes of additional data, checks that first 3 bytes
are not "CTF", generates private key, calculates some hashes in a loop and
calls `cx_ecdsa_sign_no_throw`. e007 command requires at least 40 bytes of
additional data, generates public key and calls
`cx_ecdsa_verify_no_throw((public key), (pointer to additional data), 40,
(pointer to additional data) + 40, (length) - 40)`; according to SDK, that
means the data have to be 40-byte hash followed by a ECDSA signature of that
hash. If `verify` succeeds, the code checks that first 3 bytes are "CTF", if
so, outputs the result of more calculations involving some static byte arrays
that look like decrypting of the flag.

There are (at least) two possible solutions for the task.

One solution is to ignore e006 command at all, focus on e007 command and
recite how ECDSA verification works: given a hash `h` and a pair of modulo-
curve-order integers `(r,s)`, calculate `u1=h/s`, `u2=r/s` modulo curve order,
calculate a point `u1*G + u2*Q` and check whether x-coordinate equals `r`
modulo curve order. We can start from random `u1` and `u2`, calculate `u1*G +
u2*Q`, get `r` as x-coordinate, calculate `s` and `h` from `u1` and `u2` and
get a valid triple (`h`,`s`,`r`) that passes the verification. We have no
control over the resulting `h`, so this wouldn't work if `h` would be required
to be an actual hash of something, but that is not the case for e007 function.
We just need to forge a value with fixed 3 bytes; since `h` is essentially
random, this requires 2^24 attempts on average with varying `u1` and `u2`.

Actually, the bottleneck is elliptic addition, so instead of random `u1`, `u2`
I took `u2=1` and `u1=1,2,3,...` so that each attempt is just one elliptic
addition:  
```  
u1 = 0  
u2 = 1  
R = Q  
while True:  
   u1 += 1  
   R += G  
   r = R[0].lift() % q  
   s = r  
   h = u1 * s % q  
   if hex(h).startswith('0x435446'):  
       print(r, s, h, u1, u2)  
       break  
```  
(okay, not strictly correct because 0x0435446 would also break the loop while
being invalid for the problem, but whatever). My notebook found valid values
in about ten minutes  
r=139311631778238424243685822929333226109973101219096009338726201981806436303919831322992698069905  
s=139311631778238424243685822929333226109973101219096009338726201981806436303919831322992698069905  
h=561774667424912276805954464527063183413505002816398854203852806056677912589630309235467827822607  
u1=19075642  
u2=1

It remains to serialize this to the expected format  
```  
def encode(a):  
   s = hex(a)[2:]  
   if len(s) % 2:  
       s = '0' + s  
   return '02' + '%02x' % (len(s) // 2) + s  
encoded = encode(r) + encode(s)  
encoded = '30' + '%02x' % (len(encoded) // 2) + encoded  
print('e0070000' + '%02x' % (len(encoded) // 2 + 40) +
hex(h)[2:].rjust(80,'0') + encoded)  
```  
and send the output
`e00700007e435446f54766048a99fdbda8ae969fb988ba888100c4b60db858bd506d416a1d9cc33b7d420c400f`  
`3054022810b2561d2a1fe9f79f0f3d38784733a86822495ad1d87b347ccd9dd3061c798577c44255c4be1391`  
`022810b2561d2a1fe9f79f0f3d38784733a86822495ad1d87b347ccd9dd3061c798577c44255c4be1391`
to the server.

Turns out this is not the expected solution. Another solution is to deeply
dive into e006 command. It calls `cx_ecdsa_sign_no_throw((private key), 0x800,
4, (input additional data), (signature), &(signature length), 0)` and then
outputs