## Just Take Your Time (200 Points)

### Problem  
```  
Let's go. In and out. 2 second adventure.  
nc dctf-chall-just-take-your-time.westeurope.azurecontainer.io 9999

Hint: While this may not be pwn, its tools may still be quite handy.  
File: just-take-your-time.py  
```

### Solution  
This CTF was an intro to pwntools for me, I solved some Pwn challs earlier in
the day, and I was looking forward to getting stuck into this challenge using
the same tools.

From looking at the supplied source code, we can gather that essentially what
we need to do is:  
- Return the product of two numbers within 1 second.  
- Decrypt some Triple DES'd Hex within 1 second.

**The Encryption Algorithm**  
```python  
key = str(int(time())).zfill(16).encode("utf-8")  
secret = token_hex(16)  
cipher = DES3.new(key, DES3.MODE_CFB, b"00000000")  
encrypted = cipher.encrypt(secret.encode("utf-8"))  
print("You have proven yourself to be capable of taking on the final task.
Decrypt this and the flag shall be yours!")  
print(encrypted.hex())  
```

- The Key: integer timestamp padded with 16 zeroes.  
- The Secret: some random 16-byte Hex.  
- The Cipher: Triple DES in Cipher Feedback Mode and IV `00000000`

I ran the source code locally and printed out the key, the secret and the hex
ciphertext and used the Triple DES recipe in CyberChef to experiment using
different values in attempt to decrypt.

One thing I spotted was that the Decryption Key could be off by 1-bit and
return the plaintext. Post-CTF, I now know these are known as `Parity Bits` in
DES.  
This was certainly exploitable from our side, as the Encryption Key is a int
timestamp with some 0-padding. If we generate a Decryption Key using the same
functions, we'll be able to decrypt to the plaintext as we'll have created our
Decryption Key within 1 second of the Encryption Key having been created.

This was all we needed to solve. We could copy & paste the cipher info from
the source code into our exploit, call the `decrypt` function, do some simple
data conversion so the server would accept our payload, and that will yield us
the flag.

**Exploit**

Note: Like I said in the beginning, DragonCTF was an intro to `pwntools` for
me, there is room for improvement with how I receive data from the server and
send to the server.

```python  
from pwn import *  
from Crypto.Cipher import DES3  
from time import time

def calc_product(message):  
   numbers = [int(s) for s in message.split() if s.isdigit()]  
   return numbers[0] * numbers[1]

host = remote(  
   'dctf-chall-just-take-your-time.westeurope.azurecontainer.io', 9999)

host.recvline(timeout=0.1)  
message = host.recvline(timeout=0.1)  
answer = calc_product(message)

message = host.recv(timeout=0.1)  
host.sendline(str(answer))  
host.recvuntil(b'\n')  
message = host.recvuntil(b'\n')

message = message[:-1]  
msg_decoded = message.decode('utf-8')  
msg_bytes = bytes.fromhex(msg_decoded)  
key = str(int(time())).zfill(16).encode("utf-8")  
cipher = DES3.new(key, DES3.MODE_CFB, b"00000000")  
decrypted = cipher.decrypt(msg_bytes)

host.sendline(decrypted)  
message = host.recvuntil('}')

print(message)  
```

```  
❯ python3 exploit.py  
[+] Opening connection to dctf-chall-just-take-your-
time.westeurope.azurecontainer.io on port 9999: Done  
b'> Congratulations! Here is your flag.\ndctf{1t_0n1y_t0Ok_2_d4y5...}'  
```

Flag: `dctf{1t_0n1y_t0Ok_2_d4y5...}`  

Original writeup
(https://github.com/cieran/writeups/blob/main/DragonCTF/crypto/JustTakeYourTime.md).