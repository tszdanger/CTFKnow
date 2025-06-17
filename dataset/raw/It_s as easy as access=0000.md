# It's as easy as access=0000

We can connect to a remote server and are given this Python script:

```python  
from Crypto.Util.Padding import pad, unpad  
from Crypto.Cipher import AES  
from Crypto.Random import get_random_bytes  
from datetime import datetime, timedelta

challenge_description("You can generate an access token for my network
service, but you shouldn't be able to read the flag... I think.")  
challenge_name = "It's as easy as access=0000"  
FLAG = "ractf{XXX}"  
KEY = get_random_bytes(16)

def get_flag(token, iv):  
   token = bytes.fromhex(token)  
   iv = bytes.fromhex(iv)  
   try:  
       cipher = AES.new(KEY, AES.MODE_CBC, iv)  
       decrypted = cipher.decrypt(token)  
       unpadded = unpad(decrypted, 16)  
   except ValueError as e:  
       return {"error": str(e)}  
   if b"access=0000" in unpadded:  
       return {"flag": FLAG}  
   else:  
       return {"error": "not authorized to read flag"}

def generate_token():  
   expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")  
   token = f"access=9999;expiry={expires_at}".encode()  
   iv = get_random_bytes(16)  
   padded = pad(token, 16)  
   cipher = AES.new(KEY, AES.MODE_CBC, iv)  
   encrypted = cipher.encrypt(padded)  
   ciphertext = iv.hex() + encrypted.hex()  
   return {"token": ciphertext}

def start_challenge():  
 menu = "Would you like to:\n[1] Create a guest token\n[2] Read the flag"  
 while True:  
   print(menu)  
   choice = str(input("Your choice: "))  
   while choice != "1" and choice != "2":  
       choice = str(input("Please enter a valid choice. Try again: "))  
   if choice == "1":  
     print(generate_token())  
   elif choice == "2":  
     token = input("Please enter your admin token: ")  
     while not token:  
       token = input("Tokens can't be empty. Try again: ")  
     iv = input("Please enter your token's initialization vector: ")  
     while not iv:  
       iv = input("Initialization vectors can't be empty. Try again: ")  
     print(get_flag(token, iv))  
  
start_challenge()  
```

## Description

We have two different options:  
- generate a guest token  
- login as admin using an admin token.

Guest tokens are an AES-CBC mode encryption of
`access=9999;expiry={expires_at}`. A token is considered as an admin token if
`access=0000` is present in its decryption. This is a very simple example of
malleability of AES-CBC (for the first block).

Let's recall how AES-CBC works: it selects a random IV (Initialization
Vector), then uses AES as a block cipher to encrypt data. The plaintext is
split into blocks (adding padding to get a multiple of the block length), and
the ciphertext is generated as follows:

```  
c[i] = AES_Enc(c[i-1] XOR m[i])  
```

with `c[0]` being the IV. The ciphertext is `c` (including the IV). The
decryption formula is the following:

```  
m[i] = AES_Dec(c[i]) XOR c[i-1]  
```

and the IV is discarded.

## Solution

If we replace `IV` by `IV XOR D`, the corresponding first block of the
plaintext will be decoded as `m[0] XOR D`. We can therefore XOR our IV with
the corresponding values to change 9999 into 0000. When the server will
decrypt our ciphertext, it will read `access=0000`.

```python  
token =
'606af8cd5c376066077ce589997aa89602a98905e123243aa4591a2291e4909e71cab0734fff1e71c21fee3f5e71a480'  
token = bytes.fromhex(token)

iv = token[:16]  
ct = token[16:]

for i in range(7,11):  
   iv = iv[:i] + bytes([(iv[i] ^ ord('0') ^ ord('9'))]) + iv[i+1:]

print(iv.hex())  
print(ct.hex())  
```

Flag: `ractf{cbc_b17_fl1pp1n6_F7W!}`

Original writeup (https://github.com/apoirrier/CTFs-
writeups/blob/master/AwesomeCTF2020/Crypto/Access.md).