# Solution  
This problem revolves around a webserver with a few users. Each user has
access to their own files. The flag, as hinted  
in the description and code, is held by the admin. This account is disabled
because reasons.

Each user logs in with a password and gets a token that can be used to read
files. JWEs are "scary", so this uses a  
custom system. The user's name is encrypted in an AES-CTR mode with an IV,
Nonce, and a "MAC" at the end, which is  
simply a CRC of the plaintext.

The challenge is to get a regular user's access token and turn it into a valid
token for the admin.

## Initial Access  
First we need to get a valid token for a user. The pbkdf2 hashes are
available, which can be brute forced  
using john the ripper. The john the ripper format is a little weird -- here
are inputs that can be used:

```  
admin:$pbkdf2-sha256$1000$YWRtaW4$ei9EW6v/p1hHHjNBofrc6avv8ZSt7QceT9SLJa3YVqc  
azure:$pbkdf2-sha256$1000$YXp1cmU$ljF1gXXS8EjbGWRyetLv70IzCZuX84Pk8eEhyQDz5yI  
cthon:$pbkdf2-sha256$1000$Y3Rob24$mAgJsUgjUq5Zvl0.3khMCDW0aYUwmgSsG61wsioWdnA  
```

Or, googling "QDB-244321" should provide the knowledge that azure's password
is just "hunter2".

## Modification  
Next, we need to modify the token, changing the current user to the desired
user 'admin'. Luckily, the less privileged  
user names match that of the admin user, so we don't have to deal with length
changes.

The token format is:

   IV || USER || NONCE || MAC(CRC)

The USER, NONCE, and MAC(CRC) are encrypted with AES-CTR. The MAC(CRC) is
computed over the IV, USER, and NONCE.

CRCs have an interesting property that makes this attack possible (in
combination with AES-CTR mode)...

   CRC(A ⊕ B) = CRC(A) ⊕ CRC(B)

Where ⊕ is an XOR operation. For CRCs that have a non-zero result for an all-
zero message, we also need to XOR in  
the CRC of all zeros:

   CRC(A ⊕ B) = CRC(A) ⊕ CRC(B) ⊕ CRC(00...)

AES-CTR encryption is just an XOR of a secret value against the plaintext. So,
a bit flip in the ciphertext will  
result in a corresponding bit flip in the plaintext. We can therefore modify
parts of a message via an XOR and  
compute the necessary _change_ to the CRC. We do not have to know the original
CRC or any part of the message we do  
not want to modify.

## Script  
```  
import sys  
import urllib.request

import fastcrc

IV_LEN = 16  
NONCE_LEN = 42  
MAC_LEN = 8

def xor_bytes(first: bytes, second: bytes) -> bytes:  
   assert len(first) == len(second)  
   return bytes(a ^ b for a, b in zip(first, second))

def gen_mac(data: bytes) -> bytes:  
   # The server's CRC algorithm and bit packing method  
   crc = fastcrc.crc64.go_iso(data)  
   return int.to_bytes(crc, length=MAC_LEN, byteorder="big")

def hack_token(token: bytes, current_user: str, desired_user: str) -> bytes:  
   # And what do you know... "admin" and "azure" are the same length...  
   assert len(current_user) == len(desired_user)

   # These are not modified (just an XOR of zeros)  
   iv_xor = bytes(IV_LEN)  
   nonce_xor = bytes(NONCE_LEN)

   # Compute the change to the user field that we want to see  
   user_xor = xor_bytes(current_user.encode(), desired_user.encode())

   # Compute the change to the CRC/MAC we want to see  
   # Note that we can omit leading zeros if we want (iv_xor), but not
trailing.  
   mac_xor = xor_bytes(  
       gen_mac(iv_xor + user_xor + nonce_xor),              # CRC(the change)  
       gen_mac(bytes(len(iv_xor + user_xor + nonce_xor)))   # CRC(all zeros)  
   )

   # Modify the token and return  
   hacked_token = xor_bytes(token, iv_xor + user_xor + nonce_xor + mac_xor)  
   return hacked_token

def hack_the_planet(base_url: str) -> None:  
   azure_token_hex =
urllib.request.urlopen(f"{base_url}/auth?user=azure&password=hunter2").read().decode()  
   admin_token_hex = hack_token(bytes.fromhex(azure_token_hex), "azure",
"admin").hex()

   flag =
urllib.request.urlopen(f"{base_url}/read/flag.txt?token={admin_token_hex}").read().decode()  
   return flag

if __name__ == "__main__":  
   # Pass the base URL as the only argument  
   print(hack_the_planet(sys.argv[1]))  
```