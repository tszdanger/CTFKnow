# AESy (crypto, 471p)

In the task we can access a server, which allow us to encrypt messages, and
also send encrypted messages to Alice.  
We also get the ciphertext of encrypted flag.

If we send message to Alice two things can happen:

1. Either the response contains `!`, if we send a valid message we created using the system  
2. Or the response contains `?`, if we send broken message

If we look closely at encrypted messages and their length, we can see that:

1. There is one additional block present all the time   
2. The block length is 16 bytes  
3. Our inputs cause doubled response length

This all lead us to conclusions that we have some CBC encryption there and
that our inputs are hex-encoded before encryption.

We can confirm the CBC hypothesis by sending carefully forged message to
Alice:

1. Encrypt `aaaaaaa`, which should become 14 bytes hex-encoded, and thus padding would be `\2\2`  
2. Flip last byte of the first block (which we expect to be IV) by `^2^1`, which should flip the last byte of plaintext, after decryption, into `\1` which is valid padding

For such message we get back `!` and not `?`, which confirms our hypothesis.  
This also means we have a classic CBC padding oracle.

We create oracle function:

```python  
def oracle(s, ct):  
   data = receive_until_match(s, "Enter your choice:\n")  
   send(s, "2")  
   data = receive_until_match(s, "Enter the ciphertext\(hex-encoded\):\n")  
   send(s, ct)  
   response = receive_until_match(s, "\n\n")  
   return '??' not in response  
```

And we run the solver:

```python  
def main():  
   port = 7004  
   host = "crypto.byteband.it"  
   s = nc(host, port)  
   data = receive_until_match(s, "Enter your choice:\n")  
   print(data)  
   send(s, "3")  
   data = receive_until_match(s, "Here is your ciphertext\(hex-encoded\):\n")  
   flag = receive_until(s, "\n")[:-1]  
   print('flag', flag)  
   print(oracle_padding_recovery(flag, lambda ct: oracle(s, ct)))  
```

After a while we get back hex-encoded flag:
`flag{th3_0racl3_0nly_gu1de$_7he_1337}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-04-12-ByteBanditsCTF/aesy/README.md).