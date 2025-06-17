Original writeup:
[http://toh.necst.it/hitconquals2017/crypto/Secret_Server_Revenge/](http://toh.necst.it/hitconquals2017/crypto/Secret_Server_Revenge/)

-----

This challenge naturally follows from Secret Server, of which you can find a
writeup [here](http://toh.necst.it/hitconquals2017/crypto/Secret_Server/).

We are given
[another](http://toh.necst.it/writeups_files/secretserverrevenge/secretserver.py)
python script, which pretty much resembles the first one from Secret Server.

What has changed? This time the server won't provide us with the ciphertext
for the flag, but we will instead need to find the value of a 56-byte random
token. If we prove to the server that we know its value, it will kindly give
us the flag in exchange.

To complicate things further, we are only allowed to send 340 requests before
the connection is closed and the token reset.

It's obvious that our previous approach will not work, since it required up to
256 request per character. We need to find a different way to solve this.

## A different approach

Trying to find a character at a time is a good technique.  
The problem is that we can't send 256 requests for every single character. We
would like to have, if possible, an oracle that can immediately reveal to us
the value of a byte, with a single request.

Let's look around and try to find something like this. To start, let's just
think about everything that could give us information about the value of
unknown plaintexts.

Recall: the `unpad` method can unpad up to 256 characters, depending on the
value of the last byte of the last block. Good! If we can recognize how many
of the characters have been unpadded, this means that we immediately know the
value of the last byte! (without making any additional requests)

### Finding how many of the bytes have been unpadded

We need a way to distinguish among all 256 possible lengths at which the
plaintext has been cut.

This is how we can do it: we craft a long, fixed message (longer than 256
bytes). We then replace the beginning of the message with `get-md5`, so that
the server will return to us the encrypted hash of the decrypted and unpadded
message.

We can then append any block we want to this fixed message. Whatever the
additional block is, the first part of the message will stay the same.
Depending on the decrypted value of the last byte of the block we append, the
fixed message will be cut at different positions after unpadding.  
The server will then reply with the encrypted hash of the truncated fixed
message, which is indipendent of the block we appended, and only depends on
the value of the last byte.  
We can use `unpad` as an oracle!

(Note: to preserve the original plaintext of the added block we will also have
to add the block before it)

NB: if the unpadding comes short of removing the added blocks, the MD5 hash
will include part of them, thus returning an unknown ciphertext. We can avoid
this problem by recognizing this case, flipping the most significant bit on
the last byte and making it fall in our preferred range.

This method has a limitation though: we can only find the value of the last
byte of a block. This is therefore not enough to discover the value of the
token.

### Generalizing to characters in every position

We can bypass the issue of only knowing the last byte of each block with some
creativity.

We can move to a different problem: instead of finding the characters of the
tokens at every index (which is currently impossible) we can obtain the
encrypted MD5 hash of the token, truncated at every possible index, then find
the last character of the hashes.

(Note: this is possible since the MD5 hash is a raw digest, not a hexdigest,
thus the last byte can assume any of the 256 ASCII values.)

Knowing the last byte of the hashes, it is trivially possible to find all the
preimages with a hash that ends with the same character. As before, we can
proceed one character at a time.

Collisions on a single byte are possible, but we can just keep all possible
candidates and gradually reduce the number later.

## The attack

The complete attack is something like this:  
- Collect the encrypted MD5 hashes for every truncation of the token (56 requests)  
- Send the long fixed message (starting with `get-md5`) and get the encrypted MD5 hashes of the message at every unpadding length (256-32=224 requests)  
- Add each encrypted token MD5 hash to the end of the long fixed message, without the final padding block, send it to the server and check the reply (56 requests):  
 - if the resulting hash is one of the known ones, we know the value of the last byte of the MD5 hash of that cut of the token  
 - otherwise flip the most significant bit of the last byte and check again (i.e. send a new request)  
- Locally find all possible token candidates that produce the correct last byte when hashed.

At the end of this procedure we will have a list of possible values for the
token.

### How to reduce the pool of candidates

Since the possible candidates which satisfy the constraints on the last byte
of the hashes are usually more than one, we need to find a way to reduce their
number.

A simple idea is revealing the actual value of the last byte of every token
block, instead of using their hashes. We can do this for the first, second and
third block of the token. This is still usually not enough to uniquely
identify the token, but in practice the number of candidates is reduced to
less than 30 and often less than 10.

Since the whole attack requires around 300 requests we still have some leeway
to find other ways to shrink the amount of candidates, like using the SHA1
hashes. The effort though is not really worth it, since with a little testing
I found that the attack as it is already succeeds once every ~10 runs.

We just run it a few times and get our flag:
`hitcon{uNp@d_M3th0D_i5_am4Z1n9!}`

Appreciation to HITCON for the amazing challenge! The whole CTF was
challenging but rewarding, I will be waiting to play again next year :)

Here is the complete exploit. You can also download it from
[here](http://toh.necst.it/writeups_files/secretserverrevenge/exploit.py).

```python  
from pwn import *  
import base64, random, string  
from Crypto.Hash import MD5, SHA256

def pad(msg):  
 pad_length = 16-len(msg)%16  
 return msg+chr(pad_length)*pad_length

def unpad(msg):  
 return msg[:-ord(msg[-1])]

def xor_str(s1, s2):  
 '''XOR between two strings. The longer one is truncated.'''  
 return ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(s1, s2))

def blockify(text, blocklen):  
 '''Splits the text as a list of blocklen-long strings'''  
 return [text[i:i+blocklen] for i in xrange(0, len(text), blocklen)]

def flipiv(oldplain, newplain, iv):  
 '''Modifies an IV to produce the desired new plaintext in the following
block'''  
 flipmask = xor_str(oldplain, newplain)  
 return xor_str(iv, flipmask)

def solve_proof(p):  
 instructions = p.recvline().strip()  
 suffix = instructions[12:28]  
 print suffix  
 digest = instructions[-64:]  
 print digest  
 prefix = ''.join(random.choice(string.ascii_letters+string.digits) for _ in
xrange(4))  
 newdigest = SHA256.new(prefix + suffix).hexdigest()  
 while newdigest != digest:  
   prefix = ''.join(random.choice(string.ascii_letters+string.digits) for _ in
xrange(4))  
   newdigest = SHA256.new(prefix + suffix).hexdigest()  
 print 'POW:', prefix  
 p.sendline(prefix)

HOST = '52.192.29.52'  
PORT = 9999  
welcomeplain = pad('Welcome!!')

# retry until we guess the token correctly among the candidates  
while 1:  
 try:  
   p = remote(HOST, PORT)  
   solve_proof(p)

   # get welcome  
   welcome = p.recvline(keepends=False)[13:]    # remove prompt  
   print 'Welcome:', welcome  
   welcome_dec = base64.b64decode(welcome)  
   welcomeblocks = blockify(welcome_dec, 16)

   # get command-not-found  
   p.sendline(welcome)  
   notfound = p.recvline(keepends=False)  
   print 'Command not found:', notfound

   # get encrypted token  
   payload = flipiv(welcomeplain, 'get-token'.ljust(16, '\x01'),
welcomeblocks[0])  
   payload += welcomeblocks[1]  
   p.sendline(base64.b64encode(payload))  
   token = p.recvline(keepends=False)  
   print 'Token:', token  
   token_dec = base64.b64decode(token)  
   tokenblocks = blockify(token_dec, 16)  
   tokenlen = len(token_dec) - 16

   # get encrypted md5 for the token, cut at every possible index, from 8 to
the end  
   print ''  
   print 'Collecting encrypted md5 hashes...'  
   tokenmd5s = []  
   for i in range(56):  
     # replace first 7 characters with 'get-md5'  
     payload = flipiv('token: '.ljust(16, '\x00'), 'get-md5'.ljust(16, '\x00'), tokenblocks[0])  
     payload += ''.join(tokenblocks[1:])  
     # add a block where we control the last byte, to unpad at the correct length ('token: ' + i characters)  
     payload += flipiv(welcomeplain, 'A'*15 + chr(16 + 16 + tokenlen - 7 - 1 - i), welcomeblocks[0])  
     payload += welcomeblocks[1]  
     p.sendline(base64.b64encode(payload))  
     md5_enc = p.recvline(keepends=False)  
     print i, md5_enc  
     tokenmd5s.append(md5_enc)

   # get the ciphertexts of the md5 hashes of a fixed message for every
unpadding length from 32 to 255  
   # these will be used as oracles to guess the amount that was unpadded  
   # we can reuse some of the ciphertexts we obtained before  
   print ''  
   print 'Collecting md5 oracles...'  
   oraclemd5s = {}    # key = md5ciphertext, value = unpadding amount

   # we will craft a message longer than 256 bytes to check the unpadding up
to 256 characters  
   for unpad in range(32, 209):  
     # 1 block  
     payload = flipiv('token: '.ljust(16, '\x00'), 'get-md5'.ljust(16, '\x00'), tokenblocks[0])  
     # 1 + 4 = 5 blocks  
     payload += ''.join(tokenblocks[1:])  
     # 5 + 11 = 16 blocks  
     payload += 'A' * 16 * 11    # padding to reach 256 characters  
     # 16 + 1 = 17 blocks  
     payload += flipiv(welcomeplain, chr(unpad).rjust(16, '\x00'), welcomeblocks[0])    # replace last byte  
     # 17 + 1 = 18 blocks  
     payload += welcomeblocks[1]

     p.sendline(base64.b64encode(payload))  
     md5_enc = p.recvline(keepends=False)  
     print unpad, md5_enc  
     oraclemd5s[md5_enc] = unpad

   # we can reuse the ciphertexts when the additional crafted message is
unpadded away  
   for unpad in range(209, 256):  
     md5_enc = tokenmd5s[8 + 1 + 255 - unpad]  
     print unpad, md5_enc  
     oraclemd5s[md5_enc] = unpad

   # send token md5 hashes without padding block, compare unpadding to known
ciphertexts  
   print ''  
   print 'Revealing last byte for each md5 hash...'  
   candidates = ['']  
   for index in range(56):  
     # send the same crafted message as before, but replace last block with the md5 ciphertext  
     payload = flipiv('token: '.ljust(16, '\x00'), 'get-md5'.ljust(16, '\x00'), tokenblocks[0])  
     payload += ''.join(tokenblocks[1:])  
     payload += 'A' * 16 * 11  
     payload += base64.b64decode(tokenmd5s[index])[:-16]    # send whole md5 ciphertext without padding  
     p.sendline(base64.b64encode(payload))

     print index  
     res = p.recvline(keepends=False)  
     print "received:", res

     # if the ciphertext is in oraclemd5s, we know the last byte of the md5 hash  
     if res in oraclemd5s:  
       lastbyte = oraclemd5s[res]  
       print 'Found byte:', hex(lastbyte)  
       newcandidates = []  
       for x in candidates:  
         for c in range(256):  
           if MD5.new(x + chr(c)).digest()[-1] == chr(lastbyte):  
             newcandidates.append(x + chr(c))  
       candidates = newcandidates

     # if the ciphertext is the one for 'command not found', the plaintext was completely unpadded  
     # the last byte is 0 (plain = plain[:-0] -> '')  
     elif res == notfound:  
       print 'Command not found -> 0'  
       lastbyte = 0  
       newcandidates = []  
       for x in candidates:  
         for c in range(256):  
           if MD5.new(x + chr(c)).digest()[-1] == chr(lastbyte):  
             newcandidates.append(x + chr(c))   
       candidates = newcandidates

     # if we haven't seen the ciphertext before, the unpadding included the last 2 blocks  
     else:  
       print 'Not found. [1-32]'

       # flip most significant bit of last byte to move it in a good range  
       newpayload = payload[:-17] + xor_str(payload[-17], '\x80') + payload[-16:]  
       p.sendline(base64.b64encode(newpayload))  
       res = p.recvline(keepends=False)

       # check, same as before  
       if res in oraclemd5s:  
         lastbyte = oraclemd5s[res] ^ 0x80  
         print 'Found byte:', hex(lastbyte)  
         newcandidates = []  
         for x in candidates:  
           for c in range(256):  
             if MD5.new(x + chr(c)).digest()[-1] == chr(lastbyte):  
               newcandidates.append(x + chr(c))   
         candidates = newcandidates  
       elif res == notfound:  
         print 'Command not found -> 0'  
         lastbyte = 0 ^ 0x80  
         newcandidates = []  
         for x in candidates:  
           for c in range(256):  
             if MD5.new(x + chr(c)).digest()[-1] == chr(lastbyte):  
               newcandidates.append(x + chr(c))   
         candidates = newcandidates  
       else:  
         raise AssertionError("Something went wrong, couldn't identify byte.")

   print ''  
   print 'Candidates:'  
   print candidates  
   print 'No. of candidates:', len(candidates)

   # if there's more than one candidate, we can remove some of them  
   if len(candidates) > 0:  
     print ''  
     print 'Reducing number of candidates...'  
     # get characters no. 8, 24, 40, at the end of each token block  
     for block in range(3):  
       index = 8 + block * 16  
       # send same crafted message as before, but with one of the token blocks at the end (to find its last byte)  
       payload = flipiv('token: '.ljust(16, '\x00'), 'get-md5'.ljust(16, '\x00'), tokenblocks[0])  
       payload += ''.join(tokenblocks[1:])  
       payload += 'A' * 16 * 11  
       payload += tokenblocks[block]  
       payload += tokenblocks[block + 1]  
       p.sendline(base64.b64encode(payload))

       print 'Byte at:', index  
       res = p.recvline(keepends=False)  
       print "received:", res

       # same checks as before  
       if res in oraclemd5s:  
         lastbyte = oraclemd5s[res]  
         print 'Found byte:', hex(lastbyte)  
         candidates = filter(lambda x: x[index] == chr(lastbyte), candidates)  
         print 'Candidates:'  
         print candidates  
       elif res == notfound:  
         print 'Command not found -> 0'  
         lastbyte = 0  
         candidates = filter(lambda x: x[index] == chr(lastbyte), candidates)  
         print 'Candidates:'  
         print candidates  
       else:  
         print 'Not found. [1-32]'  
         # flip most significant bit of last byte to move it in a good range  
         newpayload = payload[:-17] + xor_str(payload[-17], '\x80') + payload[-16:]  
         p.sendline(base64.b64encode(newpayload))  
         res = p.recvline(keepends=False)

         if res in oraclemd5s:  
           lastbyte = oraclemd5s[res] ^ 0x80  
           print 'Found byte:', hex(lastbyte)  
           candidates = filter(lambda x: x[index] == chr(lastbyte), candidates)  
           print 'Candidates:'  
           print candidates  
         elif res == notfound:  
           print 'Command not found -> 0'  
           lastbyte = 0 ^ 0x80  
           candidates = filter(lambda x: x[index] == chr(lastbyte), candidates)  
           print 'Candidates:'  
           print candidates  
         else:  
           raise AssertionError("Something went wrong, couldn't identify byte.")

   print ''  
   print 'Candidates left:', len(candidates)

   # if we didn't narrow down the candidates to a single one, we will just
send the first one  
   token = candidates[0]

   # send token and get flag  
   payload = flipiv(welcomeplain, 'check-token'.ljust(16, '\x01'),
welcomeblocks[0])  
   payload += welcomeblocks[1]  
   p.sendline(base64.b64encode(payload))

   print ''  
   print p.recvline(keepends=False)    # 'Give me the token!'  
   print 'Sending token...'  
   p.sendline(base64.b64encode(token))  
   flag = p.recvline(keepends=False)  
   print 'Flag:'  
   print flag

   with open('flag', 'w') as f:  
     f.write(flag)

   exit(0)

 # if the token was not correct, try again  
 except EOFError:  
   print 'Failed! Trying again...'  
   print ''  
   p.close()  
   continue  
```

Original writeup
(http://toh.necst.it/hitconquals2017/crypto/Secret_Server_Revenge/).