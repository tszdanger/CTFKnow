[First a disclaimer, we did not actually solve this challenge during the
competition, but the servers were left running...]

A server is provided: `nc 37.139.22.174 22555`

It greets us with the following text:  
```  
|-------------------------------------|  
| Welcome to the Yunnyit crypto task! |  
|-------------------------------------|  
| Options:                            |  
| [M]ixed encryption function of FLAG |  
| [D]ecrypting cipher                 |  
| [E]ncryption & decryption function  |  
| [F]LAG encrypting...                |  
| [Q]uit                              |  
|-------------------------------------|  
Submit a printable string X, such that sha256(X)[-6:] = 92730d  
```

Option `M` outputs:  
```  
def EFoF(self, suffix, prefix):  
   assert len(FLAG) == 32  
   assert len(self.key) == 16  
   return AESCipher(self.key).encrypt(suffix + FLAG + prefix)  
```

and `E`:  
```  
def encrypt(self, raw):  
   iv = Random.new().read(AES.block_size)  
   digest = hmac.new(self.key, iv + raw, sha1).digest()  
   cipher = AES.new(self.key, AES.MODE_CBC, iv)  
   return b64encode(iv + cipher.encrypt(pad(raw + digest)))

def decrypt(self, enc):  
   enc = b64decode(enc)  
   iv = enc[:BLOCK_SIZE]  
   cipher = AES.new(self.key, AES.MODE_CBC, iv)  
   plain = unpad(cipher.decrypt(enc[BLOCK_SIZE:]))  
   raw, digest = plain[:-20], plain[-20:]  
   if hmac.new(self.key, iv + raw, sha1).digest() == digest:  
       return raw  
   else:  
       raise Exception  
```

A quick websearch for `AESCipher` leads us to [some
code](https://gist.github.com/swinton/8409454).  
Hence, we can presume that  
```python  
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)  
unpad = lambda s : s[0:-ord(s[-1])]  
```

Using option `F`, we can enter a nonempty `prefix` and `suffix` and the server
returns `iv + enc(iv, k, suffix + flag + prefix + hmac + padding)` [sic].

With `D`, we can let the server decrypt some ciphertext.  
The server responds with `What?????`, `Great job :D` or `Catch FLAG if you can
:P`.  
We will use these outputs to construct an oracle.  
`What?????` is returned if the ciphertext is either not valid base64 or its
length is not a multiple of 16.  
This is of no use to us.

One might think that `Catch FLAG if you can :P` is returned if the HMAC
validation fails, but that is not the case here.  
In fact, it seems like the given `decrypt` function is not used at all.  
If it were used, we could exploit the naive `unpad` function for a POODLE-like
attack (I only learned about POODLE because it is mentioned in the flag...).  
Decryption rather seems to be done with a function like this:

```  
def decrypt2(self, enc):  
   enc = b64decode(enc)  
   iv = enc[:BLOCK_SIZE]  
   cipher = AES.new(self.key, AES.MODE_CBC, iv)  
   plain = cipher.decrypt(enc[BLOCK_SIZE:])  
   return "Great job :D" if FLAG in plain else "Catch FLAG if you can :P"  
```

This function is also vulnerable.  
But first, let us write the code to interact with the server.

```  
class YunnyIt:  
   def __init__(self):  
       self.p = remote("37.139.22.174", 22555)

   def proof_of_work(self):  
       def check(target, i):  
           s = str(i)  
           if hashlib.sha256(s).hexdigest()[-6:] == target:  
               return s

       line = self.p.readline_contains('Submit a printable string X, such that sha256')  
       target = re.search(' = ([0-9a-f]{6})', line).group(1)  
       s = search(target, check, 4)  
       self.p.sendline(s)

   def encrypt(self, prefix, suffix):  
       self.p.sendline('F')  
       self.p.sendline(prefix)  
       self.p.sendline(suffix)  
       line = self.p.readline_startswith('Mixed encrypted FLAG =')  
       return base64.b64decode(re.search(' = (\S+)', line).group(1))

   def decrypt(self, c):  
       c = base64.b64encode(c)  
       self.p.sendline('D')  
       self.p.sendlineafter('Send the cipher please:\n', c)  
       return "Great job" in self.p.readline()

y = YunnyIt()  
y.proof_of_work()  
```

The `search` function is from our little library `bruteforce` which helps
parallelize such proof of work tasks:

```  
import multiprocessing

def _search(check, target, id, proc_count, queue):  
   res = None  
   i = id  
   while res is None:  
       res = check(target, i)  
       i += proc_count  
   queue.put(res)

def search(target, check, proc=multiprocessing.cpu_count()):  
   q = multiprocessing.Queue()  
   procs = [multiprocessing.Process(target=_search, args=(check, target, i,
proc, q)) for i in xrange(proc)]  
   for p in procs:  
       p.start()  
   res = q.get()  
   q.close()  
   for p in procs:  
       p.terminate()  
   return res  
```

Now, let `iv, c0, c1, c2` be the first four blocks of `y.encrypt('a', 'a')`.  
Notice that the plaintext for `c2` only contains the last byte of the flag,
which we know is `}`.  
For some ciphertext `c` let `p = dec(k, c)`, i.e., its "real" plaintext (like
in ECB mode).  
Then `y.decrypt(iv + c0 + c1 + c) == True` iff `p[0] ^ c1[0] == '}'`.  
Let us obtain for all bytes `b` a ciphertext `iv, c0, c1, c2` such that `c1[0]
== i`.

```  
def find_ciphertexts(from_file=True):  
   """for each byte b, find a valid ciphertext c with c[32] = b"""  
   if from_file:  
       return pickle.load(open('cs.p', 'rb'))

   cs = {}  
   while len(cs) < 256:  
       # encrypt plaintext: a | flag[0:15] || flag[15:31] || flag[31] | a | digest[0:14] || digest[14:20] | padding  
       c = y.encrypt('a', 'a')  
       b = ord(c[32])  
       cs[b] = c  
       print len(cs)

   pickle.dump(cs, open('cs.p', 'wb'))  
   return cs  

cs = find_ciphertexts()  
last_flag_byte = ord('}')  
```

Using our observations from the previous paragraph, we can find the first byte
of the real plaintext of any ciphertext block:

```  
def first_byte_of_real_plaintext(c):  
   """returns first byte of real plaintext, i.e. dec(k, c)[0]"""  
   for i in xrange(256):  
       c2 = cs[i][0:48] + c  
       if y.decrypt(c2):  
           return i ^ last_flag_byte  # p[0] ^ i == last_flag_byte  
```

Finally, we can get the flag:

```  
def get_flag_byte(i):  
   """returns flag[i]"""  
   c = y.encrypt('a', 'a' * (16 - i % 16))  # pad s.t. a plaintext block
starts with flag[i]  
   block_index = 2 if i < 16 else 3  
   block = c[block_index * 16:(block_index + 1) * 16]  
   b = first_byte_of_real_plaintext(block)  
   return b ^ ord(c[(block_index - 1) * 16])  # xor with previous block

for i in xrange(32):  
   sys.stdout.write(chr(get_flag_byte(i)))  
# ASIS{M1T!g473_TH3_p0od|E_nl;2$E}  
```

Original writeup (https://upbhack.de/posts/asis-2018-ctf-writeup-yunnyit/).