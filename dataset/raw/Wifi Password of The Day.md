# Wifi Password of The Day

Category: crypto

Description:  
```  
Our network admin likes to change the WiFi password daily. He's afraid someone
might crack it :) If you know the right AES key you can request the current
wifi password from the service listed below. Attached is a testing version of
the service. Perhaps there is a flaw you can exploit to retrieve the password?  
```

Endpoint: 0.cloud.chals.io:28931

Files: A python script "wifi.py"

---  
### Disclaimer  
I did not put parts of my solve script in the ctftime version of the writeup,
visit the Original Writeup link which points to my github repo to see the
script.

### Solution:

I analyzed the `wifi.py` script which turned out to be quite simple. Data
passed by the user was inserted into a JSON (`user` variable) which also
contained the flag (`current_wifi_password`):  
```python  
wifi_data = {"user:": user,  
            "pass:": current_wifi_password}

to_send = json.dumps(wifi_data)  
```  
The JSON string was later compressed using zlib, padded with zero bytes and
encrypted using AES-CBC-128 with an IV that was also all zero bytes:  
```python  
msg = zlib.compress(to_send.encode('utf-8'))

text_padded = msg + (AES.block_size - (len(msg) % AES.block_size)) * b'\x00'

logging.info("sending wifi password to user %s" + user)

iv = 16 * b'\x00'  
cipher = AES.new(encryption_key, AES.MODE_CBC, iv)

cipher_enc = cipher.encrypt(text_padded)  
return cipher_enc  
```  
The ciphertext was later returned to the user in base64 encoded form. I wrote
two simple shell scripts, `conn.sh` and `dump.sh` to connect to the remote and
to decode the cipertext from returned token respectively.

At first i thought this was some kind of a padding oracle because of IV and
padding being zero bytes. After trying out multiple plaintexts i realized that
compression made it very difficult, or even impossible, to derive information
from padding.

Later i started searching for vulnerabilities which targeted compressed data
being encrypted, which introduced me to the CRIME attack. The main two sources
i consulted were:  
 - [This](  
https://shainer.github.io/crypto/2017/01/02/crime-attack.html) explanation of
the attack  
 - [This](https://github.com/mpgn/CRIME-poc) POC in python  
  
I allowed myself to steal some code from the second source :) though in my
defense, i took some time to understand how it works first and introduced some
modifications of my own to better suit the challenge.

---  
### Brief explanation of the CRIME attack  
The core idea behind the CRIME attack is that many popular compression
algorithms, for instance the one used by zlib, are based on detecting
repetition and duplicate sequences in the data stream. For example, let the
data be:  
```  
AAAABCCCCDAABCD  
```  
During compression of data, the algorithm will keep track of a certain number
of previous bytes. When it arrives at `AABC` at the end, it will notice that
the sequence occured previously in the data stream, exactly 8 bytes before. It
will then encode that information as:  
```  
AAAABCCCCD[same 4 bytes as 8 bytes before]D  
```  
It just happens that information necessary to encode the `[same 4 bytes as 8
bytes before]` is shorter than the `AABC` sequence of bytes. This causes the
output to be shorter without loss of information which is the main benefit of
lossless compression.

Now, in a scenario where we know and control only part of the data this
feature may allow us to find out the rest of it. Consider the example from the
challenge. The JSON string which is being compressed may look similarly to
this (let's skip the encryption part for now):  
```json  
{"user:": "<our data here>", "pass:": "flag{this_data_is_of_interest}"}  
```  
Since we know that the flag begins with `flag{`, we can start our data with
that sequence, followed by possible characters, for instance `flag{a`,
`flag{b`, `flag{c` etc. As long as the character does **not** match, the
compressed output will look like this:  
```json  
{"user:": "flag{a", "pass:": "[same 5 bytes as 19 bytes
before]this_data_is_of_interest}"}  
```  
However, the moment we try `flag{t`, the "t" will also be included in the
repetition:  
```json  
{"user:": "flag{t", "pass:": "[same 6 bytes as 19 bytes
before]his_data_is_of_interest}"}  
```  
Both `[same 6 bytes as 19 bytes before]` and `[same 5 bytes as 19 bytes
before]` are encoded using the same number of bytes, but the remainder of data
is shorter since the repetition contains one more byte. In turn, the output of
compression is shorter. During bruteforce we may then infer whether we have
the correct character by inspecting the length of compressed data. We may then
repeat the process for further characters and brute force the flag one
character at a time.

Naturally, we could just decompress the data to retrieve the flag. The
information leak is crucial, however, when the data is encrypted after being
compressed. In many cases symmetric ciphers will produce ciphertext of exactly
the same length as the plaintext, which allows this channel of information
(length of data) to break encryption. This behaviour is present in all stream
ciphers, and may be present in block ciphers as long as they are used with an
encryption mode that effectively turns it into a stream cipher, such as CTR,
OFB, CFB etc.

### The problem with CBC  
The challenge uses the CBC mode, which does **not** turn the block cipher into
a stream cipher. The plaintext is padded with zeroes before being encrypted.
Because of this, different sequences of data with different length of
compression may result in ciphertext of the same length.

To fix that issue, we must add some padding to our plaintext - just enough to
break the block boundary. We may generate random characters (random enough to
make sure that they will not be compressed by the algorithm) and prepend them
to our `flag{` until the result gets longer. Once that happens, we know that
we need **one less** characters than that. Once again let us look at an
example to see why. Assume that the text we know is equal to `flag{` and that
padding `%^;#@` makes us cross the block boundary:  
```json  
{"user:": "%^;#@flag{", "pass:": "[5 bytes 18
before]this_data_is_of_interest}"}  
```  
Assuming none of the padding bytes were compressed, removing a single
character from it should result in ciphertext thats 1 byte below the block
boundary:  
```json  
{"user:": "%^;#flag{", "pass:": "[5 bytes 18
before]this_data_is_of_interest}"}  
```  
Now, each **incorrect** character guess will make the cipertext longer, due to
the fact that 1 byte is enough to break the block boundary:  
```json  
{"user:": "%^;#@flag{a", "pass:": "[5 bytes 18
before]this_data_is_of_interest}"}  
```  
A correct guess, however, will not make the data longer so the block boundary
will be still 1 byte away, resulting in unchanged ciphertext length:  
```json  
{"user:": "%^;#@flag{t", "pass:": "[6 bytes 18
before]his_data_is_of_interest}"}  
```  
This way we can carry out the attack even when padding is in the way.

### The 'Two Tries' method  
The algorithm may still be susceptible to false-positives. The "Two Tries"
method is used to mitigate this. It is described very well in the [BREACH
attack
paper](http://breachattack.com/resources/BREACH%20-%20SSL,%20gone%20in%2030%20seconds.pdf)
in section 2.4. I will attempt to explain my understanding of the method very
briefly, although i still recommend the abovementioned paper as the more
credilbe source.

False-positives may arise if the known portion of the guess (`flag{`) and the
brute-force character guesses are both comrpessed, but separately. It may
happen if we just so happen to "hit" a byte sequence that is present somewhere
else in the same string when brute-forcing. To mitigate this, two guesses are
performed with the use of additional data, that is guaranteed to not be
compressed.

In my `solve.py` script i used a string `~#:/[|/`, stolen from [the
PoC](https://github.com/mpgn/CRIME-poc) since it mostly contains characters
absent from the flag.  
The two guesses contain data in different order, first once attempts to
encrypt `flag{` + guessed character sequence + `~#:/[|/`, while the other
encrypts `flag{` + `~#:/[|/` + guessed character sequence. If length of both
ciphertexts is the same, it means that `flag{` and guessed character sequence
were compressed separately and this marks a false-positive. If the characters
were guessed correctly, the ciphertexts will have different lengths. This
method is much more accurate and has better success rate than sending a single
request.  
### End of explanation  
---

Explanation of the attack is pretty much all there is to this challenge. After
i have understood how the attack performs, i wrote the `solve.py` script with
the help of the PoC linked earlier. I first tested it against the local copy
of the `wifi.py` script, and after it worked on test data i ran it against the
serer.

The alphabet chosen for the flag bruteforce was the one that majority of other
flags used. The flag prefix `flag{` was naturally given by the organizers. The
`encrypt_remote()` function sends in a guess at the login prompt to the server
and decodes the result from base64. It is then used first by
`adjust_padding()` which finds the correct padding for the block-boundary
break and later by the for loop wich performs the brute-force. After a closing
bracket is found in the brute-forced string, the loop ends and prints out the
flag.

At first i was not sure if it will be able do leak the entirety of the string,
so i ran it up until it read `flag{c0mpr3` and then ran it again, with known
part of the flag set to `c0mpr3`. I then repeated this process until i had the
entire flag. After cleaning the script up and testing it once again it turns
out that it succesfully leaks the entirety of the flag in one go:

```  
[msaw328]$ python solve.py  
[+] Opening connection to 0.cloud.chals.io on port 28931: Done  
sofar:  flag{  
b'KV}cGPD_iJbflag{_' 96 96  
b'KV}cGPD_iJbflag{}' 96 96  
b'KV}cGPD_iJbflag{a' 96 96  
b'KV}cGPD_iJbflag{b' 96 96  
b'KV}cGPD_iJbflag{c' 80 96  
b'KV}cGPD_iJbflag{c_' 96 96

< ... lots of brute-forcing later ... >

b'KV}cGPD_iJbflag{c0mpr3ssion_0r4cl3_FTR' 96 96  
b'KV}cGPD_iJbflag{c0mpr3ssion_0r4cl3_FTS' 96 96  
b'KV}cGPD_iJbflag{c0mpr3ssion_0r4cl3_FTT' 96 96  
b'KV}cGPD_iJbflag{c0mpr3ssion_0r4cl3_FTU' 96 96  
b'KV}cGPD_iJbflag{c0mpr3ssion_0r4cl3_FTV' 96 96  
b'KV}cGPD_iJbflag{c0mpr3ssion_0r4cl3_FTW' 80 96  
b'KV}cGPD_iJbflag{c0mpr3ssion_0r4cl3_FTW_' 96 96  
b'KV}cGPD_iJbflag{c0mpr3ssion_0r4cl3_FTW}' 80 96  
b'flag{c0mpr3ssion_0r4cl3_FTW}'  
[*] Closed connection to 0.cloud.chals.io port 28931  
```

### Flag: `flag{c0mpr3ssion_0r4cl3_FTW}`  

Original writeup
(https://github.com/msaw328/ctf_writeups/tree/master/2022/Tenable/wifi_password_of_the_day).