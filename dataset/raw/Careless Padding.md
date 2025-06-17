## The solve  
### Forge Same Plaintext Block  
Now let's look at other part of the challenge. You might notice that before
the flag is encrypted, it is wrapped in the json format. Now this is
interesting. Combined with the flag format, if we count the bytes that we
know, namely `{'win': 'hitcon{`,  that's 16 bytes, which is a full block! Is
this a hint to somthing?

As we mentioned in the previous section, the repeating tail are remove in the
first step. There are NO verification as to whether the tail is longer than a
full block. If we forge a block such that all the characters are the same, the
unpad method will remove the whole block, making the last plaintext byte in
the second to last block, and the indexed byte in the even previous block!

So lets first forge this last block. Since we have a know plaintext block, we
can xor the plaintext with the iv, and that will give us a all zero block when
decrypted. That's easy, what then?

### Leaking Top 7 Bits  
Think about the implication of having the last plantext byte in a different
block. For now we don't know what the last byte of the randomly decrypted
second to last block is, but lets assume we know X. Then by control the IV of
the thrid to last block, we can enumerate the indexed byte, and see when we
have a match. This sounds similar to the standard CBC oracle right? We're just
manipulating a byte in the middle block and not the padding bytes themselves.
Of course due to the nature of the padding, we can only leak the top 7 bits,
since the last bit will be ignored when verifying.

Back to the problem of not knowing X, we might notice that X itself is not
that important. We just need the lower half of it, as that will give us the
indexed byte. Since we know one full plaintext block, we can construct a
cipher text that looks like IV'\|CT\|IV'\|CT, so that it decrypts to
Y\*16\|random\|Y\*16. Now no matter what the X is, this should always
validate. You can then go through each byte in the first block and change it
to something different (like ^0xff) and see if it invalidate it this time. If
there is any, we found the lower half of X!

Of course to leak each position, we need to find 16 different Xs such that
every byte in the block is indexed. We can construct in total 256 different
versions of the same plaintext block, and each of them will randomly hit one
of the Xs. So the probably to not have every single X is a mere $(15/16)^{256}
\approx 6.67\times 10^{-8}$. With the Xs known, we can execute the plan above
and leak the lower 7 bits of the message.

### Leaking Low Bit  
How about the last bit? Here we'll use a different strategy. Even though we
never know the padding byte, if we brute force all 256 possible values, there
must be one hit, as long as we're actually permuting the indexed byte. So we
can manipulate the plaintext and guess if the currect byte is used as the
index or not. If after the bruteforce none of the bytes gives a valid padding,
then our assumptions of the indexing byte must be incorrect. I'd call this a
behavioral oracle, we're observing based on if there is 1 successful padding
or not within 256 oracles, and not a specific one.

In technically, this will only give us if the byte are the same as the
previous byte, so we will still need one pivot point. From the previous step
we know a method to extract the lower 4 bit of a X, so we can use a similar
technique here. We just need to construct this once and we'll get one lower
bit.

> Note that I believe that there ways to using a similar construction as the
> previous step  
> (CT\|IV\|CT) to finish the whole step, but I'm too lazy and this is already
> efficient enough.

### IO Optimization  
After you implement everything, you'll notice the oracle complexity is O(256b
+ k) where b is the messag length in bytes and k is a startup overhead. If you
do one query at a time this will be painfully slow. The good thing is that for
a lot of these nc connected challenges, you can abuse the buffering and send
out a lot of querys at once before recieveing to reduce the networking
overhead. Notice that in both of the bruteforcing step, we pretty much need to
send out all the payload to get back a result anyway. So if we batch the input
and output, we can get a much faster query time. When testing, my script can
complete each oracle block in around 40 second with a server over sea.

### Flag!  
And with everything implemented, we now fire the exploit against the server
and get out sweet prize!  
`hitcon{p4dd1ng_w0n7_s4v3_y0u_Fr0m_4_0rac13_617aa68c06d7ab91f57d1969e8e8532}`  

Original writeup
(https://bronson113.github.io/2023/09/08/hitconctf-2023-careless-
padding.html).