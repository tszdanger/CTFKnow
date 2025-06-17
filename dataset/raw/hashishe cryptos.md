# Hashishe Cryptos - Cryptography - 420 Points (haha)

Last week I decided to take part in BlazeCTF (haha get it? weed is so funny!
420 xd :P). I liked the crypto challenge offered by BlazeCTF, so I figured I
would make a full writeup, since one does not yet exist.

## Challenge Description:

While I no longer have access to what the challenge description was, it linked
to a remote encryption service.

## Lookin' at it

When we connect to the encryption service, we are fist given a bunch of values
relevant to some encryption scheme; then, we are given the encrypted flag.
Finally, we are given the opportunity to encrypt just one message of our
choice, before our connection ends. Notably, the parameters involved in each
encryption change upon reconnectiing.

My first intuition with the problem was to try buffer overflowing the message
input of the encryption service. After several minutes of poking at it,
however, I became convinced that this was not the way forward. Looking at the
way the problem is set up, it is clear that the weakness of the scheme lies in
our ability to encrypt a single arbitrary message. Perhaps we can craft a
specific message to leak unintended information about the system?

Before proceeding, I decided to identify the cryptographic scheme involved. We
are given paramters p, g, y, and two parts of an encryption: c1 and c2. The
fact that encrypted data comes in a pair (c1, c2) is a dead giveaway that the
encryption scheme is El Gamal. Working from there, g is most likely a
generator, and y is likely a randomly generated value used to calculate g^y
for encryption.

So what exactly do the encryption parameters of El Gamal mean? A quick Google
search yields the following:

c1 = g^x mod p

c2 = m * h^x = m * g^(x * y) mod p

In this case, g^(x * y) is a shared secret between the two parties. So, for
each use of the encryption service we get two encryptions: one of the flag,
and one of the arbitrary message. Since only the message changes, c1 will not
differ betwene them. However, c2 will differ (since the message has changed).
Namely,

c2\_old = m * g^(x * y) mod p

c2\_new = m' * g^(x * y) mod p

This is of course assuming that x and y get reused for each encryption
(spoiler alert: they do). Notice here that all we need to do to extract
message m is to find the inverse of g^(x * y) and multiply it to c2\_old. But
how can we extract g^(x * y)? Well, we know the message we used for the second
encryption; therefore we can find its inverse. If we multiply that inverse to
c2\_new, we can extract g^(x * y). Just like that, we have a working method
for snagging our flag. We will exploit the fact that a second message gets
encrypted after the flag with the same parameters used for x and y.

## Writin' the exploit

The solver.py file leverages pwntools and gmpy to generate a solver with our
exploit. First, we parse the incoming text from the encryption service and
grab some useful data. Since c1 is not useful, we only use c2, which is
renamed to target. Next, we encrypt any message of our chosing (in my case, a
single 'a' works). We will need to translate the message into an integer to
grab its inverse; finding the inverse is easily done with gmpy. Once the
inverse is found, it can be multiplied to our known encrypted message to grab
g^(x \* y).

With g^(x \* y) retrieved, all that is left to do is multiply its inverse to
the encrypted flag, and convert the resulting integer to a string. Doing so
yields the flag:

blaze{i_wuz_bl4z1n_s0_much_i_r3used_m4h_k3ys}

## Conclusions

This was a fun little challenge, and kept me busy for a good hour or so. The
folks who put on BlazeCTF did a good job, even if I disapprove of their *cough
cough* "blazing".  

Original writeup
(https://github.com/rkaldawy/writeups2019/tree/master/blaze/hashishe).