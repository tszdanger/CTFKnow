# storagespace Writeup

### Facebook 2019 - crypto 919 - 31 solves

> In order to fit in with all the other CTFs out there, I've written a secure
> flag storage system!  
It accepts commands in the form of json. For example: help(command="flag")
will display help info for the flag command, and the request would look like:  
`{"command": "help", "params": {"command": "flag"}}`  
`flag(name: Optional[str])`  
`Retrieve flag by name.`  
`{"command": "flag", "params": {"name": "myflag"}}`  
`flag{this_is_not_a_real_flag}`  
You can access it at nc challenges.fbctf.com 8089  
P.S. some commands require a signed request. The sign command will take care
of that for you, but no way you'll convince me to sign the flag command xD

#### Observations

To get flag,

1. Execute `sign(command="spec")`: Get spec of signing algorithm by command  
2. Execute `sign(command="list")`: Get flag file name `file_name` by command  
3. Execute `sign(command="info")`: Get ECC curve parameters(`a`,`b`,`p`,Generator `G`,Public Key `H`)  
4. Obtain secret key `key`, which satisfies `key * G == H`  
5. Generate message `flag(name=file_name)`.  
6. Sign message obtained at step 5 and get sign pair `(r, s)` using `key` and signing algorithm obtained in step 1.  
7. Update signed message with sign pair `(r, s)` and execute it.  
8. Get the flag

So, how do I get the secret key `key`?

#### Vulnerability: Order of curve is small

The order of the given curve is small enough to solve
EC[DLP](https://en.wikipedia.org/wiki/Discrete_logarithm). Sagemath has
`discrete_log()` method to solve ECDLP. The challenge had timeout of 2
minutes, but Sagemath was powerful enough(using [Pohlig-
Hellman](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm)
algorithm) to solve it just in time. You also can manually solve ECDLP using
this [code](https://github.com/hgarrereyn/Th3g3ntl3man-CTF-
Writeups/blob/master/2017/picoCTF_2017/problems/cryptography/ECC2/ECC2.md). I
get the flag:

```  
fb{random_curves_are_not_safe?}  
```

exploit driver code: [solve.py](solve.py)

ECDLP solver: [ECDLP.sage](ECDLP.sage)

Some logs while interacting: [help.log](help.log), [server.log](server.log)

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2019/Facebook/storagespace).