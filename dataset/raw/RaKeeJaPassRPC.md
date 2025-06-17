# RaKeeJaPassRPC (crypto, 466p, 9 solved)

## Description

In the task we get the [server source
code](https://raw.githubusercontent.com/TFNS/writeups/master/2020-09-25-BalCCon/RaKeeJaPassRPC/server.py)
and we even got a full
[client](https://raw.githubusercontent.com/TFNS/writeups/master/2020-09-25-BalCCon/RaKeeJaPassRPC/client.py)!  
We can also connect to remote server, where this server is running.

## Code analysis

I won't lie, the code looks pretty complex.  
There is some complicated DH-like key exchange logic with some special token
password, which by the power of math allows two sides to agree on a shared
secret which is used to encrytp the flag.

We spent some time going through the math here to understand how this all
works, but it's really not useful in the end.  
The critical part is:

```python  
key = sha256(f'{S:X}'.encode()).digest()  
```

AES key is generated from value `S`, which in turn comes from:

```python  
S = pow(A * pow(v, u, N), b, N)  
```

Where `A` is the value we provide to the server.

There is also a check on the value of:

```python  
M = sha256(f'{A:X}{B:X}{S:X}'.encode()).digest().hex()  
```

But `A` we provide, `B` is given to us by the server, hence again if we know
`S` we can compute this value easily.

## Vulnerability

Notice that the server never performs any checks on the value `A` we provided.  
It's simply taken directly into the computations.  
The issue here is similar to `invalid key` attacks.  
By using some special value, we can trick server into creating shared secret /
authentication challenge which can be bypassed without knowing the token.

If we look again at:

```python  
S = pow(A * pow(v, u, N), b, N)  
```

It should be pretty obvious that if we were to send `A = 0` the value of `S`
will also become `0`, regardless of all other parameters.

## Solver

We can just take the provided client, set `A = 0` and `S = 0` and run it to
get back the flag: `BCTF{y0u_w0uldnt_impl3m3nt_y0ur_0wn_crypt0}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-09-25-BalCCon/RaKeeJaPassRPC/README.md).