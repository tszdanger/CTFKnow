# Secure Protocol

So, there's a secret `msg`, and we are given `salt1, salt2, h` such that:  
```  
h = sha1(salt1 + msg + salt2})  
```

and we are tasked with finding `salt1', salt2', h'` such that:  
```  
1. salt1 != salt1'  
2. salt2 != salt2'  
3. h != h'  
4. h' = sha1(salt1' + msg + salt2' + s3})  
```

Note: We may assume `s3` as a given variable since it only changes every
minute.

Let's assume we weren't required to meet condition #1. In that case, we could
mount a length extension attack:  
- We have a suffix of the original message: `salt2`  
- We have the hash value of the message ending in that suffix: `h`  
- We are trying to compute hash of an extended string ending with `s3`

And an length extension attack gives us just that. [This SO
answer](https://crypto.stackexchange.com/a/3979/4449) does a good job of
explaining how the attack works.

But how about the 1st condition `salt1 != salt1'`? A minor yet important
detail is that we are not passing value of the salts directly, but rather in
`base64`ed encoding. So, we can easily pad the string with a `=` and while our
input string will change, the resulting decoded value won't. Hence we bypass
the `salt1 != salt1'` check.

Another minor detail: There's a WAF that limits the number of requests you can
make during a time interval. But it's not a big deal since you can wait
between subsequent requests, and you will find the flag on message length = 64
anyway.

```  
Wow, you have it! Flag: S4CTF{HasH_4nd_ba5e64_ok_0k_ok}  
```