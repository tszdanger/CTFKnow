# Thunderbolt

## Description

[Challenge](chall)

`nc crypto.2021.chall.actf.co 21603`

## Solution

First of all let's try to connect to this service

```console  
$ nc crypto.2021.chall.actf.co 21603  
Enter a string to encrypt: A  
c807cf076dddbc53cf17b5f26f87b879d219441b0ddf689789910fc8e130cf326279ecb3a850583fbc4b0cda4727bf5e3aa8a69d26d98b57  
```

So, the service take an input and return to us an encrypted text, let's try to
give bigger input and see if something happen

```console  
$ nc crypto.2021.chall.actf.co 21603  
Enter a string to encrypt:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
eb81340cc4ca477d21eb4dc81d077f2621589f2aa2f6d884d2d29f689c40f9d2bd40cdd2f53fd202052b627d46cab2f855a1d2c2496780574e19533e2eca8ab53b54338cebe0d2c83a372d46ab05d9ecf4f32682500c32a551dc5cc40e39c6aacc66f9064c4190c04fbb5b68190408ad608b4978a5539cc481652263a734af77bb6b82a889f4ebbad312b04fd68fd1e880754b779d563df4738c7dc4ad17f9a54b37b782555770d35fbfaa628631c43c7d  
```

The output is increased, but there is no repetition, but we can try to make
some other attempts

If we use `10 ** 4` A, we found something interesting...at the end of the
encrypted data there are a lot of `41` (A in hex), and after that there is an
hex encoded text

```  
616374667b77617463715f7468655f656467655f63617365805f3331623265623734343065363939f26365336633653562626431383447  
actf{watcq_the_edge_case._31b2eb7440e699òce3f3e5bbd184G  
```

Seems a lot like a corrupted flag, maybe we can try to send more character,
`10 ** 6` seems enough

```  
616374667b77617463685f7468655f656467655f63617365735f333162326562373434306536393932633333663365356262643138347d  
actf{watch_the_edge_cases_31b2eb7440e6992c33f3e5bbd184}  
```

#### **FLAG >>** `actf{watch_the_edge_cases_31b2eb7440e6992c33f3e5bbd184}`  

Original writeup (https://github.com/K1nd4SUS/CTF-
Writeups/tree/main/%C3%A5ngstromCTF_2021/Thunderbolt).