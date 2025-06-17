# Easy RSA 1 Writeup

### ISITDTU Quals 2019 - crypto 100 - 72 solves

> Let's warm up with RSA

#### Observations

Parameters `n`, `e`, `c` were given [here](config.py). I immediately observe
that public exponent `e` is so large(1023 bits), almost as large as `n`(1024
bits).

#### Vulnerability: `n` and `e` have almost same bit length

Since `n` and `e` have similar size, I apply [Boneh-Durfee
attack](http://antoanthongtin.vn/Portals/0/UploadImages/kiennt2/KyYeu/DuLieuNuocNgoai/8.Advances%20in%20cryptology-
Eurocrypt%201999-LNCS%201592/15920001.pdf). Nice implementation of the attack
can be found [here](https://github.com/mimoo/RSA-and-LLL-
attacks/blob/master/boneh_durfee.sage). Private key `d` is recovered less than
a second. I get the flag:

```  
ISITDTU{Thank5_f0r_4tt3nd1ng_0ur_C0nt3st}  
```

Given parameters: [config.py](config,py), [task](task)

Exploit code: [solve.sage](solve.sage)

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2019/ISITDTU/Easy_RSA_1).