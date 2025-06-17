# Double Message Writeup

### Defenit CTF 2020 - Crypto 201 - 67 solves

> Here is output of Double.sage. Catch The Flag.

#### Analysis

The challenge setting/exploit code is almost identical on this [awesome
writeup: Confidence CTF 2015 rsa1](http://mslc.ctf.su/wp/confidence-
ctf-2015-rsa1-crypto-400/).

#### Coppersmith's short pad attack + Franklin-Reiter related message attack

The only part to modify from original writeup is the solution size argument
for sage's `small_root()` function.

Two messages `M1`, `M2` are generated as below.

```python  
M1 = Flag + md5(Flag).digest()  
M2 = Flag + md5(b'One more time!' + Flag).digest()  
```

To apply [Coppersmith's short pad
attack](http://en.wikipedia.org/wiki/Coppersmith%27s_Attack#Coppersmith.E2.80.99s_Short_Pad_Attack),
knowing length of padding is necessary. Fortunately, md5 is used for padding,
having length of 16 bytes or 128 bits. Give this information to `small_root()`
function like below.

```python  
roots = h.small_roots(X=2**128, beta=0.3)  
diff = roots[0]  
```

Difference of plaintexts(`diff`) is known. Apply [Franklin-Reiter related
message attack](http://en.wikipedia.org/wiki/Coppersmith%27s_Attack#Franklin-
Reiter_Related_Message_Attack) and get flag:

```  
Defenit{Oh_C@Pp3r_SM1TH_SH0Rt_P4D_4TT4CK!!_Th1S_I5_Ve12Y_F4M0US3_D0_Y0u_UnderSt4Nd_ab@ut_LLL_AlgoriTHM?}  
```

Original problem: [double.sage](double.sage), [out.txt](out.txt)

Exploit code: [solve.sage](solve.sage) with [config.py](config.py)  

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2020/Defenit/Double_Message).