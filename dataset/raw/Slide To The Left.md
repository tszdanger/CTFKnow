# Slide To The Left  
__Category__: Crypto  
__Points__: 350

> Welcome to the AES-CBC oracle!  
> Our oracle's function is AES-CBC.  
> The oracle is found at umbccd.io:13373, and your methods are:  
> - flg - returns the encrypted flag  
> - enc - returns the encryption of the message after the : in "enc:..."  
>          as 16 bytes of initialization vector followed by the ciphertext.  
> - dec - returns the decryption of the ciphertext after the : in "dec:<16
> bytes iv>..."  
>          as a bytes string.  
>  
> \@author: pleoxconfusa  

### Overview  
I used the same method as in [Right Foot Two
Stomps](../Right%20Foot%20Two%20Stomps)  
(a simplified version of a padding-oracle attack).  
I only needed to adjust the IV to  
```python  
b'\x94\xd0g\xa3e\xb5\x1d\xa0X\x9f\x8b\xa2\xeeg\xfd\xd6'  
```  
and the encrypted flag to  
```python  
b'z\x8d4A\xfd<\'\x8d4\xf0\xaf\xef]\xb6\xd2\x88\x1b\x1b\xce\x9b\xa1\xb4\xf5!\xd3M\xcf*Ge\x15\x04\xfb$\xa5\x18\x1d\xef?\xea\xbe\xa8/U\x88\xe70\xa9E\x8a\xd7@\xe3\nl\xa3\xcb\xa7\xd00\x17\x9ew\x99U\x90\xb7\xe8u\xc2\xbf:\x0e\xa8\xf5"\x83\x0f\xe0\xa3$\xb3I\x03\x11\xfd\xcbc\xd6cE\x85\xad\xb2K\x07'  
```  
[See the last writeup for an explanation.](../Right%20Foot%20Two%20Stomps)

### Profit  
[solve.py](./solve.py) implements the attack described in the last writeup and
you get the flag  
```  
DawgCTF{@_Ch4IN_i2_N0_S7R0n93R_7H4N_i72_W34k3S7_L!NK_4nD_lif3_!2_Af73r_4Ll_@_Ch4IN.}  
```  

Original writeup (https://github.com/potato-
gang/DawgCTF/tree/master/Slide%20To%20The%20Left).