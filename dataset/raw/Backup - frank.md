Welcome folks,

This writeup is about Midnight Sun CTF frank challenge on how to recover a
full RSA private key, when half of it is erased.  
Challenge therefore requires recovering the entire RSA key from this image :

#### Get the part of the private key visible:

The first step of the challenge is to **recover the visible part**, to do this
I quickly created a small **OCR** script with the **pytesseract** module in
Python, to facilitate the recovery task.

```python  
import pytesseract

try:  
   import Image, ImageOps, ImageEnhance, imread  
except ImportError:  
   from PIL import Image, ImageOps, ImageEnhance

pytesseract.pytesseract.tesseract_cmd = 'C:\\Program Files\\Tesseract-
OCR\\tesseract.exe'

decode = pytesseract.image_to_string(r'C:\\Users\\Zeynn\\Desktop\\file.png')  
print(decode)  
```

Which gives:

```  
YZE7xr8bE94J04cqritOcE+d)4WOmt 4HvmhaSElywep9xN8xBucNSDnx1XtaMeb

me7udUNRVTDYHdFkv26P1K4Xhes8duRpQBES/TxN4YD42td2P8PCShLnvQ5JLWuY  
cCnYQa9wbEH8zL91x1lJne5+0Vc1Bd7X70ENRTxBHpYJg28m/cDeUs8KHUvlyeGHK  
gJGj ZIA03KXj vQzj OYWi/MGKCBLeeoVZOURKR7oP7Gxj ORF2DypmL F8r2374ulISy  
RHLKFQfW9TNO/ j 8L7DWm55d0cJOZr1kbDvxPAu2zLQKCAQEAWM/Hdvm8 rX6Q6C8A  
tYLA/+JvWsxLxGW4nL88dg 16 1RVWPz24PZZWPNQwb fWohay562+ccTxFMOrlxuDoH  
Dh7A4X45W0+MBJ bdYTSoVzFs1r1bj oPpwBnsL1pNAkC5zloQFUkmvpzBD6DaLx0i  
OhZtqsichyPGEyVHORYv2L3UPYAhdmeYbsbc6Ruhva9tVUUMc+nFyKf510s4vC8M  
YTnyYZJqo/50AR7wt6806Z1sTQowLbSPn1hYgtSka/RK+gBnKyFhmihi/Jy@gJNg  
T/p/Fb1DaX6s j nTpPbx fHXX9j 2ExC3uH1/ 1lynF1tpLBp2AN9/ rbc2N2NtOI3W40)  
X2krUQKCAQBRxpFTEWofHJZk7A6eaL7AKzQtJkWqRlyor7Yd1w0QdaiqDd020AbW  
Sbnb18msiGGwPm25IUFqa214ULC87s rWNBdw51/WOXaZiGzmj rct fHwZmVUQ310u  
pDWve4ButBBI0t9sEnTq+pMiC93nPprG/E8uBLyF2KX/c8WIBa/WpE/mmC31lvgtb  
PC2N9LrNeaHM4QPeRr f cj 52qxxKY1o55XUGpMSG j EUaHiTqSZa5QIR26s5Q80ceV  
sq5fUEDPbxHEhpO IUVVHarDBk2CCOiL+vQs082QQjmOybJ1/posPNfDHLYHuqhSA  
rVoRpE14r1M+FIX00S050f L2RHV8Bd f FAOIBAQCUFi7Lv3+dHMJ j Oh4HyL23rL6y  
yZXE9E jMd1ExoDP91aJSnSbS9GS+/Ro40si+rw5ixryqBXRn9tMCDtJ INQUY+MiU  
XFEs1tt 9N4XAYOWNm/ 1aUGsuICBdYbKh3DD97M+FZqzUqlI1p1Fb3NpKhat fY7Yg  
t2Z6w77B+0Mi8T6rIpeLOLxR5pEJmCCfojM8gVRGMFb7 [HcSHp1X1JpePh10ywQF  
ywaauJBnYEsIz2A22cMp4f rY/unZxeWRK82rN4d+j SYmy f9NCXwK9mXuq/pXj laB  
XqIB6+n3swDFGQX732iPBGu9iDbhsQ6vdoRBAtqcHmCTLB2dqXhrnvUSMMUS

END RSA PRIVATE KEY  
```

We can observe that there are still many errors on what the script returned.
We have no other choice than to check by hand and really be careful to avoid
mistakes, in which case the next steps won't work.

```-----BEGIN RSA PRIVATE KEY-----  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
[                             Hide!                            ]  
YZE7xr0bE94JO4cqritQcE+dJ4WOmf4HvmhaSElywcp9xN8xBucN5DnxlXt8MEbj  
me7udUNRvTDYHdFkv26P1K4Xhes8duRpQBES/TxN4YD42td2P8PCShLnvQ5JLWuY  
cCnYQa9wbEH8zL9lxlJne5+0Vc1Bd7X7OENRTxBHpYJg28m/cDeUs8KHUvlyeGHK  
qJGjzIAO3KXjvQzj0YWi/MGKCBleeoVz0URKR7oP7Gxj0RF2DypmLf8r2374uISy  
RHLKFQfW9TnO/j8L7DWm55dOcJOZr1kbDvxPAu2zLQKCAQEAwM/Hdvm8rX6Q6C8A  
tYLA/+JvWsxLxGW4nL88dgl61RVWPz4PZzWPNQwbfWohay562+ccTxFM0rlxuDoH  
Dh7A4X45W0+MBJbdYTSoVzFs1r1bjoPpwBnsL1pNAkC5zloQFUkmvpzBD6DaLx0i  
OhZtqsichyPGEyVH0RYv2L3UPYAhdmeYbsbc6Ruhva9tVUUMc+nFyKf51Os4vC8M  
YTnyYZJqo/5oAR7wt6806ZlsTQowlbSPn1hYgtSka/RK+gBnKyFhmihi/Jy0gJNg  
T/p/Fb1DaX6sjnTpPbxfHXX9j2ExC3uH1/1ynF1tpLBp2AN9/rbc2N2NtOI3W4oJ  
X2krUQKCAQBRxpFTEWofHJZk7A6eaL7AkzQtJkWqRlyor7Yd1wOQdaiqDdO20AbW  
Sbnb18msiGGwPm25IUFqa214ULC87srWNBdw51/W0XaZiGzmjrctfHwZmVUQ31Ou  
pDWve4ButBBIOt9sEnTq+pMiC93nPprG/E8uBLyF2KX/c8WIBa/WpE/mmC3lvgtb  
PC2N9lrNeaHM4QPeRrfcj52qxxKYIo55XUGpMSGjEUaHiTqSZa5QJR26s5Q8OceV  
sq5fUEDPbxHEhp0IUVVHarDBk2CC0iL+vQso82QQjm0ybJ1/posPNfDHlYHuqhSA  
rVoRpE14r1M+FIXO0S05Qfl2RHV8BdfFAoIBAQCUFi7Lv3+dHMJj0h4HyL23rL6y  
yZXE9EjMd1ExoDP91aJSnSbS9GS+/Ro4Osi+rw5ixryqBXRn9tMCDtJ1NQuY+MiU  
XFEsltt9N4XAY0WNm/1aUGsuICBdYbKh3DD97M+FZqzUqlI1p1Fb3NpKhatfY7Yg  
t2Z6w77B+OMi8T6rIpeLOLxR5pEJmCCfojM8gVRGMFb7IHc9Hp1XlJpePh1OyWQF  
ywaauJBnYEsIz2A22cMp4frY/unZxeWRK82rN4d+jSYmyf9NCXwK9mXuq/pXjlaB  
XqIB6+n3swDFGQX732iPBGu9iDbhsQ6vdoRBAtqcHmCTLB2dqXhrnvUSMMUS  
-----END RSA PRIVATE KEY-----  
```

With the size of the image we deduce that the key is coded on **4096 bits**.
Now as we know that the rsa key is encoded in **base 64** we can convert it to
**hexadecimal**  
(base 16).

```python  
from Crypto.Util.number import bytes_to_long, isPrime  
import base64

privet_key1 =
b"""YZE7xr0bE94JO4cqritQcE+dJ4WOmf4HvmhaSElywcp9xN8xBucN5DnxlXt8MEbj  
me7udUNRvTDYHdFkv26P1K4Xhes8duRpQBES/TxN4YD42td2P8PCShLnvQ5JLWuY  
cCnYQa9wbEH8zL9lxlJne5+0Vc1Bd7X7OENRTxBHpYJg28m/cDeUs8KHUvlyeGHK  
qJGjzIAO3KXjvQzj0YWi/MGKCBleeoVz0URKR7oP7Gxj0RF2DypmLf8r2374uISy  
RHLKFQfW9TnO/j8L7DWm55dOcJOZr1kbDvxPAu2zLQKCAQEAwM/Hdvm8rX6Q6C8A  
tYLA/+JvWsxLxGW4nL88dgl61RVWPz4PZzWPNQwbfWohay562+ccTxFM0rlxuDoH  
Dh7A4X45W0+MBJbdYTSoVzFs1r1bjoPpwBnsL1pNAkC5zloQFUkmvpzBD6DaLX0i  
OhZtqsichyPGEyVH0RYv2L3UPYAhdmeYbsbc6Ruhva9tVUUMc+nFyKf51Os4vC8M  
YTnyYZJqo/5oAR7wt6806ZlsTQowlbSPn1hYgtSka/RK+gBnKyFhmihi/Jy0gJNg  
T/p/Fb1DaX6sjnTpPbxfHXX9j2ExC3uH1/1ynF1tpLBp2AN9/rbc2N2NtOI3W4oJ  
X2krUQKCAQBRxpFTEWofHJZk7A6eaL7AkzQtJkWqRlyor7Yd1wOQdaiqDdO20AbW  
Sbnb18msiGGwPm25IUFqa214ULC87srWNBdw51/W0XaZiGzmjrctfHwZmVUQ31Ou  
pDWve4ButBBIOt9sEnTq+pMiC93nPprG/E8uBLyF2KX/c8WIBa/WpE/mmC3lvgtb  
PC2N9lrNeaHM4QPeRrfcj52qxxKYIo55XUGpMSGjEUaHiTqSZa5QJR26s5Q8OceV  
sq5fUEDPbxHEhp0IUVVHarDBk2CC0iL+vQso82QQjm0ybJ1/posPNfDHlYHuqhSA  
rVoRpE14r1M+FIXO0S05Qfl2RHV8BdfFAoIBAQCUFi7Lv3+dHMJj0h4HyL23rL6y  
yZXE9EjMd1ExoDP91aJSnSbS9GS+/Ro4Osi+rw5ixryqBXRn9tMCDtJ1NQuY+MiU  
XFEsltt9N4XAY0WNm/1aUGsuICBdYbKh3DD97M+FZqzUqlI1p1Fb3NpKhatfY7Yg  
t2Z6w77B+OMi8T6rIpeLOLxR5pEJmCCfojM8gVRGMFb7IHc9Hp1XlJpePh1OyWQF  
ywaauJBnYEsIz2A22cMp4frY/unZxeWRK82rN4d+jSYmyf9NCXwK9mXuq/pXjlaB  
XqIB6+n3swDFGQX732iPBGu9iDbhsQ6vdoRBAtqcHmCTLB2dqXhrnvUSMMUS"""

print(hex(bytes_to_long(base64.b64decode(privet_key1))))  
```

Which returns the part of the key in hexa:

```  
0x61913bc6bd1b13de093b872aae2b50704f9d27858e99fe07be685a484972c1ca7dc4df3106e70de439  
f1957b7c3046e399eeee754351bd30d81dd164bf6e8fd4ae1785eb3c76e469401112fd3c4de180f8dad7  
763fc3c24a12e7bd0e492d6b987029d841af706c41fcccbf65c652677b9fb455cd4177b5fb3843514f10  
47a58260dbc9bf703794b3c28752f9727861caa891a3cc800edca5e3bd0ce3d185a2fcc18a08195e7a85  
73d1444a47ba0fec6c63d111760f2a662dff2bdb7ef8b884b24472ca1507d6f539cefe3f0bec35a6e797  
4e709399af591b0efc4f02edb32d0282010100c0cfc776f9bcad7e90e82f00b582c0ffe26f5acc4bc465  
b89cbf3c76097ad515563f3e0f67358f350c1b7d6a216b2e7adbe71c4f114cd2b971b83a070e1ec0e17e  
395b4f8c0496dd6134a857316cd6bd5b8e83e9c019ec2f5a4d0240b9ce5a10154926be9cc10fa0da2d7d  
223a166daac89c8723c6132547d1162fd8bdd43d80217667986ec6dce91ba1bdaf6d55450c73e9c5c8a7  
f9d4eb38bc2f0c6139f261926aa3fe68011ef0b7af34e9996c4d0a3095b48f9f585882d4a46bf44afa00  
672b21619a2862fc9cb48093604ffa7f15bd43697eac8e74e93dbc5f1d75fd8f61310b7b87d7fd729c5d  
6da4b069d8037dfeb6dcd8dd8db4e2375b8a095f692b510282010051c69153116a1f1c9664ec0e9e68be  
c093342d2645aa465ca8afb61dd7039075a8aa0dd3b6d006d649b9dbd7c9ac8861b03e6db921416a6b6d  
7850b0bceecad6341770e75fd6d17699886ce68eb72d7c7c19995510df53aea435af7b806eb410483adf  
6c1274eafa93220bdde73e9ac6fc4f2e04bc85d8a5ff73c58805afd6a44fe6982de5be0b5b3c2d8df65a  
cd79a1cce103de46b7dc8f9daac71298228e795d41a93121a3114687893a9265ae50251dbab3943c39c7  
95b2ae5f5040cf6f11c4869d085155476ab0c1936082d222febd0b28f364108e6d326c9d7fa68b0f35f0  
c79581eeaa1480ad5a11a44d78af533e1485ced12d3941f97644757c05d7c5028201010094162ecbbf7f  
9d1cc263d21e07c8bdb7acbeb2c995c4f448cc775131a033fdd5a2529d26d2f464befd1a383ac8beaf0e  
62c6bcaa057467f6d3020ed275350b98f8c8945c512c96db7d3785c063458d9bfd5a506b2e20205d61b2  
a1dc30fdeccf8566acd4aa5235a7515bdcda4a85ab5f63b620b7667ac3bec1f8e322f13eab22978b38bc  
51e6910998209fa2333c8154463056fb20773d1e9d57949a5e3e1d4ec96405cb069ab89067604b08cf60  
36d9c329e1fad8fee9d9c5e5912bcdab37877e8d2626c9ff4d097c0af665eeabfa578e56815ea201ebe9  
f7b300c51905fbdf688f046bbd8836e1b10eaf76844102da9c1e60932c1d9da9786b9ef51230c512  
```

#### Look at the parts we have  

After being interested on how a private rsa key was created, we can notice a
particular structure: *n, e, d, p, q, d mod(p-1), d mod(q-1) and q^-1 mod p*.

```  
PrivateKeyInfo ::= SEQUENCE {  
  version Version,  
  privateKeyAlgorithm AlgorithmIdentifier ,  
  privateKey PrivateKey,  
  attributes [0] Attributes OPTIONAL  
}

RSAPrivateKey ::= SEQUENCE {  
 version           Version,  
 modulus           INTEGER,  -- n  
 publicExponent    INTEGER,  -- e  
 privateExponent   INTEGER,  -- d  
 prime1            INTEGER,  -- p  
 prime2            INTEGER,  -- q  
 exponent1         INTEGER,  -- d mod (p-1)  
 exponent2         INTEGER,  -- d mod (q-1)  
 coefficient       INTEGER,  -- (inverse of q) mod p  
 otherPrimeInfos   OtherPrimeInfos OPTIONAL  
}  
```

According to the previous analysis, we can study the structure and see that
its parts are separated by the **02 82 01 01** pattern as it's explained on
[cryptohack](https://blog.cryptohack.org/twitter-secrets).

As cryptohack [says](https://blog.cryptohack.org/twitter-secrets) they
precisely indicate that **02 82 01 01** corresponds to:

>02 for the data type, here Integer.  
>82 meaning that the length of the integer value will be encoded in the 2
following bytes.  
>0101, the actual length, which integer value is 257, meaning that the integer
value will be encoded in the following 257 bytes. Retrieving the 257 next
bytes in Big Endian and taking their integer values yield the rsa values we
are looking for.  

And bingo precisely after **decoding** our key we get pretty much the same
thing:  

So we now know that we have:  
>End => q  
>All => d mod (p-1) = dp  
>All => d mod (q-1) = dq  
>All => (inverse of q) mod p  

#### Recup key-public to get n and e:  

We also have *access* to another **authorized_keys file** which contains the
public keys **n** and **e**, so we can get them very easily with **cat**:  

```

ssh-rsa
AAAAB3NzaC1yc2EAAAADAQABAAACAQC/okaokb6dLlO889ktcFKuAzLbvCcy5Il2TiVIVzzibe+9FfH2W0RHtQ5A3aIvjbZKneQxgy9EiN+U28DOp9yBW4zAg11U77VtuF528Wp5ApwwN8SUD5YPBQssh3CFm6bKqg+O9F93J+/whzA8QGL8C2EYrN/BpOUSJKds0Az6cYYm3sqER+iQ64RDa9K2TrO5gfP/iyBTOydPD0ZNLbvsPMNk6YzuND+pjRGwtH9vxV5g0H1Pak1k+tXrcUSgpgnNkJ5Gptm5CgC0qF5yxR/+DMy/dOAc7jUhIZMeX1sWTd9rTSuQMAB/w3fONe6yXNBxaAavi5w3o1Cu7xgTUOYBUnAYaX+07AqTqu9PTrSpK08bZrnLf3oItdAUMsNStI4DiqxbdYX6TcccqdYLI7Cb3HdbBNRuMy3l25ZelSRyDaFT7ZXnMsGCbcWg3UnEbGCudAMHzU5aFLDYZJUpQsgYQblSw9EF7R/OLa8uy57CBGaqoM0wtU56A2sOPTGVbDVF2HmObg6rijqn4I6NBQsBeshANIil/amw08MJZVVK7jNYDLret23ky/uSyO/IRdp0KcByWk7vEW36J2itQOkRhKBVAgPIO3Vudez85TYoRb8ESAZ4OJtrBMP0l66lnXc5+L9keckKLZp24DNkb95ULd2g/7/jqFtv6gzFamb93w==
u@eniac

```

Now we just have to use **ssh-keygen** to decode the key:  

``>ssh-keygen -e -f ~/.ssh/id_rsa.pub -m pem >ssh-pub.pem``

Which gives this:  
```  
-----BEGIN RSA PUBLIC KEY-----  
MIICCgKCAgEAv6JGqJG+nS5TvPPZLXBSrgMy27wnMuSJdk4lSFc84m3vvRXx9ltE  
R7UOQN2iL422Sp3kMYMvRIjflNvAzqfcgVuMwINdVO+1bbhedvFqeQKcMDfElA+W  
DwULLIdwhZumyqoPjvRfdyfv8IcwPEBi/AthGKzfwaTlEiSnbNAM+nGGJt7KhEfo  
kOuEQ2vStk6zuYHz/4sgUzsnTw9GTS277DzDZOmM7jQ/qY0RsLR/b8VeYNB9T2pN  
ZPrV63FEoKYJzZCeRqbZuQoAtKhecsUf/gzMv3TgHO41ISGTHl9bFk3fa00rkDAA  
f8N3zjXuslzQcWgGr4ucN6NQru8YE1DmAVJwGGl/tOwKk6rvT060qStPG2a5y396  
CLXQFDLDUrSOA4qsW3WF+k3HHKnWCyOwm9x3WwTUbjMt5duWXpUkcg2hU+2V5zLB  
gm3FoN1JxGxgrnQDB81OWhSw2GSVKULIGEG5UsPRBe0fzi2vLsuewgRmqqDNMLVO  
egNrDj0xlWw1Rdh5jm4Oq4o6p+COjQULAXrIQDSIpf2psNPDCWVVSu4zWAy63rdt  
5Mv7ksjvyEXadCnAclpO7xFt+idorUDpEYSgVQIDyDt1bnXs/OU2KEW/BEgGeDib  
awTD9JeupZ13Ofi/ZHnJCi2aduAzZG/eVC3doP+/46hbb+oMxWpm/d8CAwEAAQ==  
-----END RSA PUBLIC KEY-----  
```  
With this [site](https://8gwifi.org/PemParserFunctions.jsp) I was able to
obtain *encryption module (n)* and *public exponent (e)*:

```  
Algo RSA  
Format X.509  
ASN1 Dump  
RSA Public Key [6b:b1:23:93:9f:b6:83:23:3e:7b:fb:d0:14:eb:d7:1f:f8:df:46:53]  

bfa246a891be9d2e53bcf3d92d7052ae0332dbbc2732e489764e2548573ce26defbd15f1f65b4447b50e40dda22f8db64a9de431832f4488df94dbc0cea7dc815b8cc0835d54efb56db85e76f16a79029c3037c4940f960f050b2c8770859ba6caaa0f8ef45f7727eff087303c4062fc0b6118acdfc1a4e51224a76cd00cfa718626deca8447e890eb84436bd2b64eb3b981f3ff8b20533b274f0f464d2dbbec3cc364e98cee343fa98d11b0b47f6fc55e60d07d4f6a4d64fad5eb7144a0a609cd909e46a6d9b90a00b4a85e72c51ffe0cccbf74e01cee352121931e5f5b164ddf6b4d2b9030007fc377ce35eeb25cd0716806af8b9c37a350aeef181350e601527018697fb4ec0a93aaef4f4eb4a92b4f1b66b9cb7f7a08b5d01432c352b48e038aac5b7585fa4dc71ca9d60b23b09bdc775b04d46e332de5db965e9524720da153ed95e732c1826dc5a0dd49c46c60ae740307cd4e5a14b0d864952942c81841b952c3d105ed1fce2daf2ecb9ec20466aaa0cd30b54e7a036b0e3d31956c3545d8798e6e0eab8a3aa7e08e8d050b017ac8403488a5fda9b0d3c30965554aee33580cbadeb76de4cbfb92c8efc845da7429c0725a4eef116dfa2768ad40e91184a0550203c83b756e75ecfce5362845bf04480678389b6b04c3f497aea59d7739f8bf6479c90a2d9a76e033646fde542ddda0ffbfe3a85b6fea0cc56a66fddf

public exponent: 10001  
```

#### Recup q and p:

With some math formulas we can succeed in expressing **p** and **q** according
to what we have, with **kp** and **kq** our only strangers:  

```  
p = (e*dp-1)/kp + 1   and q = (e*dq-1)/kq + 1  
```

Perfect, you just have to make a script to recover its **p** and **q**
potentials by trying to bruteforce **kp** and **kq**:

```python  
from Crypto.Util.number import bytes_to_long, isPrime  
from sympy import *

dp =
0xc0cfc776f9bcad7e90e82f00b582c0ffe26f5acc4bc465b89cbf3c76097ad515563f3e0f67358f350c1b7d6a216b2e7adbe71c4f114cd2b971b83a070e1ec0e17e395b4f8c0496dd6134a857316cd6bd5b8e83e9c019ec2f5a4d0240b9ce5a10154926be9cc10fa0da2d7d223a166daac89c8723c6132547d1162fd8bdd43d80217667986ec6dce91ba1bdaf6d55450c73e9c5c8a7f9d4eb38bc2f0c6139f261926aa3fe68011ef0b7af34e9996c4d0a3095b48f9f585882d4a46bf44afa00672b21619a2862fc9cb48093604ffa7f15bd43697eac8e74e93dbc5f1d75fd8f61310b7b87d7fd729c5d6da4b069d8037dfeb6dcd8dd8db4e2375b8a095f692b51  
dq =
0x51c69153116a1f1c9664ec0e9e68bec093342d2645aa465ca8afb61dd7039075a8aa0dd3b6d006d649b9dbd7c9ac8861b03e6db921416a6b6d7850b0bceecad6341770e75fd6d17699886ce68eb72d7c7c19995510df53aea435af7b806eb410483adf6c1274eafa93220bdde73e9ac6fc4f2e04bc85d8a5ff73c58805afd6a44fe6982de5be0b5b3c2d8df65acd79a1cce103de46b7dc8f9daac71298228e795d41a93121a3114687893a9265ae50251dbab3943c39c795b2ae5f5040cf6f11c4869d085155476ab0c1936082d222febd0b28f364108e6d326c9d7fa68b0f35f0c79581eeaa1480ad5a11a44d78af533e1485ced12d3941f97644757c05d7c5

e = 0x10001

for kq in range(1, e):  
   q_mul = dq * e - 1  
   if q_mul % kq == 0:  
       q = (q_mul // kq) + 1  
       if isPrime(q):  
       	print("Potential q: " + str(q))

for kp in range(1, e):  
   p_mul = dp * e - 1  
   if p_mul % kp == 0:  
       p = (p_mul // kp) + 1  
       if isPrime(p):  
       	print("Potential p: " + str(p))  
```  

Which returns:

```

>Potential q:
24312821138947295842939811430266614164483390266044923887694157098746040509093637457237135603411011833287827123602619771315554896936017168546924189851322281151620644250524117043049673777703814283705410796690775974401304283378519985368125276766049671207507190418663428295243489814095988104136549989630636041063221268290523766428047760530245982382697752496455539057488593944136069627708927281633167017337393918797915410963972736328647804191560830879679674669676405585810075964267210384497030345823969704188597922024875674517047635080525199694836436149951817779893116507111781865061463859626764914849867030257100120765229  
>Potential p:
531728207659942301795253901084381737110883040097313053322913639565173847736026567062658310606998607620829538859271019692779574663546063949380410110347896571016088740644703155824678492122200126954702690666327960507428268541835210899166622764600001960907380213645069024205628211424497796451244548457631029653033974543275052835017313659168468855844022055884671115800091077092022099362967367260138515603050906837518856621847732055920780974661504255852004514803319931650360002033069998882446652627303752496381522697600057253746343547131595999387666854098155533978693698059492388066835684589123085776392908036740654319726890609  
>Potential p:
32155793883644309494149365087347710275210633774631897274003001908876018851960968012981271807389852904017267710405842990613181825323298497180721462889930852141756696942713059737825259562300443091116514916928396257101370860052927606384048304583938193088254729901128992755541135185322798527530512122498248043845789461978413935354215871986482151417756534584220556107891332673683000687165418919940645597668777626845600908432978474596080126672805046918964956144371065049005805638187590643592564866189148070656840995258832683463131564291944605671726345796937320632480267178246999762145360703260951002442725449730325007240379

```

Problem **with script returning 2 p** we don't know which one is correct,
given that we know n and q and that by definition *n = p * q* then *q = n / p*
:

```python

n =
0xbfa246a891be9d2e53bcf3d92d7052ae0332dbbc2732e489764e2548573ce26defbd15f1f65b4447b50e40dda22f8db64a9de431832f4488df94dbc0cea7dc815b8cc0835d54efb56db85e76f16a79029c3037c4940f960f050b2c8770859ba6caaa0f8ef45f7727eff087303c4062fc0b6118acdfc1a4e51224a76cd00cfa718626deca8447e890eb84436bd2b64eb3b981f3ff8b20533b274f0f464d2dbbec3cc364e98cee343fa98d11b0b47f6fc55e60d07d4f6a4d64fad5eb7144a0a609cd909e46a6d9b90a00b4a85e72c51ffe0cccbf74e01cee352121931e5f5b164ddf6b4d2b9030007fc377ce35eeb25cd0716806af8b9c37a350aeef181350e601527018697fb4ec0a93aaef4f4eb4a92b4f1b66b9cb7f7a08b5d01432c352b48e038aac5b7585fa4dc71ca9d60b23b09bdc775b04d46e332de5db965e9524720da153ed95e732c1826dc5a0dd49c46c60ae740307cd4e5a14b0d864952942c81841b952c3d105ed1fce2daf2ecb9ec20466aaa0cd30b54e7a036b0e3d31956c3545d8798e6e0eab8a3aa7e08e8d050b017ac8403488a5fda9b0d3c30965554aee33580cbadeb76de4cbfb92c8efc845da7429c0725a4eef116dfa2768ad40e91184a0550203c83b756e75ecfce5362845bf04480678389b6b04c3f497aea59d7739f8bf6479c90a2d9a76e033646fde542ddda0ffbfe3a85b6fea0cc56a66fddf  
q =
24312821138947295842939811430266614164483390266044923887694157098746040509093637457237135603411011833287827123602619771315554896936017168546924189851322281151620644250524117043049673777703814283705410796690775974401304283378519985368125276766049671207507190418663428295243489814095988104136549989630636041063221268290523766428047760530245982382697752496455539057488593944136069627708927281633167017337393918797915410963972736328647804191560830879679674669676405585810075964267210384497030345823969704188597922024875674517047635080525199694836436149951817779893116507111781865061463859626764914849867030257100120765229  
print(n//q)

```

Which gives:

```

32155793883644309494149365087347710275210633774631897274003001908876018851960968012981271807389852904017267710405842990613181825323298497180721462889930852141756696942713059737825259562300443091116514916928396257101370860052927606384048304583938193088254729901128992755541135185322798527530512122498248043845789461978413935354215871986482151417756534584220556107891332673683000687165418919940645597668777626845600908432978474596080126672805046918964956144371065049005805638187590643592564866189148070656840995258832683463131564291944605671726345796937320632480267178246999762145360703260951002442725449730325007240379

```

Now we know the **correct p.**  
And we can build the entirely key:

```python  
from Crypto.PublicKey import RSA

n =
0xbfa246a891be9d2e53bcf3d92d7052ae0332dbbc2732e489764e2548573ce26defbd15f1f65b4447b50e40dda22f8db64a9de431832f4488df94dbc0cea7dc815b8cc0835d54efb56db85e76f16a79029c3037c4940f960f050b2c8770859ba6caaa0f8ef45f7727eff087303c4062fc0b6118acdfc1a4e51224a76cd00cfa718626deca8447e890eb84436bd2b64eb3b981f3ff8b20533b274f0f464d2dbbec3cc364e98cee343fa98d11b0b47f6fc55e60d07d4f6a4d64fad5eb7144a0a609cd909e46a6d9b90a00b4a85e72c51ffe0cccbf74e01cee352121931e5f5b164ddf6b4d2b9030007fc377ce35eeb25cd0716806af8b9c37a350aeef181350e601527018697fb4ec0a93aaef4f4eb4a92b4f1b66b9cb7f7a08b5d01432c352b48e038aac5b7585fa4dc71ca9d60b23b09bdc775b04d46e332de5db965e9524720da153ed95e732c1826dc5a0dd49c46c60ae740307cd4e5a14b0d864952942c81841b952c3d105ed1fce2daf2ecb9ec20466aaa0cd30b54e7a036b0e3d31956c3545d8798e6e0eab8a3aa7e08e8d050b017ac8403488a5fda9b0d3c30965554aee33580cbadeb76de4cbfb92c8efc845da7429c0725a4eef116dfa2768ad40e91184a0550203c83b756e75ecfce5362845bf04480678389b6b04c3f497aea59d7739f8bf6479c90a2d9a76e033646fde542ddda0ffbfe3a85b6fea0cc56a66fddf  
e = 0x10001  
q =
24312821138947295842939811430266614164483390266044923887694157098746040509093637457237135603411011833287827123602619771315554896936017168546924189851322281151620644250524117043049673777703814283705410796690775974401304283378519985368125276766049671207507190418663428295243489814095988104136549989630636041063221268290523766428047760530245982382697752496455539057488593944136069627708927281633167017337393918797915410963972736328647804191560830879679674669676405585810075964267210384497030345823969704188597922024875674517047635080525199694836436149951817779893116507111781865061463859626764914849867030257100120765229  
p =
32155793883644309494149365087347710275210633774631897274003001908876018851960968012981271807389852904017267710405842990613181825323298497180721462889930852141756696942713059737825259562300443091116514916928396257101370860052927606384048304583938193088254729901128992755541135185322798527530512122498248043845789461978413935354215871986482151417756534584220556107891332673683000687165418919940645597668777626845600908432978474596080126672805046918964956144371065049005805638187590643592564866189148070656840995258832683463131564291944605671726345796937320632480267178246999762145360703260951002442725449730325007240379  
phi = (p-1)*(q-1)  
d = pow(e,-1,phi)

key = RSA.construct((n,e,d,p,q))  
pem = key.exportKey('PEM')  
print(pem.decode())

```

Which returns this private key:

```  
-----BEGIN RSA PRIVATE KEY-----  
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  
-----END RSA PRIVATE KEY-----  
```

Now we just have to send a **request** to the ssh server with this
authentication key to obtain the flag.

```  
>> chmod 600 final_key.pem  
>> ssh -i final_key.pem -p 2222 frank@backup-01.play.midnightsunctf.se  
```  
And the ssh server returns: **midnight{D0_n07_s0w_p4r75_0f_y0ur_pr1v473}**.  
;)  

#### Zeynn & Archie Bloom & supersnail  

Original writeup (https://ret2school.github.io/post/writeuprsa/).