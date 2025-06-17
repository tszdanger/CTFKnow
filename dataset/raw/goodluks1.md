# Good Luks1

__Problem__

We've recovered an encrypted disk image from an insider threat. While he won't
give up the passphrase, we think the post-it note is related.

[goodluks1.7z](goodluks1.7z/)  
[goodluks1.jpg](goodluks1.jpg/)

__Solution__

This is the first challenge in the series.

The zip file contains an `.img` file using
[photorec](https://www.cgsecurity.org/wiki/PhotoRec) I extracted an [encrypted
luks partition](https://opensourceforu.com/2018/02/encrypting-partitions-
using-luks/). We need to decrypt it using information that is given in the
image, specifically on the `post it` note in the image.

![alt text](goodluks1.jpg/)

I started to try the conversion of those decimal to ascii and then to hex and
what not but it gave nothing. And then suddenly @unblvr said that `I think the
password is "wages upturned flogging rinse landmass number"` and we all
freaked out because this was a bit random and then he explained that the image
says something about the `EFF membership` so using https://www.eff.org/dice he
decoded those number.

Using that password we decrypted the luks partition

```  
➜ sudo cryptsetup luksOpen f0000000.luks luks  
```

For some reason this mounted the partition for me, there was the flag

FLA: `CTF{Look_Under_Keyboards_4_Secrets}`

Original writeup (https://github.com/mzfr/ctf-
writeups/tree/master/BsidesSF_2019/Good_luks1).