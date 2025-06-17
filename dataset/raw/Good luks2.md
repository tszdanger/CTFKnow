# Goodluks2

__Problem__

Our first insider threat has lead to a second insider. We haven't found any
clues to the passphrase here, but given the vocabulary of the suspect, I don't
think you'll have a hard time.

https://storage.googleapis.com/bsides-sf-ctf-2019-large-artifacts/goodluks2.7z

__Solution__

This one was a bit weird or you can say confusing(atleast for me) in the
starting. Since the description said something about the vocabulary I kept on
thinking that it is refering to password from goodluks1 i.e `wages upturned
flogging rinse landmass number` and I kept googling this but admins cleared
that goodluks2 had nothing to do with it's first part.

Since we had to bruteforce the password we decided to dump the header that
would contain the hash for the password. Even though @mementomori suddenly did
that process and provided us with the [file](goodluks2.bin/) I figured out
later we can use dd command to do so.

Now we had the file and we tried lot of password list with hascat on this one,
we started with list like https://github.com/dwyl/english-words because it
said something about the vocabulary but then later we found the password in
the rockyou.txt

The password was `gaffer3`. Using that password we did the same as for luks1  
```  
sudo cryptsetup luksOpen f0000000.luks luks  
```

When the device was mounted we found a file named flag.txt

FLAG `CTF{lame_users_keys_suck}`  

Original writeup (https://github.com/mzfr/ctf-
writeups/tree/master/BsidesSF_2019/Goodluks2).