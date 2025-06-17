## Challenge name:      Random ECB

### Description:  
> nc ecb.utctf.live 9003  
>  
> P.S: given file: *server.py*

### Solution:

We have a server with it's application. Here I explain how it works:

When you connect to server, first of all, it choose 16bytes of random, for
**AES** key, then it asks you to "*Input a string to encrypt (input 'q' to
quit):*". After that, it will concat your string with **flag** and then
encrypt it using **AES ECB mode**. And in 50% of cases, it will put a
character ('*A*') at the first. If you read about **ECB mode** you realize
that encrypting each block in this mode is independent to each other. So what
now ?!

Assume we give the server these 15 characters (e.g. *'aaaaaaaaaaaaaaa'*), then
the first block will become on of these:

   aaaaaaaaaaaaaaa? ('?' is the first character of flag)  
   Aaaaaaaaaaaaaaaa

and because the key is same for this connection, we will only 2 encryption
text for this input. Now if we use bruteforce, and try all characters in the
'*?*' place, and compare it to encrypted text received by the
'*aaaaaaaaaaaaaaa*' input, you can find the first character of the flag!
(Sorry, I'm not so good in explaining :P). Then Use this technique for finding
all characters of the flag.

**Bruteforce function**

   def bf():  
       global flag  
       pf = 'a' * (31 - len(flag))  
       print('\t|--Poison data: "%s"' % (pf))  
       resp1 = f_send(pf)[:64]  
       resp2 = ''  
       while True:  
           resp2 = f_send(pf)[:64]  
           if resp1 != resp2:  
               break  
       print('\t\t|--resp1: %s' % (resp1))  
       print('\t\t|--resp2: %s' % (resp2))

       for c in pchar:  
           pd = pf + flag + c  
           print('\t\t|--Test on "%s"' % (pd))  
           res1 = f_send(pd)[:64]  
           res2 = ''  
           while True:  
               res2 = f_send(pd)[:64]  
               if res2 != res1:  
                   break

           print('\t\t\t|--res1: %s' % (res1))  
           print('\t\t\t|--res2: %s' % (res2))  
           if (res1 == resp1 and res2 == resp2) or (res1 == resp2 and res2 == resp1):  
               flag += c  
               print('\t\t\t|--Character found: %c' % (c))  
               return 0

       print ('\t\t\t|--not found!')  
       return -1

We know The flag size is between 16bytes and 32bytes. So i start with sending
31 characters and comparing 2bytes!

[final script.py](./script.py)

**The Flag**

   utflag{3cb_w17h_r4nd0m_pr3f1x}  

Original writeup (https://github.com/RaaCT0R/CTF-
Challenges/blob/master/cryptography/utctf2020/Random-ECB/WRITEUP.md).