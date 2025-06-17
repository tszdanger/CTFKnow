## first hunt

---

#### Description:  
*Hey! We intercepted this strange message, I think we finally found them. Let me know if you find something*

*Attachment: [info.eml](https://github.com/marihere/CTF_writeups/tree/main/snakeCTF2023/flightyflightflight/attachment/info.eml)*

---

The attached file is an email encoded with BASE64. The decoded message says
that an URL link has been changed and that the recipient should paste it
somewhere else and delete the email.

The hint here is the word "paste"... It refers to the website
[Pastebin](https://pastebin.com)!

Thanks to the file we can tell that the recipient's email address is
*[email protected]*, so I searched if there was an existing account under the
username of wazzujf2 and I did found one ([click here to see the
account](https://pastebin.com/u/wazzujf2)).

The account contains only one [paste](https://pastebin.com/xZMgCeVM) that
says:

> *For my favourite shop!!!!!!! ->
> https://e2ueln4vgn6qj2q4vwkcntkeg3ftinizb3ewjkahd2aoior33dbts3qd.onion*  
>  
>  
> *user: [email protected]*  
>  
> *pass: hYpYxWRvHvKBzDes (i hope this is secure enough)*  
>  
>  
> *todo: burn this!*

And all you had to do was logging in using those credentials!

---

The flag is:  
### snakeCTF{h1dd3n_s3rv1ce5_4re_fuN_t0_bu1ld}

Original writeup
(https://github.com/marihere/CTF_writeups/tree/main/snakeCTF2023/first%20hunt).