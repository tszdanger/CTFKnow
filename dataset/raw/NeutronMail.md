# NeutronMail Writeup

### LakeCTF 2022 - crypto 416 - 14 solves

> After getting hacked, the *organizers* of the CTF created a **new** and more
> secure account. You were able to intercept this PGP encrypted e-mail. Can
> you decrypt it? [flag.eml](flag.eml)

#### What we have

Our goal is to decipher encrypted PGP message. Lets first store the encrypted
message at [msg.enc](msg.enc). Lots of information embedded at email header.
We know that the receiver is using [protonmail](https://proton.me/mail), and
receiver's name and email address: `[email protected]`. We get receiver's
public key [protonmail's public key GET api](https://mail-
api.proton.me/pks/lookup?op=get&[email protected]). Locate at [epfl-ctf-
admin2.asc](epfl-ctf-admin2.asc).

Lets inspect [epfl-ctf-admin2.asc](epfl-ctf-admin2.asc). Feed it to this
awesome tool: https://cirw.in/gpg-decoder. It shows that public key algorithm
is `publicKeyAlgorithm: "RSA (Encrypt or Sign) (0x1)"`, with public modulus
having bit len 4096, and `e` be `0x10001`. I notice that subkey is also
included, having same security with the primary key. Also you may check key
internals with below `gpg` command:

```sh  
cat epfl-ctf-admin2.asc | gpg --with-colons --import-options import-show --dry-run --import   
```

#### Read the docs

According to the [docs](https://wiki.debian.org/Subkeys),

>  GnuPG actually uses a signing-only key as the primary key, and creates an
> encryption subkey automatically. Without a subkey for encryption, you can't
> have encrypted e-mails with GnuPG at all. Debian requires you to have the
> encryption subkey so that certain kinds of things can be e-mailed to you
> safely, such as the initial password for your debian.org shell account.

So we must factor subkey's public modulus to get flag. It seems not good. All
the *fancy* factorization algorithm failed, and unfortunately we do not have
quantum computers.

#### Guess Time

We stare at the email address: `[email protected]`. We stare it again and
again, read the problem description several times, and guess to query
[protonmail's public key GET api](https://mail-
api.proton.me/pks/lookup?op=get&[email protected]) with `[email protected]`.
(Yes number `2` had vanished). We get another public key, with equal security,
and saved at [epfl-ctf-admin.asc](epfl-ctf-admin.asc). Will it help?

#### Analysis and GCD Fun

Lets get subkey's public modulus, using https://cirw.in/gpg-decoder, and take
gcds. We get a nontrivial factor! Not enough entropy was given while key
generation. See [factor.py](factor.py) to get actual numbers and get juicy
`p`, `q`, `d`, and `u`.

#### Patch pgpy to decrypt

The hardest part of this challenge. We need to use our private numbers to
decrypt. Lets patch this [pgpy](https://github.com/SecurityInnovation/PGPy)
which seems to be unmaintained.

Two thing to patch:  
1. Make `pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)` be created based on factored results: `p`, `q`, `d`, and `u`.  
2. Match signature: `2461439C55F8627A`. `pgpy` will complain when newly generated key's signature and encrypted message's signature mismatches. Extract signature using https://cirw.in/gpg-decoder, and patch the library. We do all this stuff in [solve.py](solve.py).

We finally get the flag:

```  
EPFL{https://infoscience.epfl.ch/record/174943#Lenstra<3}  
```

Which links us to this infamous paper: [`Ron was wrong, Whit is
right`](https://infoscience.epfl.ch/record/174943#Lenstra), which again tells
us public keys in the wild are not so random.

Full exploit code: [solve.py](solve.py) requiring
[requirements.txt](requirements.txt)

Keys: [epfl-ctf-admin.asc](epfl-ctf-admin.asc), [epfl-ctf-admin2.asc](epfl-
ctf-admin2.asc)

Factorization fun: [factor.py](factor.py)

Encrypted message: [msg.enc](msg.enc)

Original email: [flag.eml](flag.eml)  

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2022/Lake/NeutronMail).