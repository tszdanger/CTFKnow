The challenge begins just as Part 1, except this time the interesting request
is `TPM2_CC_Import`.  
Well, this time arguments are quite complex, but reconnaissance from Part 2  
allows to decode them with some manual work (by either following all
`Unmarshal_`  
calls in `TPM2_Import` code or reading the specification for `TPM2_Import` and  
following all structures from there):  
* `8002`: `TPM_ST_SESSIONS`  
* `0000024b`: command size, including header  
* `00000156`: command code CC_Import  
* `80000000`: parentHandle, transient #0  
* `00000049`: authSize  
* `020000000020d2de5d55410d57c9edc669bdd6b9f1b66aa1956c99c16e5fffb2d1d1e7ec68f96000203a6aed6be1615734f49a00bf2e96ec1354d973e7a0fe7bdff01d90065e68f858`: auth  
* `002027dcfdf57cf80eaf2e410c57577d374a8d8d50ccd0fcc12e25392cf3c1723c47`: encryptionKey  
* `01160001000b000400400000001000100800000000000100ef99255186ad7c50a48504669398857593505934bc59ce02388b1362dd65d94a8fdc61602874bef4`  
`c1fc74978dbb8d5d7115e4e83400363bf423a6e13eb5b42c7ec781009cce1e4f2b60c9226d5b2fae0873195ea91c968b7c5236250f85d5489bbe5d4ef287ffd5`  
`d07ccce7154e281f9c644d528788fa77b0465b4028751d61983c2ced48cb0a4d1b5f9137026b3159e8afd2c06a5483118a09b1e986e4e755d1b75c2a92af676a`  
`a55fb8d11319bd2e5d1c7574a19279df81e2e268ccf8f71faae1e730af744721f9b39d6d13ee5eb20ce1fce51ee1b8bb8d387d16c69f776ae115b93cf019f248`  
`6741185c1a3e6a272b1d4623a37ed628e0b8217732fd14a3`: objectPublic  
* `00ac4bd8ac2db10bd417520ab80b7a5e80107602292ba30bd584d7528a88906726b1f0885414e3d466f939ec6e672bdba13094d8aa395623e3042de4d4f48723`  
`5d8591a0b781ffe1489546f1620f8734f2441b7a6d7ee1760526e92c7e2c7e92f2eeba7c0d54f747490ec136bc5b1044758071234b4fab1b42a6dc23c177ef7f`  
`fcb142e5b0ac798da41f77fb79dddc8e761dabf30bd646f0bc30f6fb2f3d594e73df8bb845ef9085c9954604c6a6`:
duplicate  
* `0000`: inSymSeed, zero-length blob  
* `000601000043`: symmetricAlg  
 * `0006`: `TPM_ALG_AES`  
 * `0100`: 256 bits  
 * `0043`: `TPM_ALG_CFB`

The meaning of all those parameters is explained in Volume 3 of the
specification,  
the section named "TPM2_Import". In particular,  
* zero-length blob for `inSymSeed` means that the data  
 are not asymmetrically-encrypted with the parent key (good thing),  
* `objectPublic` is the public part, the modulus `0xef99...14a3` is easy to spot,  
* `duplicate` is the private part, encrypted by `encryptionKey`.

Well, it is all clear now, the main thing to do is  
`AES.new(key=bytes.fromhex('27dc...3c47'), mode=AES.MODE_CFB, iv=?,
segment_size=8*16).decrypt(bytes.fromhex('4bd8...c6a6')).hex()`  
(by the way, what about IV? `TPM2_Import` -> `CryptSecretDecrypt` with NULL
for nonce -> aha, zeroes as IV),  
and a divisor of the modulus will be revealed along with some hmac/whatever...

...except it does not work, the decrypted data look like they are not really
decrypted.

Let's read again the specification for TPM2_Import... well, according to it,
the decryption should have worked.

Let's look into `TPM2_Import` from libtpms... doesn't seem to deviate from the
specification.

Okay, I still have TPM image from Part 2 with gdb. Maybe I made a mistake
while decoding arguments?  
Breakpoint to `TPM2_Import`... send the packet (`import socket` and so on)...  
the handler is not called presumably due to failed auth; replace auth to
whatever worked for Part 2...  
well, the code dutifully follows the decryption above, obtains the same bytes,
interprets  
first two bytes as some length and bails out because the length is invalid.
Hmmm.

Let's try to look to the other side of the network. openssl engine from Part 2
does not  
issue `TPM2_Import` command (keygenning inside TPM seems to be `TPM2_Create`),  
so some other command should have been used. It doesn't take long to find
[https://github.com/tpm2-software/tpm2-tools](https://github.com/tpm2-software/tpm2-tools)  
near tpm2-tss/tpm2-tss-engine and the command tpm2_import.

...compiling...

`tpm2_import` indeed calls `TPM2_Import`, except this time, `inSymSeed` is
non-empty,  
which makes a direct comparison difficult. The code
[tpm2_import.c](https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/tools/tpm2_import.c#L368)  
seems to just mirror the same things that `TPM2_Import` does (in particular,
IV is indeed zero:
[tpm2_identity_util.c](https://github.com/tpm2-software/tpm2-tools/blob/0a2354d2b35a43242ffa8b3880aadd96d56821ce/lib/tpm2_identity_util.c#L209)
).

Time to change approach. The task says "But a recent security advisory stated
that this encryption was broken".  
What does Internet know about TPM-related security advisories?

...searching...

[CVE-2021-3565](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3565)
seems to fit.  
Most sources just recite the same description without much details, so  
the most relevant link is [the pull
request](https://github.com/tpm2-software/tpm2-tools/pull/2739) with the fix:  
> tpm2_import: fix fixed AES key CVE-2021-3565  
>  
> tpm2_import used a fixed AES key for the inner wrapper, which means that  
> a MITM attack would be able to unwrap the imported key. Even the  
> use of an encrypted session will not prevent this. The TPM only  
> encrypts the first parameter which is the fixed symmetric key.  
>  
> To fix this, ensure the key size is 16 bytes or bigger and use  
> OpenSSL to generate a secure random AES key.

```  
- memset(enc_sensitive_key.buffer, 0xFF, enc_sensitive_key.size);  
+ int ossl_rc = RAND_bytes(enc_sensitive_key.buffer, enc_sensitive_key.size);  
```

Before the fix, the encryption key was just a bunch of FFs. Let's try it! (By
default, PyCryptodome understands `MODE_CFB` somewhat strange,
`segment_size=8*16` makes the mode compilant with the usual definition.)  
```  
>>> from Crypto.Cipher import AES  
>>> k = AES.new(key=b'\xFF'*32, mode=AES.MODE_CFB, iv=b'\0'*16,
segment_size=8*16)  
>>>
k.decrypt(bytes.fromhex('4bd8ac2db10bd417520ab80b7a5e80107602292ba30bd584d7528a88906726b1f0885414e3d466f939ec6e672bdba13094d8aa395623e3042de4d4f487235d8591a0b781ffe1489546f1620f8734f2441b7a6d7ee1760526e92c7e2c7e92f2eeba7c0d54f747490ec136bc5b1044758071234b4fab1b42a6dc23c177ef7ffcb142e5b0ac798da41f77fb79dddc8e761dabf30bd646f0bc30f6fb2f3d594e73df8bb845ef9085c9954604c6a6')).hex()  
'0020f336ec5f79ab6271b20ff9d72ddb8129859a8b1c12e3e5ff05ea672f50d86b7800880001000000000080fdd6ee0ba5178f056a5568a24d765dd18905a432e0c0952abfd2c8f531c6878be2e40ce8902e70d6e7d819a7433666b6f4ab3784418a223f8d86bad7143d78fd697afa956d16372d00c531647c01f021c2bdc5671de7a8f1e5056c546477b94fcf68eb1ff327224f8c9e8b46b4cb27ad2e803775f46c8faae5aec26d146abbfb'  
```

Now, that is a meaningful structure; first goes some hmac/whatever, then the
divisor. Time to use them!  
```  
>>> n =
0xef99255186ad7c50a48504669398857593505934bc59ce02388b1362dd65d94a8fdc61602874bef4c1fc74978dbb8d5d7115e4e83400363bf423a6e13eb5b42c7ec781009cce1e4f2b60c9226d5b2fae0873195ea91c968b7c5236250f85d5489bbe5d4ef287ffd5d07ccce7154e281f9c644d528788fa77b0465b4028751d61983c2ced48cb0a4d1b5f9137026b3159e8afd2c06a5483118a09b1e986e4e755d1b75c2a92af676aa55fb8d11319bd2e5d1c7574a19279df81e2e268ccf8f71faae1e730af744721f9b39d6d13ee5eb20ce1fce51ee1b8bb8d387d16c69f776ae115b93cf019f2486741185c1a3e6a272b1d4623a37ed628e0b8217732fd14a3  
>>> p =
0xfdd6ee0ba5178f056a5568a24d765dd18905a432e0c0952abfd2c8f531c6878be2e40ce8902e70d6e7d819a7433666b6f4ab3784418a223f8d86bad7143d78fd697afa956d16372d00c531647c01f021c2bdc5671de7a8f1e5056c546477b94fcf68eb1ff327224f8c9e8b46b4cb27ad2e803775f46c8faae5aec26d146abbfb  
>>> n % p  
0  
>>> import gmpy2  
>>> d = int(gmpy2.invert(0x10001, (p-1)*(n//p-1)))  
>>> pow(int.from_bytes(open('ca_flag.txt.enc', 'rb').read(), 'big'), d,
n).to_bytes(256, 'big')  
b'\x00\x02\xe8\xd7\'\xf4r\x8daW\xae\x1b\xe063!\xcf\x87\xb5\xc0\xa7U\x97\xa5>\xac}<\xc5\x02\xa2S\x86\x17\xffP|\x13\x8b(X2H\xd0k\xd0\xb7\xa5\xaa\x89\xb4&\x17\xa0G\x90\xa3\x90_\xd1%\xdd\xa4lK\x8e\xf7\xcb\x19\xa2]\xaa\xa9B\xf1V\xde\xf8\xf9w\x8cx?\xed.W\x10S\x9fk\xbc8\xabh\xa9\x8dhU(\xfc\x10\x8c\t\xa2\x0e\x8d~\xa9\x82\xc4\xee\xe8\xe9t\xf3o\xbc%\xc1\x01n\x1e\xadu\x9c\x145\x9cQ\x9c\xd6?\xc5\xcd\xa0x\xf8\xf3\x1d6\x8b\xcf-\xd3\x8aV\n|\xf6\xabR\xb9\xf5\x0eo{\xc2\x0b\x82\x06\xdaY~\x9e\xcf]-\xe1\xeb\xa1x\x03\xeb^e|\xefW85\x9a\x0c\t\xa2C\x99\xb3\xbaD\x83\xfa\xa0|\x89!\xa2R\xe3\tk\x89\xfe\xb5\xb2L\xba\x7f"Sb\xfc\xc6{\xa3\xcf\xe2\x00CTF{Can_you_understand_CVE-2021-3565?}\n'  
```

The flag can be seen in the end of decrypted data. (That is a trait of used
padding;  
it wouldn't be the case with OAEP, but at this point, reconstructing a full
OpenSSL private key  
is a matter of looking into PyCryptodome documentation about RSA key
serialization.)

Okay, the last question: why is the network capture missing all those FFs?  
The commit message also provides relevant keywords: "encrypted session".
Volume 1  
of TCG specification has a dedicated section "21. Session-based encryption"
that  
says the following:  
> Only the first parameter in the parameter area of a request or response may
> be encrypted.  
> That parameter must have an explicit size field.  
> Only the data portion of the parameter is encrypted.  
> The TPM should support session-based encryption using XOR obfuscation.  
> Support for a block cipher using CFB mode is platform specific.  
> ...  
> If sessionAttributes.decrypt is SET in a session in a command, and the first
> parameter of the command is  
> a sized buffer, then that parameter is encrypted using the encryption
> parameters of the session. If  
> sessionAttributes.encrypt is SET in a session of a command, and the first
> parameter of the response is a  
> sized buffer, then the TPM will encrypt that parameter using the encryption
> parameters of the session.

The rest of the section specifies boring details. The "explicit size field"
requirement  
means that the encryption/decryption can be done by common session code rather
than  
command-specific handlers, this explains why I have not seen it in the source
code - I just have looked  
in wrong places. And, of course, stripping the authorization when tracing TPM
image  
has completely blocked this transformation.

Unfortunately, the specification does not provide any rationale, and
encrypting  
just the first parameter instead of full data seems quite weird.  
Admittedly, XOR as the cipher doesn't mix with large plaintexts containing  
predictable bytes, but rationale for requiring only XOR is also not
provided...