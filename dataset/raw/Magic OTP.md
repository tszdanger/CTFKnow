# 200- Magic OTP

Task:

```  
Bad luck, you lost the hardware device that give access to https://magic-
otp.donjon-ctf.io:9000/  
```

## One Time Password

In this challenge, we have access to an OTP server and clients through an HTTP
interface as well as the sources of the applications. The server can generate
token using a [Time-Based One-Time Password
Algorithm](https://datatracker.ietf.org/doc/html/rfc6238) and generates 10
digits long token:

```c  
static void generate_otp(uint8_t epoch[8], char otp[32])  
{  
   uint32_t truncated_hash;  
   uint8_t hmac_hash[32];  
   unsigned int offset;

   cx_hmac_sha256((uint8_t *)OTP_SECRET, sizeof(OTP_SECRET)-1, epoch, 8,
hmac_hash, 32);  
   offset = hmac_hash[31] & 0x0f;

   truncated_hash = 0;  
   truncated_hash |= (hmac_hash[offset+0] & 0x7f) << 24;  
   truncated_hash |= hmac_hash[offset+1] << 16;  
   truncated_hash |= hmac_hash[offset+2] << 8;  
   truncated_hash |= hmac_hash[offset+3] << 0;

   explicit_bzero(hmac_hash, sizeof(hmac_hash));

   memset(otp, 0, 32);  
   snprintf(otp, 32, "%010d", truncated_hash);  
}  
```

The OTP are then *AES encrypted* using a shared secret generated using an
Elliptic Curve Diffie-Hellman key exchange and sent to the client which can
then decrypt an display the OTP to the end user. The following request can be
used to request an OTP for a specific `deviceid` (`0` in this example):

```bash  
curl --insecure -X POST https://magic-otp.donjon-
ctf.io:9000/api/get_encrypted_otp \  
-H 'Content-Type: application/json' \  
-d '{"deviceid":0}'  
{"encrypted_otp":
"9b85d2abc888be0fb1848b6d823776efa37dd538c8cda69f7ec6885bb0605308"}  
```

## Vulnerability

After reading carefully the source code, I eventually found the vulnerability
which affects the function used to generate the shared secret:

```c  
static int get_shared_secret(cx_ecfp_public_key_t *pubkey, uint8_t secret[32])  
{  
   cx_ecfp_private_key_t privkey;  
   uint8_t out[32];  
   cx_err_t ret;

   get_own_privkey(&privkey); // [0]  
   ret = cx_ecdh_no_throw(&privkey, CX_ECDH_X, pubkey->W, pubkey->W_len,  
                          out, sizeof(out)); // [1]

   explicit_bzero(&privkey, sizeof(privkey));  
   if (ret != CX_OK) {  
       return -1;  
   }

   memcpy(secret, out, sizeof(secret)); // [2]

   return 0;  
}  
```

The secret is generated using an [Elliptic Curve Diffie-
Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
key exchange. Hence, the server private key is retreived in [0] using a call
to `get_own_privkey` and the Diffie-Hellman shared secret is computed in [1].
Finally, the computed secret is copied in [2] to the output buffer.  
However, there is an issue with this copy since `sizeof(secret)` isn't
equivalent to `sizeof(uint8_t secret[32])` but to `sizeof(uint8_t*)` since
`secret` is a parameter of the function. This means that only *4 bytes* of the
shared key are copied which allow us to perform a **brute force** to retrieve
the key.

**Note**: I did not try to build the application during the CTF, however, I
guess that the vulnerability can be easily found by looking at the compiler
warnings:

```  
$ cat main.c  
#include <stdio.h>  
#include <stdint.h>

void test(uint8_t buffer[32])  
{  
   printf("sizeof(buffer): %lu\n", sizeof(buffer));  
}

int main()  
{  
 test(NULL);  
 return 0;  
}  
$ gcc main.c  
main.c:6:43: warning: sizeof on array function parameter will return size of
'uint8_t *' (aka 'unsigned char *') instead of 'uint8_t [32]' [-Wsizeof-array-
argument]  
   printf("sizeof(buffer): %lu\n", sizeof(buffer));  
                                         ^  
main.c:4:19: note: declared here  
void test(uint8_t buffer[32])  
                 ^  
1 warning generated.  
```

To be able to perform a brute-force attack we must find a **stop condition**
in order to know if the *generated key* is valid or not (without testing
directly on the server). If we look at the generated OTP we can see that the
block is mostly filled with zeros so we will use that as a stop condition:

```c  
static void generate_otp(uint8_t epoch[8], char otp[32])  
{  
   // [...]  
   snprintf(otp, 32, "%010d", truncated_hash);  
}  
```

## Exploit

To find the right key, I performed a [simple brute-force](./aes-bf.c) loop
using `OpenSSL`:

```c  
   for (; *i_ptr < BF_MAX_VALUE; *i_ptr+=1)  
   {  
       if (*i_ptr % PRINT_STEP == 0)  
           printf("%#llx\n", (*i_ptr)/PRINT_STEP);

       memset(iv, 0, 0x10);

       AES_set_decrypt_key(user_key, 32*8, &aeskey);  
       AES_cbc_encrypt(ciphertext, cleartext, 16, &aeskey, iv, 0);

       if (*(uint32_t*)&cleartext[12] == 0)  
       {  
           printf("[+] Potential key found:\n");  
           hexdump(user_key, 32);  
           printf("Cleartext:\n");  
           hexdump(cleartext, 32);  
       }  
   }  
```

Compiling and running the script quickly lead to the valid key:

```  
$ gcc -lssl -lcrypto -o aes-bf aes-bf.c  
$ ./aes-bf  
[+] Potential key found:  
c2 13 ed 25 00 00 00 00 00 00 00 00 00 00 00 00  
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Cleartext:  
30 33 36 32 36 32 34 33 32 34 00 00 00 00 00 00  
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  
```

We can finally get the flag using this [Python script](./solve.py):

```  
$ python solve.py  
Here is the flag: Congratulation! Here's the flag: CTF{RustFTW!}.  
```

Original writeup (https://github.com/Team-Izy/Donjon-
CTF-2021-writeups/tree/main/crypto/magic-otp).Sources are provided. HTTP server is not really interesting, it does some
bookkeeping, returns ECDH-encrypted OTP when asked and the flag when called
with correctly decrypted (and not stale) OTP. The actual work is in LedgerNano
app; both server and client are provided, the crypto part is the following
code:  
```  
#include <stdlib.h>  
#include <string.h>

#include "cx.h"  
#include "ox.h"  
#include "os_seed.h"

#include "crypto.h"

void get_own_privkey(cx_ecfp_private_key_t *privkey)  
{  
   uint8_t privkey_data[32];  
   uint32_t path[5] = { 0x8000000d, 0x80000025, 0x80000000, 0, 0 };

   os_perso_derive_node_bip32(CX_CURVE_256K1, path, 5, privkey_data, NULL);  
   cx_ecfp_init_private_key(CX_CURVE_256K1, privkey_data,
sizeof(privkey_data), privkey);  
   explicit_bzero(&privkey_data, sizeof(privkey_data));  
}

int get_own_pubkey(cx_ecfp_public_key_t *pubkey)  
{  
   cx_ecfp_private_key_t privkey;  
   get_own_privkey(&privkey);

   cx_err_t err = cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, pubkey,
&privkey, 1);  
   explicit_bzero(&privkey, sizeof(privkey));  
   if (err != CX_OK) {  
       return -1;  
   }

   return 0;  
}

int get_pubkey(uint8_t out[65])  
{  
   cx_ecfp_public_key_t server_pubkey;

   if (get_own_pubkey(&server_pubkey) != 0) {  
       return -1;  
   }

   size_t size = server_pubkey.W_len;  
   if (size > 65) {  
       size = 65;  
   }

   memcpy(out, server_pubkey.W, size);

   return (int)size;  
}

static int get_shared_secret(cx_ecfp_public_key_t *pubkey, uint8_t secret[32])  
{  
   cx_ecfp_private_key_t privkey;  
   uint8_t out[32];  
   cx_err_t ret;

   get_own_privkey(&privkey);  
   ret = cx_ecdh_no_throw(&privkey, CX_ECDH_X, pubkey->W, pubkey->W_len,  
                          out, sizeof(out));

   explicit_bzero(&privkey, sizeof(privkey));  
   if (ret != CX_OK) {  
       return -1;  
   }

   memcpy(secret, out, sizeof(secret));

   return 0;  
}

int encrypt_otp_helper(cx_ecfp_public_key_t *pubkey, uint8_t otp[32], uint8_t
out[32], bool decrypt)  
{  
   uint8_t secret[32] = { 0 };  
   if (get_shared_secret(pubkey, secret) != 0) {  
       return -10;  
   }

   cx_aes_key_t key;  
   cx_err_t err = cx_aes_init_key_no_throw(secret, sizeof(secret), &key);

   explicit_bzero(secret, sizeof(secret));  
   if (err != CX_OK) {  
       return -11;  
   }

   size_t out_len = 32;  
   int flag = CX_CHAIN_CBC | CX_LAST | ((decrypt) ? CX_DECRYPT : CX_ENCRYPT);  
   err = cx_aes_iv_no_throw(&key, flag, NULL, 0,  
                            otp, 32, out, &out_len);

   explicit_bzero(&key, sizeof(key));  
   if (err != CX_OK) {  
       return -12;  
   }

   return out_len;  
}  
```  
The rest is more bookkeeping, the server app stores public keys of all
clients, the client app decrypts OTP given encrypted data and server's public
key. OTP itself is 10 digits right-padded to 32 bytes with zeroes; since AES
block size is 16 bytes, it means that the second block is all-zeroes, CBC-
encrypting all-zeroes block gives the condition `encryptedBlock2 ==
AESEncrypt(key, encryptedBlock1)`. However, this has no consequences by itself
(assuming AES is solid).

Can you see a bug in the code above? There is one :)

After reading all the sources for the fifth time, I noticed that there are too
much `sizeof`s and too much array-to-pointer decays; in C, using `type
array[number]` as a function argument actually works as `type* array` for all
purposes, including `sizeof` (C++ behaves the same way on the same code, but
also provides references-to-arrays `type (&array)[number]` for fixed-length
arrays and `std::span` for pairs of pointer+length), so I specifically looked
whether these two come together somewhere. Indeed, `get_shared_secret` takes
pointer-instead-of-array `secret` and copies only `sizeof(secret)=4` bytes of
the generated secret; the rest is initialized by zeroes in the caller, so
there are only `2**32` possible keys, these can be bruteforced in reasonable
time.

PyCryptodome that I usually use seems to be quite slow for this task, so I
have resorted to plain C based on [openssl wiki
example](https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption),
based on sample encrypted OTP from the server for device #0 (checker uses the
aforementioned condition, although directly checking that AESDecrypt(block1)
has digits and zeroes is equally valid):  
```  
#include <openssl/conf.h>  
#include <openssl/evp.h>  
#include <openssl/err.h>  
#include <string.h>

void handleErrors(void)  
{  
   ERR_print_errors_fp(stderr);  
   abort();  
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,  
           unsigned char *iv, unsigned char *plaintext)  
{  
   EVP_CIPHER_CTX *ctx;

   int len;

   int plaintext_len;

   /* Create and initialise the context */  
   if(!(ctx = EVP_CIPHER_CTX_new()))  
       handleErrors();

   /*  
    * Initialise the decryption operation. IMPORTANT - ensure you use a key  
    * and IV size appropriate for your cipher  
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The  
    * IV size for *most* modes is the same as the block size. For AES this  
    * is 128 bits  
    */  
   if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv))  
       handleErrors();  
   if(1 != EVP_CIPHER_CTX_set_padding(ctx, 0))  
       handleErrors();

   /*  
    * Provide the message to be decrypted, and obtain the plaintext output.  
    * EVP_DecryptUpdate can be called multiple times if necessary.  
    */  
   if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
ciphertext_len))  
       handleErrors();  
   plaintext_len = len;

   /*  
    * Finalise the decryption. Further plaintext bytes may be written at  
    * this stage.  
    */  
   if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))  
       handleErrors();  
   plaintext_len += len;

   /* Clean up */  
   EVP_CIPHER_CTX_free(ctx);

   return plaintext_len;  
}

int main()  
{  
	static unsigned char bytes[32] = {  
0x6c,0x0f,0x0b,0xf1,0x15,0xb5,0x99,0x95,0xae,0x03,0xdb,0x36,0x3b,0x5e,0x84,0x8f,  
0x5c,0x88,0xe2,0x32,0x97,0x99,0xd4,0x04,0x1e,0xbd,0xfd,0x05,0x94,0x88,0x7f,0xe1,  
	};  
	unsigned char decrypted[16];  
	unsigned char key[32] = {0};  
	unsigned k = 0;  
	for (;;) {  
		if (k % (1 << 24) == 0) {  
			printf(".");  
			fflush(stdout);  
		}  
		memcpy(key, &k, 4);  
		decrypt(bytes+16, 16, key, NULL, decrypted);  
		if (memcmp(decrypted, bytes, 16) == 0) {  
			printf("%X\n", k);  
			break;  
		}  
		if (++k == 0)  
			break;  
	}  
	return 0;  
}  
```  
I'm not sure whether PyCryptodome is really significantly slower due to Python
stuff, or plain OpenSSL was able to use hardware-assisted AES in my notebook,
but OpenSSL-version turned out to be much faster and took just several minutes
to find the key: `b'\x81\xDA\x03\x39'`. Decrypting OTP after those several
minutes is too late, so one more request for encrypted OTP is needed,
decrypted with already-known key; presented with decrypted OTP, the server
responds with flag `CTF{RustFTW!}`.