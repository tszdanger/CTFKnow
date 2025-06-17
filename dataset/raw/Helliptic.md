The server is written in NodeJS, full sources are provided. package.json:  
```  
{  
 "name": "helliptic",  
 "version": "1.0.0",  
 "description": "",  
 "main": "index.js",  
 "dependencies": {  
   "elliptic": "^6.5.3",  
   "express": "^4.17.1",  
   "joi": "^17.3.0",  
   "x509": "^0.3.4"  
 },  
 "devDependencies": {},  
 "scripts": {  
   "test": "echo \"Error: no test specified\" && exit 1"  
 },  
 "author": "[email protected]",  
 "license": "ISC"  
}  
```  
```  
$ npm install [email protected]

added 8 packages, and audited 9 packages in 2s

1 moderate severity vulnerability

To address all issues, run:  
 npm audit fix

Run `npm audit` for details.  
$ npm audit  
# npm audit report

elliptic  <6.5.4  
Severity: moderate  
Use of a Broken or Risky Cryptographic Algorithm -
https://github.com/advisories/GHSA-r9p9-mrjm-926w  
...  
```  
The advisory link gives away half of solution (and the linked blogpost
[https://github.com/christianlundkvist/blog/blob/master/2020_05_26_secp256k1_twist_attacks/secp256k1_twist_attacks.md](https://github.com/christianlundkvist/blog/blob/master/2020_05_26_secp256k1_twist_attacks/secp256k1_twist_attacks.md)
explains everything in details in case you have never heard about it before).

Most of crypto code is contained in encryption.js:  
```  
'use strict';

const crypto = require("crypto");

module.exports = { decrypt, encrypt };

function big_int_to_buffer(n, size) {  
   var s = BigInt(n).toString(16);  
   while (s.length < size * 2) {  
       s = '0' + s;  
   }  
   return Buffer.from(s, 'hex');  
}

function kdf(secret) {  
   const key = big_int_to_buffer(secret, 32);  
   return crypto.createHash('sha256').update(key).digest();  
}

function encrypt(text, secret, iv) {  
   const key = kdf(secret);  
   iv = big_int_to_buffer(iv, 16);  
   const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);  
   return cipher.update(text, "utf-8", "hex") + cipher.final("hex");  
}

function decrypt(encrypted, secret, iv) {  
   const key = kdf(secret);  
   iv = big_int_to_buffer(iv, 16);  
   const cipher = crypto.createDecipheriv("aes-256-cbc", key, iv);  
   return cipher.update(encrypted, "hex", "utf-8") + cipher.final("utf-8");  
}

module.exports = { big_int_to_buffer, decrypt, encrypt };  
```

Two remaining js files, db.js and index.js have too much boring bookkeeping to
recite them here, but in short, there are two types of users, those who have
provided a secp256k1 public key (`e2e` is `true`) and those who let the server
process everything for them (`e2e` is `false`). The server publishes public
keys for all users. For `e2e` users, that's all. For other users, the server
also keeps the corresponding private key and encrypts/decrypts their messages
via code above, where `secret` is calculated in the following way:  
```  
const EC = require('elliptic').ec;  
var ec = new EC('p256');

class User {  
...  
   derive_secret(pubkey) {  
       if (this.e2e) {  
           throw `User.derive_secret() can't be called when end-to-end encryption is enabled`;  
       }  
       return ec.keyFromPrivate(this.key, 'hex').derive(pubkey);  
   }  
...  
}  
```  
In other words, a message between two users is encrypted with AES using sha256
of the shared secret as a key, and the shared secret is ECDH-standard
x-coordinate of (public key of one user) multiplied by (private key of another
user).

`jane` uses e2e; we can login as her and get the message mentioned in the
description, but the server can only serve the message in encrypted form
(together with IV; right now neither of that gives any information beyond the
length, but let's save both the encrypted message and the IV for later), her
private key remains unknown.

`markz` does not use e2e, so the server knows his private key and will decrypt
and encrypt messages on his behalf. First, let's try to talk them while
registered as a normal user... he instantly responds with "Hello and thanks
for your message. I'm currently out of the office until 12/21 with no access
to Internet. If your request is urgent, please contact me by phone."
regardless of an incoming message, and even ignoring whether an incoming
message is correctly encrypted.

Next, talk to `markz` after registering with a fake public key that has a
small order. The shared secret is calculated as (his private key) multiplied
by our fake public key; due to a small order, only a small number of points
are possible as the result, we can enumerate them all and find the one that
correctly decrypts his message. I have used the fact that he always responds
with the same phrase, so decrypting the first AES block is sufficient (the
"honest" way would be to fully decrypt and check a padding, but it would take
longer and give many false positives because 01 as the last byte makes a valid
padding and has quite large probability of 1/256 to appear). Also, the server
chooses IV as big-endian representation of the current timestamp, so first 8
bytes are zero and first 8 bytes of a correctly decrypted block must match
"Hello an" (that does not change the big picture, but simplifies code a bit).

Prepare a fake public key (SageMath):  
```  
p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff  
E=EllipticCurve(GF(p),
[-3,0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b])  
G=E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)  
n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551  
def tobytes(e):  
 return
(b'\x04'+int(e[0].lift()).to_bytes(32,byteorder='big')+int(e[1].lift()).to_bytes(32,byteorder='big')).hex()

x=GF(p).random_element()  
y=GF(p).random_element()  
E2=EllipticCurve(GF(p),[-3,y^2-x^3+3*x])  
E2(x,y)  # just checking it does not result in exception  
factor(E2.order())  
```  
If factoring takes too long or if the factorization has no small factors,
repeat. For example, my first factorization happened to be `2^6 * 3 *
447861143 * 1571582181773 * 28692314881667862244477519 *
29862873354695120327357319337`; one possible fake key of order 447861143 is  
```  
tobytes(E2(x,y)*(E2.order()//447861143))  
```  
i.e.
`04efda69d736389cbb05b2ab483a76d2f4f1bd09aeb635f92ed8898578b5c633352a1dd828068075a4ee8bff5c5e86f57eaf14a3c7ea9ff03998e57ec25f244f54`.

Register with this key, send random bytes to `markz` (he ignores the content
anyway) and get his answer (Python):  
```  
import sys  
import requests

pubkey = sys.argv[1]

s = requests.Session()  
r = s.post('http://helliptic.donjon-ctf.io:8001/api/user/signup',  
	json={"name":"meltdown","password":"cKrBpt8I8LDABxd7oQlX","public_key":pubkey})  
r.raise_for_status()  
r = s.post('http://helliptic.donjon-ctf.io:8001/api/message/send',  
	headers={'Authorization': 'YoloSecure bWVsdGRvd246Y0tyQnB0OEk4TERBQnhkN29RbFg='},  
	json={"to":"markz","iv":1638882718261,"message":"00"*16})  
r.raise_for_status()  
while True:  
	r = s.get('http://helliptic.donjon-ctf.io:8001/api/message/1',  
		headers={'Authorization': 'YoloSecure bWVsdGRvd246Y0tyQnB0OEk4TERBQnhkN29RbFg='})  
	if r.status_code == 200:  
		break  
print(r.json()["message"])  
r = s.delete('http://helliptic.donjon-ctf.io:8001/api/user/delete',  
	headers={'Authorization': 'YoloSecure bWVsdGRvd246Y0tyQnB0OEk4TERBQnhkN29RbFg='})  
r.raise_for_status()  
```  
(the password is generated for this challenge, don't bother trying to hack
into my account with it :) API and authorization are boring parts that I have
skipped in the description above). With this particular key, the response of
`markz` is
`1c54630576b7d5104eee2106e39849a744389ba5b8ccd4b2be88d99a41bf6e1b48d372558b1c6eca2b8571abf72f2343736a7aef1ac0f81b0246a2efd14432f4`  
`f748bffe489257fa035ace73c1b4989121ac49b00400976225b13cd0f1bdaec299763b2cf1da59674c06563f7df4640e5e3882f0703b577e1bb27caa693612ed`  
`c946198b77f685410ba962e37cf68fd249c21146c70b4d3bfe632641f746626993e2d856171c527c8b52427bb69a4777`.

Find the shared secret and, correspondingly, private key modulo the order of
fake key (I did this task after Magic OTP, so basing on code for that
challenge was a natural choice):  
```  
#include <openssl/conf.h>  
#include <openssl/ec.h>  
#include <openssl/evp.h>  
#include <openssl/err.h>  
#include <openssl/sha.h>  
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

int main(int argc, char* argv[])  
{  
	if (argc != 3) {  
		printf("Usage: %s <publickey> <message>\n", argv[0]);  
		return 1;  
	}  
	if (strlen(argv[1]) != 65*2 || argv[1][0] != '0' || argv[1][1] != '4') {  
		printf("Invalid publickey, expected hex 04...\n");  
		return 1;  
	}  
	static const char phex[] = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";  
	static const char expected[] = "Hello and thanks"; // XORed with IV but whatever, first 8 bytes are not modified  
	long msglen = strlen(argv[2]);  
	unsigned char* message = OPENSSL_hexstr2buf(argv[2], &msglen);  
	if (!message || msglen < 16) {  
		printf("Invalid message, expected >= 16 hex bytes\n");  
		return 1;  
	}  
	BIGNUM* p = NULL;  
	if (BN_hex2bn(&p, phex) != 64)  
		handleErrors();  
	BIGNUM* x = NULL;  
	BIGNUM* y = NULL;  
	char* xhex = argv[1] + 2;  
	char* yhex = xhex + 64;  
	char tmpchar = *yhex;  
	*yhex = 0;  
	if (BN_hex2bn(&x, xhex) != 64)  
		handleErrors();  
	*yhex = tmpchar;  
	if (BN_hex2bn(&y, yhex) != 64)  
		handleErrors();  
	BIGNUM* tmp = BN_new();  
	if (!tmp)  
		handleErrors();  
	BIGNUM* tmp2 = BN_new();  
	if (!tmp)  
		handleErrors();  
	BN_CTX* ctx = BN_CTX_new();  
	if (!ctx)  
		handleErrors();  
	// y^2 - (x^3-3x)  
	BIGNUM* three = BN_new();  
	if (!three || !BN_set_word(three, 3))  
		handleErrors();  
	if (!BN_mod_sqr(tmp, x, p, ctx))  
		handleErrors();  
	if (!BN_mod_sub(tmp, tmp, three, p, ctx))  
		handleErrors();  
	if (!BN_mod_mul(tmp, x, tmp, p, ctx))  
		handleErrors();  
	if (!BN_mod_sqr(tmp2, y, p, ctx))  
		handleErrors();  
	if (!BN_mod_sub(tmp2, tmp2, tmp, p, ctx))  
		handleErrors();  
	// EllipticCurve([-3,tmp2])  
	if (!BN_sub(tmp, p, three))  
		handleErrors();  
	EC_GROUP* ec = EC_GROUP_new_curve_GFp(p, tmp, tmp2, ctx);  
	if (!ec)  
		handleErrors();  
	EC_POINT* basepoint = EC_POINT_new(ec);  
	if (!basepoint || !EC_POINT_set_affine_coordinates(ec, basepoint, x, y, ctx))  
		handleErrors();  
	EC_POINT* current = EC_POINT_new(ec);  
	if (!current || !EC_POINT_copy(current, basepoint))  
		handleErrors();

	unsigned result = 1;  
	for (;;) {  
		unsigned char xbytes[32];  
		unsigned char key[32];  
		unsigned char decrypted[16];  
		if (!EC_POINT_get_affine_coordinates(ec, current, x, y, ctx))  
			handleErrors();  
		if (BN_bn2binpad(x, xbytes, 32) != 32)  
			handleErrors();  
		SHA256_CTX sha256;  
		SHA256_Init(&sha256);  
		SHA256_Update(&sha256, xbytes, 32);  
		SHA256_Final(key, &sha256);  
		decrypt(message, 16, key, NULL, decrypted);  
		if (memcmp(decrypted, expected, 8) == 0) {  
			printf("%u\n", result);  
			break;  
		}  
		if (!EC_POINT_add(ec, current, current, basepoint, ctx))  
			handleErrors();  
		if (EC_POINT_is_at_infinity(ec, current)) {  
			printf("not found\n");  
			// memory leaks but who cares  
			return 1;  
		}  
		++result;  
		if (result % (1u << 20) == 0) {  
			printf(".");  
			fflush(stdout);  
		}  
	}  
	// memory leaks but who cares  
	return 0;  
}  
```  
This stage defines what exactly "small order" means - any order such that the
bruteforce at this stage takes no longer than you are ready to wait. For my
notebook, 447861143 turned out to be relatively large; I left it running while
doing other keys in parallel (after all, my notebook has more than one CPU
core), but for further curves, only took order-of-magnitude-lesser factors.

Anyway, repeat the process while the product of fake orders is less than the
real order. In my case, the restored remainders are:  
```  
modulus 447861143:  
./a.out
04efda69d736389cbb05b2ab483a76d2f4f1bd09aeb635f92ed8898578b5c633352a1dd828068075a4ee8bff5c5e86f57eaf14a3c7ea9ff03998e57ec25f244f54
1c54630576b7d5104eee2106e39849a744389ba5b8ccd4b2be88d99a41bf6e1b48d372558b1c6eca2b8571abf72f2343736a7aef1ac0f81b0246a2efd14432f4f748bffe489257fa035ace73c1b4989121ac49b00400976225b13cd0f1bdaec299763b2cf1da59674c06563f7df4640e5e3882f0703b577e1bb27caa693612edc946198b77f685410ba962e37cf68fd249c21146c70b4d3bfe632641f746626993e2d856171c527c8b52427bb69a4777  
161541777

modulus 29*1370723:  
$ time ./a.out
0411e2c78adadc9bf5bbc658843c1bad7f0e807ad90e1d8fd0ec00355adc008243c0e4d7306626a2e7037312000dffae0926f66676a21409597a59ecbf2015ea4e
f5baf07f5238186df3d6020dae4c3b7a54b216fa759e4aafa560cf425cb2ccee16dd95e129e9a9609891e1ba6bd06e170e739aa6cca320b8e081e93759cf76c7737555805ae6a6cc20d8e4d4f49b64cc37252b9e87d9db7594b8474b0760e2579165bc441b4bbb62a714f5e375da9ba8e78d031c398a6e5dc8b001a750300c4a51e4721eed336e6ce75fafc80475b4e9bae04bb1e3c2aeb31c28a9e8c0b27b3d28560e735db89331e6cf64ef6195219f  
12531341  
real    2m36.310s  
user    2m36.288s  
sys     0m0.020s

modulus 5*11*957349:  
$ time ./a.out
04e507dce34b39618624f0ff913c022306a1e672afd992927aa73521c6c64af7c115c31b013673728411cab237bfd34b43fa71ab9374ceae74933a21c9a9a7be81
2c421a9fec803ad1fea5dfe67c9c3ed5babb187361df8b076dfaa5d34511076e0e82bc34e87c0ed96b6ee362c3285f8b6227ed2975a79435dcb13f7a13a809f1e2ca7fd7c3363dbe23b04df03f8a88e08ce1b44e85051b49c5a96ec9ca9f32906ccadac5757d0fcbaf2227a0057a0c0875c62a5c60a24c768e230b2e95e63cc9ab06c984b68156c012d9f7248bd5fe720af5be997a5dd93186d760a1313e5d222189f23f6495f1efeb8c1633c07513e8  
12559028  
real    2m35.850s  
user    2m35.847s  
sys     0m0.000s

modulus 3*13*109*1019:  
$ time ./a.out
04aadab119410bf690be4832ff4453296cd6e5db988de14cc82f11519b75435e3e03d20e8c5ab90c12b9f6b55e14b342d7ee60446bffce7557bdddf4d04092ab21
adb4f718b089bc8951426b96151b19aae4d99b65c0e70d9a1cd966c2c1c15322a1250ee4106a791f751367dedafdd045fa4f65e92c90d7cd21799494451c0417d1cf5bf3232881e8cb8920939af6677d9481761572424eead8bcff659de05b22d383118cf2437023b4332dcc1d4135b9ec3f08672eff142726fa84a0019b59ec85c6e75b50ba1978bbe28559ed9fe61cb9890680dbbfc89d76d33f13c05fe4ef3665bf564150bf788e2f228d0c24757e  
1232045  
real    0m15.826s  
user    0m15.822s  
sys     0m0.000s

modulus 855511:  
$ time ./a.out
0479217a27e92fb3cf6527b6d9b962f8f6b1807aa98c2e1b3ca810e1f61b72d642b0762c31effc94b5e0fa9148f159adf364eccaa01948bc0c0ce790e54c9369fa
8c7ea45534ecd803c1243c1cfa71b27b771dd2adb379a32c381a95dbb23467941b0537416937ebe6add5da1984a650f995374ebf4ac1ee5acc593bc58b9cbb489bf0cfddbfcf656a6182a1947e50850d18464b66af0787072ce89730bbc192fba88877d605776207c99fe3e182be893022f3babbace767c90ec300f571cc5b337582d8eb93806c5eca14891dccbda09f2dc23fecd65c180b55c501aab392881f1d086f6d9fa9583af1039c1bbf8ff51d  
318387  
real    0m3.845s  
user    0m3.842s  
sys     0m0.000s

modulus 1480429:  
$ time ./a.out
04c48a0b3e6938ab471a383d7b25934c111282face880c13c05eaa22204588724fa65a4fcfa19859f43d970e626bf98ab5180000f2829c0a2228d59f84a236ddd0
3cb82f5eedcd692e4255a8488410fec9fc4bf76df742e5b8b9dd3b56db4c8bde07d93e41ca2cafc4685f1af81aba22f902f708536d2c2e043f5dd06abe7a9d281b01b54f6551a6b5cbe1080babeb6a783ee15933c03876a0c6e2a3027aec94b9afaff9e731ef9ff5315d6b7477dfc533f939c33e6eeccacf3051597ae6129dfdec7529f41c8cd6ab965180ce10fea339940f01506e46d069d1243bedc4a8314951ee4db37850052b7d2df000c80e9fba  
448612  
real    0m5.285s  
user    0m5.282s  
sys     0m0.000s

modulus 419*4073:  
$ time ./a.out
04223e5cc2988abc5730f98359532b58026d847fb68f52227f6ac1f0483b4169c6a283a10a44fa9449751f3cc875efcaadf39ae2333e495dee2b928dbb1c5bea2a
19650a19e52378d7b11a8c5cccfe64c286b15c0e0ba001534a5e47dac0270d390e86ba83ddf763003190feec3c84133d4f3d3c09d1b3d5a616beb4881c30a063fc2fbd92dae64b2e64976a7cd3868cfda25685dd2c76142231f5ec7e20f7a647f38f6342970559e00364f80052f7d3ecd4601d252545bcae299cb4c769f9891b6b2525c207ec7b9e04b6bb448ecf5e57486495676d366714e860116f193611bd9fbe70cc69e3de242ae760cc84ff70ce  
130219

real    0m1.532s  
user    0m1.528s  
sys     0m0.001s

modulus 102301:  
$ time ./a.out
04936b35fab62235eeefd3d5ff6f5e117dc033a33c973f7262b8634053ae1df3177050b84898ab419194c01d5eea36cccebaba334cbde47632ea223bb04cc2bd27
5484c83c09021ec17f15b425d1c223c9aba0c2fc7747a96703b46bd84ecb2791e0e3ceb786ae82fa2247fa040bc97b65064bc83264d03fb87de1d3f13a2dccb0da29b1e3cff960346411e244535602346e2b9e50506d188f4c615fac88abf359f6a40f6e055b39a19b29b23920e75fbd7098255f41df2a483e374761578b94cb102a8dc48ec18b33de47ffcfb6fe5e081908ddcdc93485dbf6b36b9b6d94c6f08c9b05b7bb5574acf30d67934c806885  
18101

real    0m0.216s  
user    0m0.213s  
sys     0m0.000s

modulus 197*44293:  
$ time ./a.out
044c32c9bfc3924dc1d93feaeb1254a9944944caae6c7c025dea5994b10b797a91179e41444d7bcf194a7d8736120f9a6727666b460fb9b9c6ce74dcf3674c3b92
34a2e61387175fdf1f33603fea9e442260c2e293286d8ddd0f5fa9b38e667eb9357757528fc9d3478c18ce46a7773bdc5905b469b1fb3cbcd34c0f4ff06e6b1a34c2bef0d27e499a45d803df95bedc49395a43b536e9d8a313e52b62d4e9f1f08588dc2a7b859669f64ce4ebd58baecd2ac8b5a45cf41f7d3b1df455d2c8dae62be3b2fd71b3d2899bdbdfd723fb182c138d4b7fb71e3bc2d8aad3bcd5cc9c56c18b9d53206135f5898f6ebd862a6253  
2938518

real    0m34.670s  
user    0m34.666s  
sys     0m0.000s

modulus 5366377:  
$ time ./a.out
046d73a6fc54d3fd06175afa9cb83f7f35fe1366a5ebab02f3a0247fc5190b2546d313de1491bcfb0fbbc1d7fdaa9dd37b58a833f2698c1d5c0f9061c2729c1dc5
1a0ed8758c0c66fc4990620bfe6f05c097aaed4d001647284fc3bcb62d250267330ce7ec781752b6c7a14d715e0e0a1dc1da4f9418a5d47ab3a215e53810d48f6bcb9a61053650663b473d68876da542b2ddee94b79ea37962d78925cad7d4436ee29ddca1bf4fb0e5f2f8ec7a75d776da3dfe01a5f229757977ec89cc0eebd8cc8437bebb8e8f31538435295d38b3c3a5554628dd22345bb5c3d97da98b03c78e3a33134b1d4d3d6a86de723358b16f  
1824594

real    0m21.436s  
user    0m21.432s  
sys     0m0.000s

modulus 823663:  
$ time ./a.out
0404aad783f3e724ae6888efe5016403619a0db8bc46436de57b30beddaf6b8ebe916b3dbbe426b90e8ed8449a7c38eaf1f021d356e06b1ae0a9eba5cb3da90e6e
fa5de5eaf81647df98c5500d111a7796b7640bbf93b02215dc71c77e0083496542c235a5cd179fc94ba2008060e68ebac49a2cd33b4dbbd4324841c08645fcb211491cd165233df68c4dfd5aa9aac3a1ced9308f5605ab28984616c3067ebcc2e1f7d861a398a749a850a6c7bb5e5261490431a3e965f38009499ff705c51d3715eb7f9c9c97351077408f25e029cccf5df851f128c0dfb662635deca11f899d09019ac6657a3b5fa83bcb9bf611853d  
20834

real    0m0.249s  
user    0m0.246s  
sys     0m0.000s

modulus 2339921:  
$ time ./a.out
043f1f074adc3ae9db289134cfd6d3d990258529fa19d313cb845afe8e70749446385c8026f100dd480f46f6108654f47fa91dd78697b482d6bf720a03f95a6fde
a51829c50608e6710d55e6af2fc3ef14a23acebf87f498f636c8a6f1535241be5c384afe0babe22451395a31115bc243d821a3eb31509c0c835b8195715ba37add63f6a62f97bf46d877b09b8d43e64251d2397873b5784cb47f3aea813a937926e5d49472beed4e9eb093a6550a19b9b27f6a1f26b428e0637bf90b72b8043356cce632755dc0fc707ac3b4b65a45a1d817a942fdff4527cf201ade284108cd0da4a31b5574decf3bf4da918e644976  
265636  
real    0m3.123s  
user    0m3.119s  
sys     0m0.001s  
```

With enough known remainders, throw everything to SageMath:  
```  
CRT(  
[161541777,12531341,12559028,1232045,318387,448612,130219,18101,2938518,1824594,20834,265636],  
[447861143,29*1370723,5*11*957349,3*13*109*1019,855511,1480429,419*4073,102301,197*44293,5366377,823663,2339921]  
)  
```  
...and the result is too big for a private key and does not match a public
key.

Since ECDH only uses x-coordinate, two points +P and -P will result in the
same shared secret, so if the bruteforce has found a remainder `r`, the actual
remainder can be either `+r` or `-r`. The true private key should be less than
order of the curve, so:  
```  
import itertools  # I have never bothered to get external modules into
SageMath but standard ones just work  
n = E.order()  
for i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12 in
itertools.product([-1,1],repeat=12):  
   k = CRT(  
[161541777*i1,12531341*i2,12559028*i3,1232045*i4,318387*i5,448612*i6,130219*i7,18101*i8,2938518*i9,1824594*i10,20834*i11,265636*i12],  
[447861143,29*1370723,5*11*957349,3*13*109*1019,855511,1480429,419*4073,102301,197*44293,5366377,823663,2339921]  
   )  
   if k < n:  
       print(k)  
```  
This gives 4 candidates; for all of them, compare `tobytes(<candidate>*G)`
with `markz`'s public key to reveal a match for
60396115384426505961049463727258194624965342467679972032839015354450233237757.

The rest is straightforward:  
```  
janeP = E(0xc91dc3dafc2e71e28c6f9d8128ec87baf55ee93df54a08429617b93a59806815,  
         0xd3998853c8f3d3b6bad426c8d667919863a719eede5fffa545a9e44644f0c731)  
hex((60396115384426505961049463727258194624965342467679972032839015354450233237757*janeP)[0])  
```  
returns
`'0xaa419c652a4fb57f8aade69643b2f7cf62d76f89408fde9142655e0ef78ed211'`. Then,  
```  
>>> from Crypto.Cipher import AES  
>>> import hashlib, struct  
>>>
AES.new(key=hashlib.sha256(bytes.fromhex('aa419c652a4fb57f8aade69643b2f7cf62d76f89408fde9142655e0ef78ed211')).digest(),
mode=AES.MODE_CBC,
iv=b'\0'*8+struct.pack('>Q',1632832394079)).decrypt(bytes.fromhex('989aab0d7210482b4e8e6f169debe88889d201474430cc906a1c9afc49295c292793eb607c1282491ab39640a1cb6320eb04503959cfad57de5f138413b8e54ee19301370ae397859f3d9b184d79506e'))  
b"Congratz! Here's the flag: CTF{PracticalInvalidCurveAttacksonTLS-
ECDH*}.\x08\x08\x08\x08\x08\x08\x08\x08"  
```