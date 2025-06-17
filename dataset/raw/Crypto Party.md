apk is provided. A random online decompiler transforms it into something
readable, but with obfuscated names of packages and classes.  
```  
import b.b.a.b;  
...  
   public class a implements b.b.a.c {  
       public a() {  
       }

       public void b(String qrCode) {  
           MainActivity.this.L();  
           String simpleName = MainActivity.class.getSimpleName();  
           Log.i(simpleName, "QR Code Found: " + qrCode);  
           if (b.b(MainActivity.this.getApplicationContext(), qrCode)) {  
               MainActivity.this.K();  
               return;  
           }  
           Toast.makeText(MainActivity.this.getApplicationContext(), b.d(qrCode), 1).show();  
           new Handler().postDelayed(new C0052a(), 3500);  
       }

       /* renamed from: com.learntodroid.androidqrcodescanner.MainActivity$a$a  reason: collision with other inner class name */  
       public class C0052a implements Runnable {  
           public C0052a() {  
           }

           public void run() {  
               MainActivity.this.K();  
           }  
       }

       public void a() {  
       }  
   }  
```  
There is a lot of code, mostly revolving around camera stuff and QR
recognition; it is important not to sink and look only for something that is
directly related to the task. MainActivity has several `if`-s related to
permissions and one `if` directly after logging a string "QR Code Found", the
latter should be investigated more closely:  
```  
package b.b.a;

import android.content.Context;  
import android.content.Intent;  
import android.net.Uri;  
import java.io.BufferedReader;  
import java.io.IOException;  
import java.io.InputStreamReader;  
import java.io.OutputStream;  
import java.net.URL;  
import java.nio.charset.StandardCharsets;  
import java.security.KeyManagementException;  
import java.security.NoSuchAlgorithmException;  
import java.security.SecureRandom;  
import java.security.cert.X509Certificate;  
import javax.net.ssl.HostnameVerifier;  
import javax.net.ssl.HttpsURLConnection;  
import javax.net.ssl.KeyManager;  
import javax.net.ssl.SSLContext;  
import javax.net.ssl.SSLSession;  
import javax.net.ssl.SSLSocketFactory;  
import javax.net.ssl.TrustManager;  
import javax.net.ssl.X509TrustManager;  
import org.json.JSONException;  
import org.json.JSONObject;

public class b {

   /* renamed from: a  reason: collision with root package name */  
   public static final byte[] f1173a = {9, 26, 16, 2, 28, 83, 75, 1, 19, 23,
11, 29, 29, 28, 94, 25, 14, 28, 90, 58, 111, 41, 42, 60, 43, 14, 0, 73, 17,
27, 15, 74, 71, 31, 95, 67, 93, 89, 67, 67, 70, 14, 29, 93, 38, 53, 62, 106,
61, 49, 4, 0, 59, 1, 0, 28, 22, 77, 21, 74, 27, 3, 13, 22, 11, 71, 7, 26, 67,
47};

   /* renamed from: b  reason: collision with root package name */  
   public static final byte[] f1174b = {9, 26, 16, 2, 28, 83, 75, 1, 19, 23,
11, 29, 29, 28, 94, 25, 14, 28, 90, 58, 111, 41, 42, 60, 43, 14, 0, 73, 17,
27, 15, 74, 71, 31, 95, 67, 93, 89, 67, 67, 70, 14, 30, 71, 108, 45, 40, 49,
13, 44, 4, 49, 13, 28};

   public static String e(byte[] a2) {  
       byte[] key = "android.permission.CAMERA".getBytes();  
       byte[] out = new byte[a2.length];  
       for (int i = 0; i < a2.length; i++) {  
           out[i] = (byte) (a2[i] ^ key[i % key.length]);  
       }  
       return new String(out, StandardCharsets.US_ASCII);  
   }

   public static HostnameVerifier a() {  
       return new a();  
   }

   public class a implements HostnameVerifier {  
       public boolean verify(String hostname, SSLSession session) {  
           return true;  
       }  
   }

   public static SSLSocketFactory c() {  
       try {  
           TrustManager[] trustAllCerts = {new C0051b()};  
           SSLContext sslContext = SSLContext.getInstance("SSL");  
           sslContext.init((KeyManager[]) null, trustAllCerts, new SecureRandom());  
           return sslContext.getSocketFactory();  
       } catch (KeyManagementException | NoSuchAlgorithmException e) {  
           return null;  
       }  
   }

   /* renamed from: b.b.a.b$b  reason: collision with other inner class name
*/  
   public class C0051b implements X509TrustManager {  
       public void checkClientTrusted(X509Certificate[] chain, String authType) {  
       }

       public void checkServerTrusted(X509Certificate[] chain, String authType) {  
       }

       public X509Certificate[] getAcceptedIssuers() {  
           return new X509Certificate[0];  
       }  
   }

   public static boolean b(Context context, String qrCode) {  
       if (!e(new byte[]{46, 62, 33, 60, 48, 58, 43, 123, 34, 38, 55, 50, 37, 58, 48, 44, 33, 61, 107, 16}).equals(qrCode)) {  
           return false;  
       }  
       Intent browserIntent = new Intent("android.intent.action.VIEW", Uri.parse(e(f1173a)));  
       browserIntent.addFlags(268435456);  
       context.startActivity(browserIntent);  
       return true;  
   }

   public static String d(String qrCode) {  
       try {  
           HttpsURLConnection con = (HttpsURLConnection) new URL(e(f1174b)).openConnection();  
           con.setHostnameVerifier(a());  
           con.setSSLSocketFactory(c());  
           con.setRequestMethod("POST");  
           con.setDoOutput(true);  
           OutputStream os = con.getOutputStream();  
           os.write(("{\"qrcode\": \"" + qrCode + "\"}").getBytes());  
           os.flush();  
           os.close();  
           int responseCode = con.getResponseCode();  
           if (responseCode == 200) {  
               BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));  
               StringBuffer response = new StringBuffer();  
               while (true) {  
                   String readLine = in.readLine();  
                   String inputLine = readLine;  
                   if (readLine == null) {  
                       break;  
                   }  
                   response.append(inputLine);  
               }  
               in.close();  
               try {  
                   JSONObject json = new JSONObject(response.toString());  
                   if (json.has("error")) {  
                       return "error: " + json.getString("error");  
                   } else if (json.has("message")) {  
                       return json.getString("message");  
                   } else {  
                       return "invalid JSON: " + response.toString();  
                   }  
               } catch (JSONException e) {  
                   return "failed to parse JSON response" + ": " + e;  
               }  
           } else {  
               return "failed to post HTTP request: HTTP reponse code = " + responseCode;  
           }  
       } catch (IOException e2) {  
           return "failed to post HTTP request: " + e2;  
       }  
   }  
}  
```  
Three byte arrays can be seen, obfuscated by XOR with
"android.permission.CAMERA":  
```  
>>> def deobfuscate(s):  
...  key = b'android.permission.CAMERA'  
...  return bytes([s[i] ^ key[i%len(key)] for i in range(len(s))])  
...  
>>> deobfuscate([46, 62, 33, 60, 48, 58, 43, 123, 34, 38, 55, 50, 37, 58, 48,
44, 33, 61, 107, 16])  
b'OPEN_SOURCE_LICENSES'  
>>> deobfuscate([9, 26, 16, 2, 28, 83, 75, 1, 19, 23, 11, 29, 29, 28, 94, 25,
14, 28, 90, 58, 111, 41, 42, 60, 43, 14, 0, 73, 17, 27, 15, 74, 71, 31, 95,
67, 93, 89, 67, 67, 70, 14, 29, 93, 38, 53, 62, 106, 61, 49, 4, 0, 59, 1, 0,
28, 22, 77, 21, 74, 27, 3, 13, 22, 11, 71, 7, 26, 67, 47])  
b'https://crypto-party.donjon-ctf.io:10000/assets/open_source/index.html'  
>>> deobfuscate([9, 26, 16, 2, 28, 83, 75, 1, 19, 23, 11, 29, 29, 28, 94, 25,
14, 28, 90, 58, 111, 41, 42, 60, 43, 14, 0, 73, 17, 27, 15, 74, 71, 31, 95,
67, 93, 89, 67, 67, 70, 14, 30, 71, 108, 45, 40, 49, 13, 44, 4, 49, 13, 28])  
b'https://crypto-party.donjon-ctf.io:10000/api/let_me_in'  
```  
The code treats them, in order, as some special value for QR code; url to
navigate to; url to POST json with qrcode.  
```  
$ curl https://crypto-party.donjon-ctf.io:10000/api/let_me_in -d
'{"qrcode":"OPEN_SOURCE_LICENSES"}'  
curl: (60) SSL certificate problem: self signed certificate  
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not  
establish a secure connection to it. To learn more about this situation and  
how to fix it, please visit the web page mentioned above.  
```  
Well, that explains why the code goes to some trouble with keyword
"X509Certificate".  
```  
$ curl https://crypto-party.donjon-ctf.io:10000/api/let_me_in -d
'{"qrcode":"OPEN_SOURCE_LICENSES"}' -k  
{"error":"invalid QR code: invalid prefix"}  
```  
The task is in crypto category, and so far there was nothing about crypto
(other tasks strongly suggest that this CTF does not treat XOR as real
crypto), so it would be more surprising if that curl had actually worked. (The
"special value for QR code" means NOT submitting it to the server and
navigating to another url instead... well, turns out it is not so special for
the server.)

`https://crypto-party.donjon-ctf.io:10000/assets/open_source/index.html` is a
listing with three Python files, this is where the real fun begins.

app.py:  
```  
#!/usr/bin/env python3

from flask import Flask, jsonify, redirect, request  
import os

import crypto_party

app = Flask(__name__, static_url_path="/assets/open_source",
static_folder="static/")

@app.route("/api/get_certificates", methods=["GET"])  
def get_certificates():  
   return jsonify(crypto_party.CERTS)

@app.route("/api/let_me_in", methods=["POST"])  
def let_me_in():  
   content = request.get_json(force=True, silent=True)  
   if content is None or "qrcode" not in content:  
       return jsonify({"error": "missing qrcode"})

   result = crypto_party.verify_qrcode(content["qrcode"])  
   return jsonify(result)

# @app.route("/", methods=['GET'])  
@app.route("/assets/open_source", methods=['GET'], strict_slashes=False)  
def redirect_to_index():  
   return redirect("/assets/open_source/index.html", code=302)

if __name__ == "__main__":  
   tls_cert = os.path.join(os.path.dirname(__file__), "data/https.pem")  
   app.run(host="0.0.0.0", port=10000, ssl_context=(tls_cert, tls_cert))  
```  
This shows the handler for already-known `/api/let_me_in` and reveals one more
API:  
```  
$ curl https://crypto-party.donjon-ctf.io:10000/api/get_certificates -k  
{"MDU5MWI1OWM=":[1,[64231366944007128611348919651104804909435973587058913853892482269232788324041,54772973722616689122700859762282578769822156610875026825025566223653351599293]],...,"MGIwOGUzZGM=":[0,[122866140422466013826785528118621422276782165937835130785806537381269517943199236220629107823703555638672818673422999715302638860711291136523826289175166844856649618910707312388536263738921504610024822114023925075691589276062913223225854523473602389281105109564818657926698862297561918920480184112846229228677,65537]],...  
```

qrcode.py:  
```  
import base64  
import cbor  
import zlib

from datetime import datetime, timedelta  
from typing import Union

BASE45_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"  
BASE45_DICT = {v: i for i, v in enumerate(BASE45_CHARSET)}

def b45decode(s: Union[bytes, str]) -> bytes:  
   """Decode base45-encoded string to bytes"""  
   try:  
       if isinstance(s, str):  
           buf = [BASE45_DICT[c] for c in s.strip()]  
       elif isinstance(s, bytes):  
           buf = [BASE45_DICT[c] for c in s.decode()]  
       else:  
           raise TypeError("Type must be 'str' or 'bytes'")

       buflen = len(buf)  
       if buflen % 3 == 1:  
           raise ValueError("Invalid base45 string")

       res = []  
       for i in range(0, buflen, 3):  
           if buflen - i >= 3:  
               x = buf[i] + buf[i + 1] * 45 + buf[i + 2] * 45 * 45  
               if x > 0xFFFF:  
                   raise ValueError  
               res.extend(divmod(x, 256))  
           else:  
               x = buf[i] + buf[i + 1] * 45  
               if x > 0xFF:  
                   raise ValueError  
               res.append(x)  
       return bytes(res)  
   except (ValueError, KeyError, AttributeError):  
       raise ValueError("Invalid base45 string")

class DecodingError(Exception):  
   pass

class CryptoId:  
   """QR code data decoder."""

   def __init__(self, data):  
       self.data = data

   def decode_qr_data(self):  
       if not self.data.startswith("LDG:"):  
           raise DecodingError("invalid prefix")

       try:  
           qr_data_zlib = b45decode(self.data[4:])  
       except ValueError as e:  
           raise DecodingError(e)

       try:  
           qr_data = zlib.decompress(qr_data_zlib)  
       except zlib.error as e:  
           raise DecodingError(e)

       cbor_value = cbor.loads(qr_data).value  
       if len(cbor_value) != 4:  
           raise DecodingError("invalid CBOR data")

       headers1, headers2, cert_data, signature = cbor_value  
       cert = cbor.loads(headers1)  
       if len(cert) != 2:  
           raise DecodingError("invalid CBOR value")

       if 1 not in cert or 4 not in cert or type(cert[1]) != int or type(cert[4]) != bytes or type(cert_data) != int:  
           raise DecodingError("invalid certificate parameters")

       if type(signature) != bytes:  
           raise DecodingError("invalid signature format")

       now = datetime.utcnow()  
       expired = datetime.utcfromtimestamp(cert_data)  
       if now > expired:  
           raise ValueError("cert has expired")  
       if (expired - now) > timedelta(days=1):  
           raise ValueError("cert aren't valid for more than 24 hours")

       signed_data = cbor.dumps(["Signature1", headers1, headers2, cert_data])

       self.cert_id = base64.b64encode(cert[4]).decode()  
       self.algo_index = cert[1]  
       self.signature = signature  
       self.signed_data = signed_data  
```  
Boring technical details of the format that `/api/let_me_in` expects: prefixed
by `LDG:`... base-45 encoded... zlib-compressed... CBOR tagged sequence of 4
items... where the last one is named `signature` and should be a binary
string, the third one is expiration timestamp that should be greater than the
current time but less than 24 hours in the future, the second one is ignored
and the first one should be a dictionary that maps key 1 to `algo_index` and
key 4 to a binary string that is used to initialize `cert_id`. Everything here
is easily invertible.

crypto_party.py, the real worker:  
```  
import abc  
import json  
import os

from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  
from cryptography.hazmat.primitives import hashes, serialization  
from cryptography.exceptions import InvalidSignature

import qrcode

ALGOS = ["rsa", "ec"]

class CertABC(metaclass=abc.ABCMeta):  
   ENCODING = serialization.Encoding.PEM  
   FORMAT = serialization.PublicFormat.SubjectPublicKeyInfo  
   SIG_ALGO = hashes.SHA1()

   @abc.abstractmethod  
   def verify(self, signature, data):  
       pass

   @abc.abstractmethod  
   def _public_key(self):  
       pass

   @property  
   def public_key(self):  
       return self._public_key.public_key(default_backend())

   def __str__(self):  
       pem = self.public_key.public_bytes(encoding=CertABC.ENCODING, format=CertABC.FORMAT)  
       return pem.decode("ascii")

class CertRSA(CertABC):  
   PADDING = padding.PSS(mgf=padding.MGF1(CertABC.SIG_ALGO), salt_length=0)  
   DEFAULT_EXPONENT = 65537

   def __init__(self, n, e=65537):  
       self.n, self.e = n, e

   @property  
   def _public_key(self):  
       return rsa.RSAPublicNumbers(self.e, self.n)

   def verify(self, signature, data):  
       self.public_key.verify(signature, data, CertRSA.PADDING, CertABC.SIG_ALGO)

class CertEC(CertABC):  
   CURVE = ec.SECP256K1()

   def __init__(self, x, y):  
       self.x, self.y = x, y

   @property  
   def _public_key(self):  
       return ec.EllipticCurvePublicNumbers(self.x, self.y, CertEC.CURVE)

   def verify(self, signature, data):  
       self.public_key.verify(signature, data, ec.ECDSA(CertABC.SIG_ALGO))

def Cert(algo, public_key):  
   klasses = {"rsa": CertRSA, "ec": CertEC}  
   return klasses[algo](*public_key)

def load_certs(path="data/certs.json"):  
   path = os.path.join(os.path.dirname(os.path.realpath(__file__)), path)  
   with open(path) as fp:  
       return json.load(fp)

def verify_signature(crypto_id):  
   cert = Cert(ALGOS[crypto_id.algo_index], CERTS[crypto_id.cert_id][1])  
   try:  
       cert.verify(crypto_id.signature, crypto_id.signed_data)  
   except InvalidSignature:  
       return {"error": "Please provide a valid QR code to enter the party."}  
   else:  
       flag = os.environ.get("FLAG", "CTF{FLAG environment variable is unset}")  
       return {"message": f"Welcome to the party! Here is your Free Drinks Voucher: {flag}."}

def verify_qrcode(data):  
   crypto_id = qrcode.CryptoId(data)

   # TODO: improve error handling  
   try:  
       crypto_id.decode_qr_data()  
   except qrcode.DecodingError as e:  
       return {"error": f"invalid QR code: {e}"}  
   except ValueError as e:  
       return {"error": f"invalid QR code: {e}"}

   if crypto_id.cert_id not in CERTS:  
       return {"error": "invalid certificate id"}

   if crypto_id.algo_index < 0 or crypto_id.algo_index >= len(ALGOS):  
       return {"error": "invalid algorithm"}

   return verify_signature(crypto_id)

CERTS = load_certs()  
```  
There are two algorithms, RSA and ECDSA using SECP256K1 curve. `algo_index`
must point to one of them, `cert_id` must point to one of known certificates.
This code also gives meaning to the output of `/api/get_certificates`, RSA
certificates are stored as `[0,[n,e]]`, ECDSA certificates are stored as
`[1,[x,y]]`. Our certificates are not invited to the party :(

But not everything is lost, the code forgets to check that `algo_index` from
input data matches the algorithm of an actual certificate, instead the code
interprets a known certificate according to the type that we provide.

Reinterpreting RSA certificates as ECDSA is useless, a pair of `(n,e)`
interpreted as a point certainly does not belong to the curve, and the
underlying library checks that:  
```  
>>> from cryptography.hazmat.primitives.asymmetric import ec  
>>> from cryptography.hazmat.backends import default_backend  
>>>
ec.EllipticCurvePublicNumbers(1234,4321,ec.SECP256K1()).public_key(default_backend())  
...  
ValueError: Invalid EC key.  
```

On the other hand, reinterpreting ECDSA certificates as RSA is promising;
`(n,e)` have no equation that would bind them, only basic conditions; the
underlying library checks that `3<=e<n` and that `e` is odd, but that is just
about it. In particular, the first certificate from the output of
`/api/get_certificates` is happily accepted as RSA; and a random integer is
much easier to factorize than a proper RSA modulus. SageMath finds the
factorization
`64231366944007128611348919651104804909435973587058913853892482269232788324041
= 3^4 * 59 * 110647 * 1262927 * 9717632942113556809805909084119 *
9897642244809737193051574181189` in less than a minute (and if `x` from the
first certificate would take longer than a minute to factorize, there are many
more choices to try).

Doing the PSS/MGF1 padding manually seems to be a non-trivial amount of work,
an existing library would handle it better. Knowing the factorization is
sufficient in mathematical sense, but trying to convince an existing code is
another matter. In particular, OpenSSL uses more sophisticated algorithm than
just powering to a private exponent, and needs an actual key with two divisors
that would better be actual primes and additional data; there exist keys with
several primes, but the factorization above includes a prime power and who
knows what else OpenSSL could decide to be picky about. So I have used
PyCryptodome that is much less picky (still, RSA implementation in there
turned out to decrypt in a "blinded" way as `x -> (x*r**e,r) ->
((x*r**e)**d=x**d*r,r) -> x**d` for a random `r`, when `n` is divisible by 3,
this fails with probability 1/3; fortunately, it is easy to mock a simple
powering instead of that).

SageMath:  
```  
>>>
54772973722616689122700859762282578769822156610875026825025566223653351599293.inverse_mod(euler_phi(64231366944007128611348919651104804909435973587058913853892482269232788324041))  
24964856803835239775464681118886184024003818538584513246510362993110229374997  
```

The solution:  
```  
from cryptography.hazmat.primitives.asymmetric import rsa, padding  
from cryptography.hazmat.primitives import hashes  
import gmpy2  
from Crypto.PublicKey import RSA  
from Crypto.Signature import pss  
from Crypto.Hash import SHA1  
import cbor  
import zlib  
from datetime import datetime

n_ =
64231366944007128611348919651104804909435973587058913853892482269232788324041  
e_ =
54772973722616689122700859762282578769822156610875026825025566223653351599293  
d_ =
24964856803835239775464681118886184024003818538584513246510362993110229374997

class fakersa:  
   n = n_  
   def _decrypt(self, v):  
       return pow(v, d_, n_)

headers1 = cbor.dumps({1: 0, 4: b'0591b59c'})  
timestamp = int(datetime.utcnow().timestamp()) + 12*60*60  
signed_data = cbor.dumps(["Signature1", headers1, None, timestamp])

signature = pss.new(fakersa(), salt_bytes=0).sign(SHA1.new(signed_data))

# just to make sure, reproduce the check from crypto_party.py  
pub = rsa.RSAPublicNumbers(e_, n_)  
pad = padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=0)  
pub.public_key().verify(signature, signed_data, pad, hashes.SHA1())

# there could be any number instead of 55799, but it seems to be standard  
cbor_value = cbor.dumps(cbor.Tag(55799, [headers1, None, timestamp,
signature]))  
value = zlib.compress(cbor_value)

BASE45_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"  
result = 'LDG:'  
for i in range(0, len(value), 2):  
	if len(value) == i+1:  
		result += BASE45_CHARSET[value[i] % 45] + BASE45_CHARSET[value[i] // 45]  
	else:  
		v = value[i] * 256 + value[i+1]  
		result += BASE45_CHARSET[v % 45] + BASE45_CHARSET[v // 45 % 45] + BASE45_CHARSET[v // 45 // 45]  
print('{"qrcode":"'+result+'"}')  
```

Given the `qrcode`, `/api/let_me_in` responds with
`CTF{FreeDr1nksForEvery0ne}`.