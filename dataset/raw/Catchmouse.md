# Catchmouse - 2020 Defenit CTF (rev, 690p, 8 solved)
## Introduction

Catchmouse is a reversing task.

A single file is provided : `catchMouse.apk`. It is an Adroid application.

The application is a game. Each round last 10 seconds. The player has to tap on
images of mouse gain points. When the time is over, the best 5 scores are
stored.

The apk contains JVM code and a native library, `libjniCalculator.so`.

## Java 

The Java code can be decompiled with recent decompilers.
[Procyon](https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler) worked
the best.

The class `com.example.touchgame.ResultActivity` contains a string that mentions
the flag. It is slightly obfuscated in the sense that `jadx` could not decompile
the `onStart` method.

The `onCreate` method sets class properties, in particular `this.t` is set to
the current player's name and `this.u` is set to the current player's score.

```java
this.t = ((Activity)this).getIntent().getStringExtra("name");
this.u = ((Activity)this).getIntent().getIntExtra("score", 0);
```

The `onStart` method takes `this.u`, the score, and calls `Convertkey1` on it.
It then calls `Convertkey2` on its return value, and so on until `Convertkey7`.

```java
this.v = this.Convertkey1(this.u);
this.v = this.Convertkey2(this.v);
this.v = this.Convertkey3(this.v);
this.v = this.Convertkey4(this.v);
this.v = this.Convertkey5(this.v);
this.v = this.Convertkey6(this.v);
this.v = this.Convertkey7(this.v);
```

The method then retrieves a signature, hashes it, and encodes the result in
base64.

The [Android documentation](https://developer.android.com/reference/android/content/pm/Signature)
states that Signature is an `Opaque[...] representation of a signing
certificate`.

```java
for (final Signature signature : ((Activity)this).getPackageManager().getPackageInfo("com.example.touchgame", 64).signatures) {
	final MessageDigest instance = MessageDigest.getInstance("SHA-256");
	instance.update(signature.toByteArray());
	this.y = Base64.encodeToString(instance.digest(), 0);
}
```

The score is then concatenated with the base64 string, and hashed again.

```java
final StringBuilder sb = new StringBuilder();
sb.append(Long.toString(this.v));
sb.append(this.y);
final String string = sb.toString();

final MessageDigest instance2 = MessageDigest.getInstance("SHA-256");
instance2.update(string.getBytes());
final byte[] digest = instance2.digest();
```

The new digest is converted to its hexadecimal representation.

```java
final StringBuffer sb2 = new StringBuffer();
for (int k = n; k < digest.length; ++k) {
	sb2.append(Integer.toString((digest[k] & 0xFF) + 256, 16).substring(1));
}
String string2 = sb2.toString();
```

And this hexadecimal representation is used as a parameter of the `b.b.a.a`
class.

Snippets of the `b.b.a.a` class would serve no purpose in this write-up. It
performs encryption and decryption of AES-128-CBC. The parameter is both the key
and the IV. Only the first 128 bits are used. The IV and the key are the same.

The player's name is encrypted as explained above. If the result matches
`6ufrtSAmvqHgdpLJ3dJJYmKHcE3FyqnXGe2rzFGDsBE=`, the good boy is displayed.

In other words, `6ufrtSAmvqHgdpLJ3dJJYmKHcE3FyqnXGe2rzFGDsBE=` is the flag
encrypted with a key derived from the score and the application's signature.

```java
final b.b.a.a a2 = new b.b.a.a(string2); // aes-128-cbc
final String b2 = a2.b(this.t); // encrypt
final String a3 = a2.a(b2); // decrypt
final StringBuilder sb3 = new StringBuilder();
sb3.append("decrypt:");
sb3.append(a3);
Log.e("catname", sb3.toString());

if (b2.equals("6ufrtSAmvqHgdpLJ3dJJYmKHcE3FyqnXGe2rzFGDsBE=")) {
	Toast.makeText(((Activity)this).getApplicationContext(), (CharSequence)"Good!!! Cat Name is Flag", 1).show();
}
```

To sum it up :
```python
hash = ck7(ck6(ck5(ck4(ck3(ck2(ck1(score)))))))
key  = sha256(str(hash) + base64(sha256(signature)))
iv   = key[0x00:0x10]

flag = decode(key, iv, "6ufrtSAmvqHgdpLJ3dJJYmKHcE3FyqnXGe2rzFGDsBE=")
```

This construction ensures the application is not modified, as the signature
would become invalid.

## JNI

The `libCalculator.so` library exports the `Convertkey` functions.

These contain the same pattern repeated multiple times :
```c
local_40 = 1;
while (local_40 < 0x4d5) {
	local_18 = local_18 + 0x539 % local_40 + -0x852a4b69;
	local_40 = local_40 + 1;
}

local_44 = 1;
while (local_44 < 0x25) {
	local_18 = local_18 + 0x539 % local_44 + 0x852a5a91;
	local_44 = local_44 + 1;
}
```

`Convertkey1` is different. It checks that the input is within the `[500, 1000]`
interval. It returns a constant value if it is not, hinting that the expected
score is between 500 and 1000.

```c
if ((param_3 < 1000) && (499 < param_3)) {
	local_20 = [...];
}
else {
	local_20 = 0x12535623cbac930f;
}
return local_20;
```

Fortunately, `libCalculator.so` has been compiled for x86_64. None of its
function call any functions. It is thus possible to lift the code from those
functions and use it without any modification.

## Finding the flag

With both parts of the application reversed, it becomes clear that the following
are required in order to find the flag :
1. retrieve the signature, its hash or the base64 of it
2. bruteforce the score between 500 and 1000 to find the key

The first part can be done with Frida. Frida is a great tool. Its documentation
however...

Frida can find an Android phone connected via USB with `frida.get_usb_device()`.

It can attach to a running process with `device.attach('package.id')`.

Then, it can execute code within the Java context with `Java.perform(code)`.

The code can obtain references to Java classes with `Java.use("class.name")`.

The methods can be accessed with `class.methodName`. If a method is defined
multiple time (overloaded), it can be discriminated with
`class.methodName.overload("arg1_type", "arg2_type", ...)`. type is the
descriptor representation of the type (e.g. `[B` for a byte array) as defined in
Chapter [4.3. Descriptors and Signature](https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.3)
of the Java Virtual Machine Specification.

The easiest way is to pretend there is no need for an overload. Frida will print
a helpful message about what methods signatures can be overloaded.

The implementation of a method can be replaced with `method.implementation =
function(x) { ... }`. The `this` object represents the current object.
`this.foo` will call the original `foo` method, even if it is overloaded.

The `hook.py` script hooks `java.lang.StringBuilder` and outputs strings it
built. This shows the following base64 :
`wo6sy9VK4Aql1J6+yXpizrQcKa33BlE48v+LmgOiKrY=\n` (mind the new line !)

Using this string and a C script to try every scores, the flag can be decrypted
in no time.

```
./bf | ./pwn.php | strings
Defenit{Cat_Name_Is_MeOw_mEOw}
```

**Flag**: `Defenit{Cat_Name_Is_MeOw_mEOw}`

## Appendices

### hook.py

```python
import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(function () {
	Java.use("android.util.Base64").encodeToString.overload('[B', 'int').implementation = function(a, b) {
		console.log("base64");

		var str = "";
		for(var i = 0; i < a.length; i++) {
			var byte = a[i] & 0xFF;

			if(byte < 0x10)
				str += "0";

			str += byte.toString(16) + " ";
		}

		console.log(str);
		return this.encodeToString(a, b);
	};

	Java.use("java.lang.StringBuilder").toString.implementation = function() {
		var ret = this.toString();

		console.log("sb = " + ret);
		return ret;
	};
});
"""

process = frida.get_usb_device().attach('com.example.touchgame')
print(process)

script = process.create_script(jscode)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

### bf.c

```c
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>

typedef long jni(int, int, long);

int main(int argc, char *argv[])
{
	int fd;
	void *base;
	long (*ck1)(int, int, long);
	long (*ck2)(int, int, long);
	long (*ck3)(int, int, long);
	long (*ck4)(int, int, long);
	long (*ck5)(int, int, long);
	long (*ck6)(int, int, long);
	long (*ck7)(int, int, long);

	fd = open("lib/x86_64/libjniCalculator.so", O_RDONLY);
	base = mmap(NULL, 0x2000, 7, MAP_PRIVATE, fd, 0);

//	printf("%p\n", base);
	ck1 = (jni*)(base + 0x850);
	ck2 = (jni*)(base + 0x910);
	ck3 = (jni*)(base + 0xb20);
	ck4 = (jni*)(base + 0xe50);
	ck5 = (jni*)(base + 0x1200);
	ck6 = (jni*)(base + 0x1430);
	ck7 = (jni*)(base + 0x1650);

	for(int i = 500; i < 1000; i++) {
		long hash = i;

		hash = ck1(0, 0, hash);
		hash = ck2(0, 0, hash);
		hash = ck3(0, 0, hash);
		hash = ck4(0, 0, hash);
		hash = ck5(0, 0, hash);
		hash = ck6(0, 0, hash);
		hash = ck7(0, 0, hash);

	//	printf("%d %016lX\n", i, hash);
		printf("%ld\n", hash);
	}
}
```

### pwn.php

```php
#!/usr/bin/php
<?php
const FLAG = "6ufrtSAmvqHgdpLJ3dJJYmKHcE3FyqnXGe2rzFGDsBE=";

while($line = fgets(STDIN)) {
	if(feof(STDIN))
		break;

	$n   = (int)trim($line);
	$key = hash("sha256", $n . "wo6sy9VK4Aql1J6+yXpizrQcKa33BlE48v+LmgOiKrY=\n");
	$key = substr($key, 0, 0x10);
	$iv  = $key;

	$clear = openssl_decrypt(FLAG, "aes-128-cbc", $key, 0, $iv);
	printf("%s\n", $clear);
}
```