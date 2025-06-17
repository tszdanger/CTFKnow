# Another APK.... with a surprise

First we try the app on the phone. Damn, we need a 4 digits pin.... We could
just brute force it right?

Okay, it's been a few mobile problems now, we got the handle of unpacking APKs
and looking at files. We find the following interesting function:

```  
function b() {  
 var t;  
 (0, o.default)(this, b);  
 for (var n = arguments.length, l = new Array(n), u = 0; u < n; u++) l[u] =
arguments[u];  
 return (t = v.call.apply(v, [this].concat(l))).state = {  
   output: 'Insert the pin to get the flag',  
   text: ''  
 }, t.partKey = "pgJ2K9PMJFHqzMnqEgL", t.cipher64 =
"AA9VAhkGBwNWDQcCBwMJB1ZWVlZRVAENW1RSAwAEAVsDVlIAV00=", t.onChangeText =
function(n) {  
   t.setState({  
     text: n  
   })  
 }, t.onPress = function() {  
   var n = p.Base64.toUint8Array(t.cipher64),  
     o = y.sha256.create();  
   o.update(t.partKey), o.update(t.state.text);  
   for (var l = o.hex(), u = "", c = 0; c < n.length; c++) u +=
String.fromCharCode(n[c] ^ l.charCodeAt(c));  
   t.setState({  
     output: u  
   })  
 }, t  
}  
```

We immidiatly notice the XOR based encryption:

```  
for (var l = o.hex(), u = "", c = 0; c < n.length; c++) u +=
String.fromCharCode(n[c] ^ l.charCodeAt(c));  
```

which can be reversed by using the rule ``` a = b ^ c <=> b = a ^ c``` since
we have the keys.  
Wait, what am I saying? All we need to do is run a similar code with similar
key / cipher and try all the pins.

I decided to write a javascript code that would help go through that. I later
realized that I could have used the "crypto" module (I didn't know this was a
thing). But here is my raw solution:

```  
// string to base64  
function s2b(s) {  
 return Buffer.from(s).toString('base64')  
}

// base64 to string  
function b2s(s) {  
 return Buffer.from(s, 'base64').toString();  
}

// array buffer wrapper  
function _base64ToArrayBuffer(base64) {  
 var binary_string = b2s(base64);  
 var len = binary_string.length;  
 var bytes = new Uint8Array(len);  
 for (var i = 0; i < len; i++) {  
   bytes[i] = binary_string.charCodeAt(i);  
 }  
 return bytes.buffer;  
}

// string buffer wrapper  
function _stringToArrayBuffer(s) {  
 var len = s.length;  
 var bytes = new Uint8Array(len);  
 for (var i = 0; i < len; i++) {  
   bytes[i] = s.charCodeAt(i);  
 }  
 return bytes.buffer;  
}

// apply on pin  
function decode(pin) {  
 cipher64 = "AA9VAhkGBwNWDQcCBwMJB1ZWVlZRVAENW1RSAwAEAVsDVlIAV00="  
 partKey = "pgJ2K9PMJFHqzMnqEgL" + pin  
  
 // you can get the sha256 function from https://geraintluff.github.io/sha256/  
 partKeySHA256 = sha256(partKey)

 cipherBuff = new Uint8Array(_base64ToArrayBuffer(cipher64))  
 keyBuff = new Uint8Array(_stringToArrayBuffer(partKeySHA256))

 out = ""  
 // don't forget to module when you loop  
 for (var i = 0; i < 38; i++) {  
   code = cipherBuff[i] ^ keyBuff[i % keyBuff.length]  
   out += String.fromCharCode(code)  
 }  
 return out  
}

// try all combinations  
// ignore why i used 4 for-loops  
// just to finish quickly really  
for (let a = 0; a < 10; a++)  
 for (let b = 0; b < 10; b++)  
   for (let c = 0; c < 10; c++)  
     for (let d = 0; d < 10; d++) {  
       pin = String(a) + String(b) + String(c) + String(d)  
       out = decode(pin)  
       if (out.includes("flag{"))  
         console.log("PIN", pin, out)  
     }

```

and the output (with a filter on "lag" instead of "flag{" just to make the
write-up look nicer :D):

```  
PIN 0804 c:46-4d55k3;4;lagn7f55b>?g022e6i50g63  
PIN 3472 flag,454c;ec>7o4oaogfd9=c`7`1<0?`ac9o(  
PIN 4304 bl`f,6>;7>e3f2lagd5``c9=?66b73e82fb1g~  
PIN 4784 flag{06754e57e02b0c505149cd1055ba5e0b} ← ← ←  
PIN 5403 6lagz714go4gba:be3o5ed68:dk7a<4mgccf4{  
PIN 5464 6kcg)7?23lagde1f4obned45mf0ec<3j2o3bn|  
PIN 7882 9lag-gb5fi05>a0bnf4oh0d4idjb5fbl;40ef}  
PIN 8301 e7d:}047co>7?6<12aa0clc<mlagf`g9fed8o}  
PIN 8527 cng4z71e4<d5b2=55f07dae8jlagcf387f644{  
PIN 9172 8im:z25:g?4640>dog5`2fe=laga2ebk;c3cg/  
PIN 9948 6600 g20e:a52e15f`7gf22h>532bg2lag066+  
```

I could have been done it more easily (thanks @tkiela#8295, their solution
below)

```  
const crypto = require("crypto");

const partKey = "pgJ2K9PMJFHqzMnqEgL";  
const pad = "AA9VAhkGBwNWDQcCBwMJB1ZWVlZRVAENW1RSAwAEAVsDVlIAV00=";  
const pad64 = Buffer.from(pad, "base64");  
for (var i = 0; i <= 9999; i++) {  
 const sha256 = crypto.createHash("sha256");

 hash.update(partKey);

 hash.update(${i});

 for (var l = hash.digest("hex"), u = "", c = 0; c < pad64.length; c++)  
   u += String.fromCharCode(pad64[c] ^ l.charCodeAt(c));

 if (u.includes("flag")) {  
   console.log("PIN:", i);  
   console.log(u);  
 }  
}  
```

Nice challenge overall! Technically could have ran a robot on the emulator and
then let it try all pins (I'm kidding don't worry), but this taught me a bit
more about crypto!