# Harekaze 2019 "[a-z().]" (200)

Writeup by Ben Taylor

## Description

Description  
if (eval(your_code) === 1337) console.log(flag);

http://(redacted)
([server/Dockerfile](https://github.com/TeamHarekaze/HarekazeCTF2019-challenges/tree/master/a-z/server))

- [a-z.tar.xz](https://github.com/TeamHarekaze/HarekazeCTF2019-challenges/blob/master/a-z/attachments/a-z.tar.xz)

## Solution

Wow, this was a fun problem! Maybe my favorite CTF problem yet. If you haven't
tried working through it already, I highly recommend you give it a shot. There
will be spoilers.

Since we we're graciously provided the source code, let's start by taking a
look inside. Line 15 is what's important here:

``` JavaScript  
12 app.get('/', function (req, res, next) {  
13   let output = '';  
14   const code = req.query.code + '';  
15   if (code && code.length < 200 && !/[^a-z().]/.test(code)) {  
16     try {  
17       const result = vm.runInNewContext(code, {}, { timeout: 500 });  
18       if (result === 1337) {  
19         output = process.env.FLAG;  
20       } else {  
21         output = 'nope';  
22       }  
23     } catch (e) {  
24       output = 'nope';  
25     }  
26   } else {  
27     output = 'nope';  
28   }  
29   res.render('index', { title: '[a-z().]', output });  
30 });  
```

For the code to run it must (a) exist, (b) have a length less than 200, and
(c) can only contain lowercase letters, parenthesis, and dots. Once these
checks pass, we get to run in a [super locked down node
context](https://nodejs.org/api/vm.html#vm_script_runinnewcontext_sandbox_options).
If the code evaluates to the number `1337` (note the triple equals here — a
string won't cut it).

My first thought was something along the lines of BF's competitor, [non
alphanumeric JavaScript](http://patriciopalladino.com/blog/2012/08/09/non-
alphanumeric-javascript.html). However, this JS standard relies heavily on
`[`, `]`, and `+`, all of which we don't have access to.

Instead, we'll start more basic than what the challenge calls for — how do we
get a string with our limited alphabet? Digging around in documentation, we
find the [typeof](https://developer.mozilla.org/en-
US/docs/Web/JavaScript/Reference/Operators/typeof) operator. If we try to find
the type of an undefined variable we get `"undefined"`. What if we try to get
the type of that? We unlock the string `"string"`. Also note that we can get
`"boolean"` by looking at the type of `true`.

``` JavaScript  
(typeof(x)) == "undefined"  
(typeof(typeof(x))) == "string"  
(typeof(true)) == "boolean"  
```

Great, we have strings. From here, we can use any string methods or properties
that don't contain uppercase letters. For instance, `length`! This unlocks the
numbers 6, 7, and 9. While we can't use `indexOf()` due to the uppercase `O`,
inspecting a strings properties in any JavaScript console reveals the
[search](https://developer.mozilla.org/en-
US/docs/Web/JavaScript/Reference/Global_Objects/String/search) method, which
means we can search `"undefined"` for `"undefined"` to get `0` and
`"undefined"` for `"boolean"` to get `-1`. Also note that since we have access
to numbers, we also have access to the string `"number"` through `typeof`.

``` JavaScript  
(typeof(x)).length == 9  
(typeof(typeof(x))).length == 6  
(typeof(true)).length == 7  
(typeof((typeof(x)).length)) == "number"  
(typeof((typeof(x)).length)).length == 6  
(typeof(x)).search((typeof(x))) == 0  
(typeof(x)).search((typeof(true))) == -1  
```

Because we can use `concat`, it might be a good idea to form the digits
individually and concatenate them since we're lacking any mathematical
methods. How can we turn a number into a string? We can't use `toString`,
`String`, or `+ ""`. But because JavaScript is a prototype based language,
every instance is itself a "class". So using one string, we can access it's
constructor with the `constructor` property! We can extend this ideas to
numbers to get access to the `Number` class as well to turn strings back into
numbers — remember, the final expression must evaluate to a number.

``` JavaScript  
(typeof(x)).constructor == String  
((typeof(x)).length).constructor == Number  
(typeof(x)).constructor((typeof(true)).length) == "7" // we have our first
digit to concatenate!  
((typeof(x)).length).constructor("123") == 123  
```

Lets see if we can get a `"1"`. Because JavaScript is stupid-typed, `true` ==
1. But if we try to pull a `String(true)` using our equivalence above, we get
`"true"`. Therefore, we need to first cast the boolean to a number, then the
number to a string, leaving us with the monstrosity below. (true => 1 => "1")

``` JavaScript  
((typeof(x)).length).constructor(true) == 1  
(typeof(x)).constructor(((typeof(x)).length).constructor(true)) == "1"  
```

The last digit that we need is a `"3"`. If you're dumb like me, you'll sit
down for an hour or two and come up with something along the lines of
`(typeof(x)).constructor((typeof(x)).constructor((typeof(x)).length.constructor(typeof(x))).length)`.
No, I don't remember how this works and I don't plan on reverse engineering
it. The point is, if you recall the rest of the constraints, we have to have
an expression under 200 characters, so having _two_ 98 character expressions
to get the `"3"`'s might be a problem. Thankfully, one of my teammates saved
the day and brought up (in another conversation!) the `name` property of
functions. This bad boy returns a string with the name of the function, which
we can then take the length of. So really we just need any function with a
three letter name. I decided to go with `(typeof(x)).big.name.length` to get
`3`, which we can then cast to a string.

``` JavaScript  
(typeof(x)).constructor((typeof(x)).constructor((typeof(x)).length.constructor(typeof(x))).length)
== "3"  
(typeof(x)).big.name.length == 3  
(typeof(x)).constructor((typeof(x)).big.name.length) == "3"  
```

Here is what the combined expression looks like right now. We're making a
`"1"`, then concatenating the rest of the digits and parsing to an integer.

``` JavaScript  
((typeof(x)).length).constructor((typeof(x)).constructor(((typeof(x)).length).constructor(true)).concat((typeof(x)).constructor((typeof(x)).big.name.length)).concat((typeof(x)).constructor((typeof(x)).big.name.length)).concat((typeof(x)).constructor((typeof(true)).length)))  
```

If you look closely, you'll see this won't actually get us the flag. Why? It's
274 characters long. We need to do some optimizing.

Once again, JavaScript's stupid-typing comes in handy. We can append a number
to a string and get a string, so we don't need to parse each number to a
string, just the first digit. This gets us the following, clocking in at just
199 characters! We can also optimize `1 == (typeof(x)).match().length` to get
down to 187 characters, and there might be a few extra parenthesis (though
most are necessary due to `typeof`'s weird precedence), but either way, 199 <
200, and we get the flag!

``` JavaScript  
((typeof(x)).length).constructor((typeof(x)).constructor(((typeof(x)).length).constructor(true)).concat((typeof(x)).constructor((typeof(x)).big.name.length)).concat((typeof(x)).constructor((typeof(x)).big.name.length)).concat((typeof(x)).constructor((typeof(true)).length)))  
```

Flag: `HarekazeCTF{sorry_about_last_year's_js_challenge...}`

Original writeup (https://github.com/swv-l/writeups/blob/master/2019-harekaze-
a-z.md).