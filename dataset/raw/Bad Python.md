# Bad Python

> My friend wrote a cool program to encode text data! His code is sometimes
> hard to understand, and only he knows how it works. I ran the program twice,
> but forgot the input I used for the first time. I didn't save the key I used
> either, but I know it was 15 characters long. Can you figure out what text I
> encoded the first time?

Attached are 4 files:

Output1  
```  
b'\x02\x19\x01\x16Q\r\x07\nS\x02)\x1a1=EE2\x0e=G/D\nRY)\nV\x1bJ'  
```

Input 2  
```  
Lorem ipsum dolor sit amet, consectetur adipiscing elit  
```

Output 2  
```  
b':\x1c\x10\x07ZV\x1a\x12\x11B\x1bS\x06\r[\x19\x01B\x11^\x02S\x03\x0fR\x02_B\x01X\x18\x00\x07\x01C\x13\x07\x17\x10\x17\x17\x17\x0b\x12^\x05\x10\x0b\x0cPV\x16\x0e\x0bC'  
```

Source  
```python  
import random  
A=bool  
N=ord  
y=sorted  
Y=list  
h=bin  
T=int  
e=range  
F=len  
L=open  
O=repr  
R=random.shuffle  
import itertools  
import functools  
D=functools.reduce  
S=A  
P=lambda a,b:(N(a)^N(b)).to_bytes(1,'big')  
B='[redacted - 15 chars]'  
E=((0,3),(1,4),(0,1),(3,4),(2,3),(1,2))  
B=y(Y(B))  
x=lambda a,b:h((N(a)-N(b))^(T('1'*10,2)))[0]!='-'  
def u(li):  
Q=[li[i::3]for i in e(3)]  
for i in Q:  
 while not W(i):  
  pass  
return Q  
def W(i):  
R(i)  
a=[S(T(h(N('e'))[2:][-1]))]  
return[n(a,x(i[E[j][0]],i[E[j][1]]))for j in e(F(E))][-1]  
def n(g,k):  
g[0]=g[0]and k  
return g[0]  
f=u(B)  
a=L('input.txt','r').read()  
m='output.txt'  
L(m,'w').write(O(b''.join([D(P,[(((N(a[i])&(~N(f[j][i%5])))|((~N(a[i]))&(N(f[j][i%5])))).to_bytes(1,"big"))for
j in e(F(f))])for i in e(F(a))])))

#   if c%100000==0:  
#     print(i)  
#     print(c)  
```

## Description

Here we get some obfuscated code. But if we reverse engineer it, we will know
how the key is used to encrypt messages, and therefore we can deduce the 15
char key, and with it decrypt the first output.

## Solution

### Deobfuscate Python

Let's have a look at what happens here. Apart from constants definitions and
functions, the real code is the following:

```python  
B=y(Y(B))  
f=u(B)  
a=L('input.txt','r').read()  
m='output.txt'  
L(m,'w').write(O(b''.join([D(P,[(((N(a[i])&(~N(f[j][i%5])))|((~N(a[i]))&(N(f[j][i%5])))).to_bytes(1,"big"))for
j in e(F(f))])for i in e(F(a))])))  
```

#### Password transformation

Here `B` is the password. `Y(B)` transforms the password as a list of char,
and then is sorted (this is because `y=sorted`). So actually the order of the
characters in the password doesn't matter.

Then the password is transformed using `f=u(B)`. Here is what `u` does:

```python  
def u(li):  
Q=[li[i::3]for i in range(3)]  
for i in Q:  
 while not W(i):  
  pass  
return Q  
```

`Q` is an array of arrays. There are 3 arrays, and array `i` contains the
characters of the password whose index is `i` modulo 3 (array 0 contains
characters 0,3,... of the password).

Then, each subarray is given to `W` until it returns `True`.

```python  
def W(i):  
random.shuffle(i)  
a=[S(T(h(N('e'))[2:][-1]))]  
return[n(a,x(i[E[j][0]],i[E[j][1]]))for j in e(F(E))][-1]  
```

The line `a=[S(T(h(N('e'))[2:][-1]))]` is actually a constant and does not
depend on the input. It is equivalent to `a=[True]`. Then it constructs the
array `[n(a,x(i[E[j][0]],i[E[j][1]]))for j in e(F(E))]` and returns the last
element.

Let's deobfuscate this:

```python  
E=((0,3),(1,4),(0,1),(3,4),(2,3),(1,2))  
[n(a,x(i[E[j][0]],i[E[j][1]])) for j in range(len(E))]  
```

For every element `(e1,e2)` in `E`, the array contains `n(a,x(i[e1], i[e2]))`.
At the beginning, `a` is a single cell array containing `True`. `n(a,b)`
changes this cell to be `a[0] and b`. Therefore the array contains some
`True`, but once one cell is `False` every subsequent will be `False`. We are
only interested in cells returning always `True` as otherwise `W` will be
called again.

Therefore `W` shuffles our input array `i` until for all pair `(e1,e2)` in
`E`, `x(i[e1], i[e2]) == True`.

Let's write `x` in a prettier fashion:

```python  
def x(a,b):  
   difference = ord(a) - ord(b)  
   c = difference ^ 0b1111111111  
   return c >= 0  
```

So actually `x` only compares `a` and `b` and returns `True` if `a >= b`. So
the function `W` is true if and only if `i[0] >= i[1] >= i[2] >= i[3] >=
i[4]`.

In the end, `f` is an array of array with every array containing one char out
of 3 of the password and sorted in decreasing order.

#### Encryption

Then comes the real encryption.

```python  
a=L('input.txt','r').read()  
m='output.txt'  
L(m,'w').write(O(b''.join([D(P,[(((N(a[i])&(~N(f[j][i%5])))|((~N(a[i]))&(N(f[j][i%5])))).to_bytes(1,"big"))for
j in e(F(f))])for i in e(F(a))])))  
```

`a` holds the input, and it writes in `output.txt`:

```python  
repr(b''.join([functools.reduce(P,[(((ord(a[i])&(~ord(f[j][i%5])))|((~ord(a[i]))&(ord(f[j][i%5])))).to_bytes(1,"big"))for
j in range(len(f))])for i in range(len(a))]))  
```

Here we learn that characters are encrypted one by one. Character `a[i]` if
the input is encrypted in the following way:

```python  
functools.reduce(P,[(((ord(a[i])&(~ord(f[j][i%5])))|((~ord(a[i]))&(ord(f[j][i%5])))).to_bytes(1,"big"))for
j in range(len(f))])  
```

Let's simplify this. For a given `j`, we have actually only two values: `ord(a[i])` and `ord(f[j][i%5])`. If we denote them `a` and `f`, the computation is `a & ~f | ~a & f`, which actually corresponds to `a ^ f`. As the `reduce` operation is also a xor operation, we can simplify it. The encryption of character `a[i]` is:

```python  
ord(a[i]) ^ ord(f[0][i%5]) ^ ord(f[1][i%5]) ^ ord(f[2][i%5])  
```

It uses characters by groups of 3, and they are consecutive in the original
password. If password were `abcdefghijklmno`, then the first group
corresponding to `i%5 = 0` would be `mno`, the one corresponding to `i%5=1`
would be `jkl`, etc...

### Password retrieval

Once we know this, we can bruteforce the password by groups of 3.

```python  
first_input = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit'  
first_output =
b':\x1c\x10\x07ZV\x1a\x12\x11B\x1bS\x06\r[\x19\x01B\x11^\x02S\x03\x0fR\x02_B\x01X\x18\x00\x07\x01C\x13\x07\x17\x10\x17\x17\x17\x0b\x12^\x05\x10\x0b\x0cPV\x16\x0e\x0bC'

output = [' ']*15  
maxichar = 127 # We know password is sorted  
for j in range(5):  
 possibles = []  
 for c1 in range(32, maxichar):  
   for c2 in range(c1, maxichar):  
     for c3 in range(c2,maxichar):  
       possibles.append((c1, c2, c3))  
 for i in range(j, len(first_input), 5):  
   x = ord(first_input[i])  
   possibles2 = []  
   for c in possibles:  
     c1, c2, c3 = c  
     if (x ^ c1 ^ x2 ^ c3) == first_output[i]:  
       possibles2.append((c1,c2,c3))  
   possibles = possibles2  
 print((possibles))  
 if len(possibles) == 0:  
   break  
 output[(4-j)*3] = chr(possibles[-1][0])  
 output[(4-j)*3+1] = chr(possibles[-1][1])  
 output[(4-j)*3+2] = chr(possibles[-1][2])  
 maxichar = possibles[-1][0]+1  
print("".join(output))  
```

And here we get one possible password: `7bbbbbbsssvvv~~`.

### Decryption

Finally we can decrypt the output easily

```python  
key = '7bbbbbbsssvvv~~'  
second_output =
b'\x02\x19\x01\x16Q\r\x07\nS\x02)\x1a1=EE2\x0e=G/D\nRY)\nV\x1bJ'  
second_input = []  
for j in range(len(second_output)):  
 c1, c2, c3 = ord(key[(4-j%5)*3]), ord(key[(4-j%5)*3+1]),
ord(key[(4-j%5)*3+2])  
 second_input.append(chr(second_output[j] ^ c1 ^ c2 ^ c3))  
print("".join(second_input))  
```

Flag: `tjctf{th15_iS_r3Al_pY7h0n_y4y}`

Original writeup (https://github.com/apoirrier/CTFs-
writeups/blob/master/TJCTF2020/Reversing/BadPython.md).