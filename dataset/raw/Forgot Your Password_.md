# Forgot Your Password?  
Description  
```  
Written by: Ptomerty

Help! I got this new lock for Christmas, but I've forgotten the first two
values. I know the last value is hsctfissocoolwow. I also managed to grab a
copy of their secret key generator. Can you help me out?

Note: submit the first two combo values separated by a space in hex format.  
```  
[generator.py](generator.py)

I explain only the `next()` and `h()` bacause others is not important

`m()` function reduce the size of number become 8 bytes (Because of &
operator)

`h()` function is do some complicated calculation and put it to `s[0]` and
`s[1]`

`next()` function is just running `h()` and return `m(b)`  
```python  
def m(a):  
	return a&0xffffffffffffffff  
def next():  
	b = m(s[0]+s[1])  
	h()  
	return m(b)  
def h():  
	s1 = m(x(s[0],s[1]))  
	s[0] = m(x(oro(o(s[0],55),p(55,s[0])),x(s1,(o(s1,14)))))  
	s[1] = m(oro(o(s1,36),p(36,s1)))  
```

`bin2chr` function is just binary to characters

`isp` function is just check whether the binary is printable (In ASCII range)  
```python  
# Helper methods  
def bin2chr(data):  
   result = ''  
   while data:  
       char = data & 0xff  
       result += chr(char)  
       data >>= 8  
   return result

def isp(d):  
	if all(c in ch for c in d):  
		return d  
	else:  
		return d.encode('hex')  
```  
And the last part:  
```python  
# throw away first value for additional randomness  
next()  
next()

COMBO_NUM_1 = isp(bin2chr(next())) + isp(bin2chr(next()))  
COMBO_NUM_2 = isp(bin2chr(next())) + isp(bin2chr(next()))  
COMBO_NUM_3 = isp(bin2chr(next())) + isp(bin2chr(next()))

print "Thanks! Your numbers are: "  
print COMBO_NUM_1  
print COMBO_NUM_2  
print COMBO_NUM_3  
```  
According to the description, it said the last value is `hsctfissocoolwow`

And tell us to recover first two combo values, which is `COMBO_NUM_1` and
`COMBO_NUM_2`

So we need to find the original `s[0]` and `s[1]` after calling `next()` 6
times and resulting the `COMBO_NUM_3` is `hsctfissocoolwow`

I used the popular **z3 solver** which can solve very complex maths algorithm

[Full script in python](solve.py)  
```python  
from z3 import *  
solver = Solver()  
s = [BitVec('s%i' % i, 128) for i in range(2)]  # Declare two binary value in
size of 128  
flag = 'hsctfissocoolwow'  
flag1 = int(flag[:-8][::-1].encode('hex'),16)   # Convert first half into
integer  
flag2 = int(flag[8:][::-1].encode('hex'),16)    # Convert second half into
integer

def o(x,k):                     # Copied the functions in the generator.py  
	return x<<k  
...  
...  
...

next()          # Call next() 6 times  
next()  
next()  
next()  
next()  
next()  
solver.add(next() == flag1)             # Add condition in 7th next() is equal
to first half  
solver.add(next() == flag2)             # Add condition in 8th next() is equal
to second half  
print solver.check()                    # Check is solvable  
print solver.model()                    # Print the result  
```  
## Result  
```  
sat  
[s1 = 16423178736247365899, s0 = 81081519719372872192]  
[Finished in 54.5s]  
```  
Completed in just 54 second

The result means the `SECRET_1` is 81081519719372872192 and `SECRET_2` is
16423178736247365899

We can just substitute inside `generator.py` and run it!

And the first two value is our flag!

## Result  
```  
Thanks! Your numbers are:  
e06f76cd556604f0f21c34f1519d2fd2  
73c8535ab0f954b5ad1cbab7abc18309  
hsctfissocoolwow  
```

## Flag  
> e06f76cd556604f0f21c34f1519d2fd2 73c8535ab0f954b5ad1cbab7abc18309

Original writeup
(https://github.com/Hong5489/hsctf6/tree/master/forgot_your_password).