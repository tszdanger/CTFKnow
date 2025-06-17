## Description  
Warmup your crypto skills with the superior number system!

* enc.py  
* flag.enc

## Write up  
when looking at `enc.py`  
```  
fib = [1, 1]  
for i in range(2, 11):  
	fib.append(fib[i - 1] + fib[i - 2])

def c2f(c):  
	n = ord(c)  
	b = ''  
	for i in range(10, -1, -1):  
		if n >= fib[i]:  
			n -= fib[i]  
			b += '1'  
		else:  
			b += '0'  
	return b

flag = open('flag.txt', 'r').read()  
enc = ''  
for c in flag:  
	enc += c2f(c) + ' '  
with open('flag.enc', 'w') as f:  
	f.write(enc.strip())

```  
you can see that every charachter of the flag is being encrypted through a
function called c2f  through transforming the ascii code n by comparing it  to
the fibonacci number corresponding to that index and replacing it by b..u get
the idea

## My Approach  
My approach is  mathematically based and it consists basically on finding the
lower and upper bound of n at each iteration of the loop:  
by iterating through the binary if the charachter is 0 then n was at the
iteration less than that fib[i] so u can at each time change the lower bound
and upper bound  
so u can finally find lower and upper bound differing by just 1 and since the
comparison in the enc.py is "greater or equal" so n at the last iteration is
the lower bound  
and then I apply the chr function to get the charachter put together u get the
flag :D

## Code

```  
fib = [1, 1]  
for i in range(2, 11):  
	fib.append(fib[i - 1] + fib[i - 2])

with open('flag.enc','rb') as f:  
	ct=f.read()  
ct_blocks = ct.split(b' ')  
pt=''  
for blo in ct_blocks:  
	upper=0  
	lower=0  
	test_n=0  
	for b,i in zip(blo,range(10,-1,-1)):  
		idx = bytes([b])  
		if idx == b'1':  
			lower= fib[i]-test_n  
			test_n-=fib[i]  
		else:  
			upper= fib[i]-test_n  
		print(lower,upper)  
	pt+=chr(lower)  
print(pt)

#FLAG: corctf{b4s3d_4nd_f1bp!113d}

```

#hmxforlife