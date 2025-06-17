# Baby Encoder  
Here is the challenge code and Description  
```  
I encoded the flag with my own encoder. I'm sure you can decode it because my
encoder is just a baby encoder!  
```

```python  
from Crypto.Util.number import bytes_to_long

def displace(a, base):  
   res = []  
   for i in range(base):  
       if base + i >= len(a):  
           for j in range(base - 1, i - 1, -1):  
               res.append(a[j])  
           return res  
       res.append(a[base + i])  
       res.append(a[i])  
   for j in range(len(a) - 1, 2 * base - 1, -1):  
       res.append(a[j])  
   return res

def flag_encoder(flag):  
   encoded_flag = []  
   n = len(flag)  
   f = [ord(ff) for ff in flag]  
  
   for i in range(n):  
       encoded_flag.append(ord(flag[i]) ^ ord(flag[i - 1]))  
  
   for i in range(n):  
       encoded_flag[i] ^= encoded_flag[n - i - 1]  
  
   a = []  
   for i in range(0, n, 3):  
       a.append(encoded_flag[i] + encoded_flag[i + 1])  
       a.append(encoded_flag[i + 1] + encoded_flag[i + 2])  
       a.append(encoded_flag[i + 2] + encoded_flag[i])  
   encoded_flag = a  
   for i in range(1, n):  
       if i % 6 == 0:  
           encoded_flag = displace(encoded_flag, i)  
  
   encoded_flag = ''.join(chr(encoded_flag[i]) for i in range(n))  
   return encoded_flag

with open('/home/kourosh/CTF/TMU/crypto/BabyEncoder/flag', 'rb') as f:  
   flag = f.read().decode('UTF-8')  
   print(str(bytes_to_long(flag_encoder(flag).encode())))  
```

# Solution

This challenge really blowed my mind :')\  
It has 4 custom encoding parts which are like below

## step 1

It `xor` every byte of the flag with it's previous byte  
```python  
encoded_flag = []  
n = len(flag)  
f = [ord(ff) for ff in flag]  
for i in range(n):  
	encoded_flag.append(ord(flag[i]) ^ ord(flag[i - 1]))  
```

to reverse this step I wrote this code  
```python  
def decode3(data):

   last = ord('}')  
   size = len(data)  
   new1 = []

   for i in range(size-1, -1, -1):

       last = last ^ data[i]  
       new1.append(last)  
  
   new1 = reverse(new1)  
   new2 = []  
   for i in range(size):  
       new2.append(new1[(i+1)%size])

   return new2  
```

## step 2  
This step `xor` every byte of the previous steps output with its mirror bytes
`(0 with n-1)(1 with n-2)` and ...  
```python  
for i in range(n):  
	encoded_flag[i] ^= encoded_flag[n - i - 1]  
```

To reverse this step I wrote this code  
```python  
def decode2(data):

	size = len(data)  
	for i in range(size-1, -1, -1):  
		data[i] ^= data[size - i - 1]

	return(data)  
```

## step 3  
This step seperate previous steps output into 3 blocks and sum each block with
it's next block  
```python  
a = []  
for i in range(0, n, 3):  
	a.append(encoded_flag[i] + encoded_flag[i + 1])  
	a.append(encoded_flag[i + 1] + encoded_flag[i + 2])  
	a.append(encoded_flag[i + 2] + encoded_flag[i])  
encoded_flag = a  
```

And here is the reversed code to recover  
```python  
def decode1(data):

   size = len(data)  
   new = []

   for i in range(0, size, 3):  
       a0 = (data[i] - data[i+1] + data[i+2]) // 2  
       a1 = (data[i+1] - data[i+2] + data[i]) // 2  
       a2 = (data[i+2] - data[i] + data[i+1]) // 2

       new.append(a0)  
       new.append(a1)  
       new.append(a2)  
  
   return(new)  
```

## step 4  
Here is the code  
```python  
def displace(a, base):  
   res = []  
   for i in range(base):  
       if base + i >= len(a):  
           for j in range(base - 1, i - 1, -1):  
               res.append(a[j])  
           return res  
       res.append(a[base + i])  
       res.append(a[i])  
   for j in range(len(a) - 1, 2 * base - 1, -1):  
       res.append(a[j])  
   return res

for i in range(1, n):  
	if i % 6 == 0:  
		encoded_flag = displace(encoded_flag, i)  
```

Actually I didn't realize what this function really does (LOL) because I had
limited time to put on it to understand\  
But the thing I know is that it just changes bytes positions without any
change in bytes values.\  
As I saw in previous CTFs These functions usually reaches the same state if we
repeat them\  
So I used the same function with try and error numbers to find exact iteration
number

```python  
def displace(a, base):  
   res = []  
   for i in range(base):  
       if base + i >= len(a):  
           for j in range(base - 1, i - 1, -1):  
               res.append(a[j])  
           return res  
       res.append(a[base + i])  
       res.append(a[i])  
   for j in range(len(a) - 1, 2 * base - 1, -1):  
       res.append(a[j])  
   return res  
  
test = [ord(f) for f in
long_to_bytes(28946494946812141829547706026065914605092406854105997612241563383442514740934913838546119691331952671988567947306226900850151388621540356510466883510328793101483278519506803779932615196763052658252298923048223762802716830885754352726914690907223838594044069643833511017514637891042919056).decode()]

for i in range(1, 30):  
   test = displace(test, 72)  
  
for i in range(1, 310):  
   test = displace(test, 66)

for i in range(1, 4290):  
   test = displace(test, 60)

for i in range(1, 2590):  
   test = displace(test, 54)

for i in range(1, 37128):  
   test = displace(test, 48)

for i in range(1, 168):  
   test = displace(test, 42)

for i in range(1, 18):  
   test = displace(test, 36)

for i in range(1, 60):  
   test = displace(test, 30)

for i in range(1, 42):  
   test = displace(test, 24)

for i in range(1, 36):  
   test = displace(test, 18)

for i in range(1, 20):  
   test = displace(test, 12)

for i in range(1, 12):  
   test = displace(test, 6)  
```

Because this function has been called several times with different
bases(6,12,18,..,72). so we should repeat it with different bases each base
has different iteration number

So here is the final overall decoding process  
```python  
from Crypto.Util.number import long_to_bytes

def displace(a, base):  
   res = []  
   for i in range(base):  
       if base + i >= len(a):  
           for j in range(base - 1, i - 1, -1):  
               res.append(a[j])  
           return res  
       res.append(a[base + i])  
       res.append(a[i])  
   for j in range(len(a) - 1, 2 * base - 1, -1):  
       res.append(a[j])  
   return res

def reverse(lst):  
   return [ele for ele in reversed(lst)]

def decode1(data):

   size = len(data)  
   new = []

   for i in range(0, size, 3):  
       a0 = (data[i] - data[i+1] + data[i+2]) // 2  
       a1 = (data[i+1] - data[i+2] + data[i]) // 2  
       a2 = (data[i+2] - data[i] + data[i+1]) // 2

       new.append(a0)  
       new.append(a1)  
       new.append(a2)  
  
   return(new)

def decode2(data):

   size = len(data)  
   for i in range(size-1, -1, -1):  
       data[i] ^= data[size - i - 1]  
  
   return(data)

def decode3(data):

   first = ord('}')  
   size = len(data)  
   new1 = []

   for i in range(size-1, -1, -1):

       first = first ^ data[i]  
       new1.append(first)  
  
   new1 = reverse(new1)  
   new2 = []  
   for i in range(size):  
       new2.append(new1[(i+1)%size])

   return new2

test = [ord(f) for f in
long_to_bytes(28946494946812141829547706026065914605092406854105997612241563383442514740934913838546119691331952671988567947306226900850151388621540356510466883510328793101483278519506803779932615196763052658252298923048223762802716830885754352726914690907223838594044069643833511017514637891042919056).decode()]

flags = True

for i in range(1, 30):  
   test = displace(test, 72)  
  
for i in range(1, 310):  
   test = displace(test, 66)

for i in range(1, 4290):  
   test = displace(test, 60)

for i in range(1, 2590):  
   test = displace(test, 54)

for i in range(1, 37128):  
   test = displace(test, 48)

for i in range(1, 168):  
   test = displace(test, 42)

for i in range(1, 18):  
   test = displace(test, 36)

for i in range(1, 60):  
   test = displace(test, 30)

for i in range(1, 42):  
   test = displace(test, 24)

for i in range(1, 36):  
   test = displace(test, 18)

for i in range(1, 20):  
   test = displace(test, 12)

for i in range(1, 12):  
   test = displace(test, 6)

print(test)

size = len(test)

test1 = decode1(test)  
print(test1)

test2 = decode2(test1)  
print(test2)

test3 = decode3(test2)  
print(test3)

flag = ''.join(chr(test3[i]) for i in range(size))  
print(flag)  
```

Here is the output and the flag  
```text  
[128, 45, 131, 170, 99, 103, 183, 126, 115, 88, 91, 3, 63, 137, 92, 148, 94,
68, 162, 82, 84, 148, 142, 184, 130, 141, 111, 161, 227, 166, 105, 76, 107,
169, 122, 171, 68, 145, 91, 6, 111, 105, 214, 213, 213, 153, 144, 143, 115,
195, 134, 111, 101, 198, 155, 110, 53, 215, 193, 198, 180, 169, 179, 96, 106,
176, 234, 199, 181, 163, 136, 149, 41, 45, 40, 49, 66, 65]  
[107, 21, 24, 87, 83, 16, 86, 97, 29, 0, 88, 3, 9, 54, 83, 61, 87, 7, 82, 80,
2, 95, 53, 89, 50, 80, 61, 50, 111, 116, 68, 37, 39, 109, 60, 62, 7, 61, 84,
0, 6, 105, 107, 107, 106, 76, 77, 67, 27, 88, 107, 104, 7, 94, 49, 106, 4,
110, 105, 88, 95, 85, 84, 83, 13, 93, 108, 126, 73, 88, 75, 61, 18, 23, 22,
24, 25, 41]  
[41, 25, 24, 22, 23, 18, 61, 75, 88, 73, 126, 108, 93, 13, 83, 84, 85, 95, 88,
105, 110, 4, 106, 49, 94, 7, 104, 107, 88, 27, 67, 77, 76, 106, 107, 107, 105,
6, 0, 84, 59, 110, 85, 87, 7, 107, 104, 7, 111, 55, 89, 85, 87, 108, 104, 95,
91, 108, 57, 10, 88, 2, 105, 0, 59, 84, 111, 38, 73, 69, 42, 107, 2, 68, 65,
0, 12, 66]  
[84, 77, 85, 67, 84, 70, 123, 48, 104, 33, 95, 51, 110, 99, 48, 100, 49, 110,
54, 95, 49, 53, 95, 110, 48, 55, 95, 52, 108, 119, 52, 121, 53, 95, 52, 95,
54, 48, 48, 100, 95, 49, 100, 51, 52, 95, 55, 48, 95, 104, 49, 100, 51, 95,
55, 104, 51, 95, 102, 108, 52, 54, 95, 95, 100, 48, 95, 121, 48, 117, 95, 52,
54, 114, 51, 51, 63, 125]  
TMUCTF{0h!_3nc0d1n6_15_n07_4lw4y5_4_600d_1d34_70_h1d3_7h3_fl46__d0_y0u_46r33?}  
```

```  
Flag :
TMUCTF{0h!_3nc0d1n6_15_n07_4lw4y5_4_600d_1d34_70_h1d3_7h3_fl46__d0_y0u_46r33?}  
```

[solution code](https://github.com/KooroshRZ/CTF-
Writeups/blob/main/TMU2021/Crypto/BabyEncoder/solve.py)

> KouroshRZ for **AbyssalCruelty**

Original writeup (https://kooroshrz.github.io/CTF-
Writeups/TMU2021/Crypto/BabyEncoder/).