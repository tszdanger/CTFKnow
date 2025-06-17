# Infinity Gauntlet  
- Category: Reverse  
- Points: 75  
- Solved by: mindlæss, drw0if, Iregon

## Description:  
All clam needs to do is snap and finite will turn into infinite...

```  
nc shell.actf.co 21700  
```

## Analysis:  
Launching the program (or the netcat connection) we see that it asks us to
complete a given function, which appears to be either "foo()" or "bar()". When
will we get the flag though? To understand better what to do we decide to open
the binary in Ghidra. As expected, we have (besides the main function of
course) a foo() and a bar(); after a quick look, we see that they make some
simple operations with the given parameters and then return the result.

Another interesting thing we noticed was that the flow in the main function
was different depending on the round we were playing.

Also, most importantly, we see that in the beginning of the code a "flag.txt"
file is read into a pointer and then each character is XORed by its position
times 0x11; this will be useful to know in the final part of the challenge.

Now that we know what we are dealing with, we can start thinking about an
exploit.

## Exploitation and Solution:  
First of all, we need the exploit to know which function he has to reverse and
which value needs to be calculated.  
To do this, we used regular expressions, one for foo() and one for bar():

```  
foo_regex = 'foo\((\d*|\?), (\d*|\?)\) = (\d*|\?)\n'  
```

```  
bar_regex = 'bar\((\d*|\?), (\d*|\?), (\d*|\?)\) = (\d*|\?)\n'  
```

With these, we can create a variable for each known value the program gives
us, as follows:  
```  
if 'bar' in l:  
   matches = re.search(bar_regex, l)  
   a, b, c, d = [matches.group(x) for x in range(1, 5)]  
```

```  
elif 'foo' in l:  
   matches = re.search(foo_regex, l)  
   a, b, c = [matches.group(x) for x in range(1, 4)]  
```  
where l is the program's request.

After seeing the code of foo() and bar(), we implemented some functions to get
the required value, one for each unknown parameter.  
```  
def foo1(b, c):  
   b = int(b)  
   c = int(c)

   return c ^ 0x539 ^ (b + 1)

def foo2(a, c):  
   a = int(a)  
   c = int(c)

   return (c ^ a ^ 0x539) - 1

def foo3(a, b):  
   a = int(a)  
   b = int(b)

   return (b + 1) ^ a ^ 0x539

def bar1(b, c, d):  
   b = int(b)  
   c = int(c)  
   d = int(d)

   return -((c + 1) * b) + d

def bar2(a, c, d):  
   a = int(a)  
   c = int(c)  
   d = int(d)

   return (d - a)//(c + 1)

def bar3(a, b, d):  
   a = int(a)  
   b = int(b)  
   d = int(d)

   return ((d-a)//b)-1

def bar4(a, b, c):  
   a = int(a)  
   b = int(b)  
   c = int(c)

   return (c + 1)*b + a  
```

By sending the values returned by these functions to the server, we can easily
pass every round!  
Wait... where's our flag though?!

Well, remember when I told you that the flow changes depending on the round we
are playing? Well, here's what happens: depending on the round number a
variable is created; in this variable the high bits are an element in an array
(let's call it flag_buffer) and the lower bits represent the element in that
position itself.  
Now to reconstruct the flag after the 49th round we need to do the following:  
1) Create a bytes array to store the flag characters

```  
flag = [0]*30  
```

2) Reconstruct the position in which the character will be stored:

```  
pos = (ans >> 8) & 0xFF  
pos -= round_counter  
```

3) Taking the character that has to be stored in that position:

```  
letter = ans & 0xFF  
```

4) Store the character in its position without forgetting that it was XORed in
the beginning of the program:

```  
flag[pos] = (letter ^ (0x11*pos)) & 0xFF  
```

## Conclusion  
After all these steps we are finally able to obtain the flag in our bytes
array, which we can print after every round after the 49th:

```  
actf{snapped_away_the_end}  
```  

Original writeup
(https://github.com/r00tstici/writeups/tree/master/angstromCTF_2021/infinity_gauntlet).