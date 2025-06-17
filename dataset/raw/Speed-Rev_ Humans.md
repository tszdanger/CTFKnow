## Speed Rev Humans

> This challenge requires us to solve 6 reverse engineering problems in 30
> minutes.

> The server will give us the binary in base64 which we will have to decode
> and reverse to get the flag. After entering the correct flag, the server
> will then proceed to give us the second set of binaries, and so on. If you
> fail, the server will exit and you will have to reconnect and obtain a
> slightly different set of binaries (varied values). My set of 6 RE problems
> can be found
> [here](https://github.com/Rookie441/CTF/blob/main/Categories/Reverse%20Engineering/Medium/speed-
> rev-humans/binaries.zip)

> The first RE problem is easy as the flag is just written in plaintext.

![image](https://github.com/Rookie441/CTF/blob/main/Categories/Reverse%20Engineering/Medium/speed-
rev-humans/1.png?raw=true)

```  
RI6dEKEAByHzmfTi  
```

> The second and third binary is also trivial as we can deduce the flag from
> following the if statements in the array.

![image](https://github.com/Rookie441/CTF/blob/main/Categories/Reverse%20Engineering/Medium/speed-
rev-humans/2.png?raw=true)

```  
Pew0TG34kIVCra3f  
```

![image](https://github.com/Rookie441/CTF/blob/main/Categories/Reverse%20Engineering/Medium/speed-
rev-humans/3.png?raw=true)

```  
fEsrfdYQ8G3t3Os0  
```

> Now the fourth binary starts to be more interesting.

![image](https://github.com/Rookie441/CTF/blob/main/Categories/Reverse%20Engineering/Medium/speed-
rev-humans/4.png?raw=true)

> These are a series of constraints or equations that involve the elements of
> the `param_1` array and their sum with other elements, and they must be
> satisfied in order to reach the nested if-condition to give us the flag.

> In more specific terms:  
- `param_1[1] + param_1[0] == 0x8c` means that the sum of `param_1[1]` and `param_1[0]` must be equal to `0x8c` (140 in decimal).  
- `param_1[2] + param_1[1] == 0xa2` means that the sum of `param_1[2]` and `param_1[1]` must be equal to `0xa2` (162 in decimal).  
- `param_1[3] + param_1[2] == 0xb0` means that the sum of `param_1[3]` and `param_1[2]` must be equal to `0xb0` (176 in decimal).  
- and so on...

> We can write a python code using the [z3
> library](https://pypi.org/project/z3-solver/), which is a powerful solver
> for Satisfiability Modulo Theories (SMT) problems.

```python  
from z3 import *

s = Solver()

# Define variables  
param_1 = [BitVec('param_%d' % i, 8) for i in range(16)]

# Add constraints  
s.add(param_1[1] + param_1[0] == 0x8c)  
s.add(param_1[2] + param_1[1] == 0xa2)  
s.add(param_1[3] + param_1[2] == 0xb0)  
s.add(param_1[4] + param_1[3] == 0x8f)  
s.add(param_1[5] + param_1[4] == 0xc2)  
s.add(param_1[6] + param_1[5] == 0xda)  
s.add(param_1[7] + param_1[6] == 0x93)  
s.add(param_1[8] + param_1[7] == 0x92)  
s.add(param_1[9] + param_1[8] == 0x96)  
s.add(param_1[10] + param_1[9] == 0x68)  
s.add(param_1[11] + param_1[10] == 0x6b)  
s.add(param_1[12] + param_1[11] == 0xa1)  
s.add(param_1[13] + param_1[12] == 0xbc)  
s.add(param_1[14] + param_1[13] == 0xa3)  
s.add(param_1[15] + param_1[14] == 0x9a)

# Add additional constraints for lowercase letters, uppercase letters, and
numbers  
for i in range(16):  
   s.add(Or(And(param_1[i] >= 48, param_1[i] <= 57),  # numbers  
            And(param_1[i] >= 65, param_1[i] <= 90),  # uppercase letters  
            And(param_1[i] >= 97, param_1[i] <= 122)))  # lowercase letters

# Check if the constraints are satisfiable and print the solution if it exists  
if s.check() == sat:  
   m = s.model()  
   decoded_message = ''  
   for i in range(16):  
       char_value = m[param_1[i]].as_long()  
       decoded_message += chr(char_value)  
   print(decoded_message)  
else:  
   print("unsatisfiable")  
```

> These constraints are used to guide the search for values of `param_1` that
> satisfy these relationships, ultimately resulting in a solution that
> satisfies all the constraints.

```  
V6lDKwc0b447jRQI  
```

> The fifth and last binary differ slightly from the fourth in that not all
> the constraints is an addition of adjacent array values

![image](https://github.com/Rookie441/CTF/blob/main/Categories/Reverse%20Engineering/Medium/speed-
rev-humans/5.png?raw=true)

> We can simply modify the constraints portion of our code.

```python  
s.add(param_1[1] + param_1[0] == 0x98)  
s.add(param_1[2] + param_1[1] == 0x97)  
s.add(param_1[3] + param_1[2] == 0xad)  
s.add(param_1[4] + param_1[3] == 0xab)  
s.add(param_1[5] + param_1[4] == 0x89)  
s.add(param_1[6] + param_1[5] == 0xab)  
s.add(param_1[7] + param_1[6] == 0xed)  
s.add(param_1[8] + param_1[7] == 0xa8)  
s.add(param_1[8]  == ord('0'))  
s.add(param_1[9]  == ord('D'))  
s.add(param_1[10]  == ord('w'))  
s.add(param_1[11]  == ord('d'))  
s.add(param_1[12]  == ord('3'))  
s.add(param_1[13]  == ord('e'))  
s.add(param_1[14]  == ord('b'))  
```

> Note that since there are no restrictions for `param_1[15]`, it can be any
> character. In my run I got a `w`, you may have a different character.

```  
VBUXS6ux0Dwd3ebw  
```

![image](https://github.com/Rookie441/CTF/blob/main/Categories/Reverse%20Engineering/Medium/speed-
rev-humans/6.png?raw=true)

```python  
s.add(param_1[1] + param_1[0] == 0xc3)  
s.add(param_1[2] + param_1[1] == 0xd9)  
s.add(param_1[3] + param_1[2] == 0xd4)  
s.add(param_1[4] + param_1[3] == 0xc0)  
s.add(param_1[5] + param_1[4] == 0xa3)  
s.add(param_1[6] + param_1[5] == 200)  
s.add(param_1[7] + param_1[6] == 0xbe)  
s.add(param_1[8] + param_1[7] == 0x80)  
s.add(param_1[9] + param_1[8] == 0x99)  
s.add(param_1[10] + param_1[9] == 0xd2)  
s.add(param_1[11] + param_1[10] == 0xdd)  
s.add(param_1[12] + param_1[11] == 0xbb)  
s.add(param_1[12]  == ord('N'))  
s.add(param_1[13]  == ord('c'))  
s.add(param_1[14]  == ord('e'))  
```

```  
NudpPSuI7bpmNcez  
```

> I made a short "speedrun video" which can be found
> [here](https://youtu.be/r4AumzdBK9g). The script used can be found in
> [solver.py](https://github.com/Rookie441/CTF/blob/main/Categories/Reverse%20Engineering/Medium/speed-
> rev-humans/solver.py)

`flag{Human_or_r0b0t_1dk}`  

Original writeup
(https://github.com/Rookie441/CTF/blob/main/Categories/Reverse%20Engineering/Medium/speed-
rev-humans/speed-rev-humans.md#speed-rev-humans).