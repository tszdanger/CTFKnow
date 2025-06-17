# Machine Trouble

tag: medium e4stw1nd

I don't think even smart people like you can get the flag out of such a
machine with so little memory. Prove me wrong. If you find it, enclose the
flag in pearl{}.

NOTE: Flag does not have any upper case character and number.

## Solve

We are welcome with this, which is the true problem

```  
(ins)→ nc dyn.ctf.pearlctf.in 30018  
ooooooooo.   oooooooooooo       .o.       ooooooooo.   ooooo  
`888   `Y88. `888'     `8      .888.      `888   `Y88. `888'  
888   .d88'  888             .8"888.      888   .d88'  888  
888ooo88P'   888oooo8       .8' `888.     888ooo88P'   888  
888          888    "      .88ooo8888.    888`88b.     888  
888          888       o  .8'     `888.   888  `88b.   888       o  
o888o        o888ooooood8 o88o     o8888o o888o  o888o o888ooooood8

Welcome to The Finite State Machine:  
=======================RULES===========================  
The flag is set as the input string, and the alphabets of the language are set
to a-z, {, }, _.  
Here, you can define your own states and transitions.  
If there is no defined transition for a particular letter, then the machine
gets trapped.  
It must be a DFA, not an NFA.  
An output of 1 means that the string is present in the language; 0 means
otherwise.  
'@' takes the machine from one state to another by consuming any one letter.  
'~l' takes the machine from one state to another by consuming one letter
unless the letter is 'l'.  
Example: '5 @ 6' takes the machine from state 5 to state 6 for all letters.  
Example: '6 ~b 7' takes the machine from state 6 to state 7 for all letters
except 'b'.  
=================================================  
Enter number of states:  
```

What we can do is rather simple, we new create a machine that run on the flag,
what this mean is  
- We chose our machine  
   - have how much state `S` - Zero index  
   - stated state alway set to 0  
   - (at least one) final states `f[] = [...]`  
   - how much transitor `T`  
   - define exact transition with two type `t[] = [...]`  
       - '@' consume a character (which I assumming we running on flag character here)  
       - '~a' consume a character unless the letter is 'a'  
       - Each transitor can tranform a state to other state with one of either type 

Now let start with a string, and a defined machine

- This machine jump state one by one, with any character

   ```python  
   length = 11  
   t = ["".join([str(i), ' @ ', str(i+1)]) for i in range(length-1)]  
   T = len(t)  
   S = len(t) + 1  
   f = [S - 1]

   print(S)  
   print(" ".join([str(i) for i in f]))  
   print(T)

   for line in t:  
       print(line)  
   ```

   Not thing much, I trial and error until i found a length where it not stuck

- This machine not allow a single character

   > the alphabets of the language are set to a-z, {, }, _.

   ```python  
   # ...  
   t = ["".join([str(i), ' ~b ', str(i+1)]) for i in range(length-1)]  
   # ...  
   ```

   So we update the code that automate this process for us, base on the final
byte return by nc  
   ```python  
   import time  
   import socket

   class Netcat:  
       """ Python 'netcat like' module """

       def __init__(self, ip, port):  
           self.buff = ""  
           self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
           self.socket.connect((ip, port))

       def read(self, length=1024):  
           """ Read 1024 bytes off the socket """  
           return self.socket.recv(length)

       def read_until(self, data):  
           """ Read data into the buffer until we have data """  
           while data not in self.buff:  
               self.buff += self.socket.recv(1024).decode("ascii")

           pos = self.buff.find(data)  
           rval = self.buff[:pos + len(data)]  
           self.buff = self.buff[pos + len(data):]

           return rval

       def write(self, data):  
           self.socket.send(data)

       def close(self):  
           self.socket.close()

   def crafted(f=None, position=None):  
       result = ""  
       length = 11  
       t = ["".join([str(i), ' @ ', str(i+1)]) for i in range(length-1)]  
       if f is not None:  
           if position is not None:  
               t[position] = "".join([str(position), f' ~{f} ', str(position+1)])  
           else:  
               t = ["".join([str(i), f' ~{f} ', str(i+1)])  
                    for i in range(length-1)]

       T = len(t)  
       S = len(t) + 1  
       f = [S - 1]

       result += str(S) + '\n'  
       result += " ".join([str(i) for i in f]) + '\n'  
       result += str(T) + '\n'  
       for line in t:  
           result += line + '\n'  
       return result

   # whitelist = "_acdefhk"  
   for i in 'abcdefghijklmnopqrstuvwxyz':  
       s = Netcat('dyn.ctf.pearlctf.in', 30018)

       data = bytes(crafted(i), 'ascii')  
       s.write(data)  
       time.sleep(3)  
       buf = s.read()  
       buf = s.read()  
       print(i, buf[-2])  
       s.close()  
   ```

   output, i seperate those with b"49"  
   ```python  
   a 46  
       b 49  
   c 46  
   d 46  
   e 46  
   f 46  
       g 49  
   h 46  
       i 49  
       j 49  
   k 46  
       l 49  
       m 49  
       n 49  
       o 49  
       p 49  
       q 49  
       r 49  
       s 49  
       t 49  
       u 49  
       v 49  
       w 49  
       x 49  
       y 49  
       z 49  
   ```

   I can test that we have  
   ```python  
   # blacklist = "bgijl..z{},"  
   whitelist = "_acdefhk"  
   ```

- Final step, just try and error every character, the helper function already cover it so all we have is just update some param  
   ```python  
   whitelist = "_acdefhk"  
   result = ""  
   for pos in range(11):  
       for i in whitelist:  
           s = Netcat('dyn.ctf.pearlctf.in', 30018)

           data = bytes(crafted(i, pos), 'ascii')  
           s.write(data)  
           time.sleep(3)  
           buf = s.read()  
           buf = s.read()  
           print(pos, i, buf[-2])  
           if buf[-2] == 46:  
               result += i  
               break  
           s.close()  
   ```

   output that I already trim-out b"49"  
   ```python  
   0 d 46  
   1 f 46  
   2 a 46  
   3 _ 46  
   4 h 46  
   5 a 46  
   6 c 46  
   7 k 46  
   8 e 46  
   9 d 46  
   ```

   dfa_hacked

Only thing left is  
> enclose the flag in pearl{}

pearl{dfa_hacked}  

Original writeup (https://github.com/nghiango1/pearlctf-
writeup/edit/main/miscellaneous/Machine%20Trouble/).