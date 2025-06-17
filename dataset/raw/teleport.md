Hi, last week I participated in Google CTF 2020 with my team `pwnPHOfun`

Although I didn't solve the challenge in time for the points,  
still, here is a writeup for the challenge `teleport` for you.

I like to write detailed articles that are understandable and replicable to my
past self. Feel free to skip any parts. Here is a table of content for you.

- [Teleport](#teleport)  
- [1. Story](#1-story)  
- [2. Overview](#2-overview)  
 - [2.1. Sandboxed or unsandboxed](#21-sandboxed-or-unsandboxed)  
 - [2.2. Provided primitives](#22-provided-primitives)  
- [3. Leaking the browser process](#3-leaking-the-browser-process)  
- [4. Googling](#4-googling)  
- [5. Leaking the renderer process](#5-leaking-the-renderer-process)  
- [6. Nodes and Ports](#6-nodes-and-ports)  
- [7. Leaking ports' names](#7-leaking-ports-names)  
 - [7.1. Finding offsets](#71-finding-offsets)  
   - [7.1.1. Simple structures](#711-simple-structures)  
   - [7.1.2. F**k C++/Traversing `std::unordered_map`](#712-fk-ctraversing-stdunordered_map)  
- [8. What do we do with stolen ports?](#8-what-do-we-do-with-stolen-ports)  
 - [8.1. Factory of network requests](#81-factory-of-network-requests)  
 - [8.2. Making the leaked ports ours](#82-making-the-leaked-ports-ours)  
   - [8.2.1. Calling functions from shellcode](#821-calling-functions-from-shellcode)  
 - [8.3. Sending our messages](#83-sending-our-messages)  
 - [8.4. Writing our messages](#84-writing-our-messages)  
 - [8.5. To know who our receivers are](#85-to-know-who-our-receivers-are)  
 - [8.6. Where are my factory ??](#86-where-are-my-factory-)  
   - [8.6.1. Setting the sequence_num](#861-setting-the-sequence_num)  
   - [8.6.2. Getting the correct function parameters](#862-getting-the-correct-function-parameters)  
- [9. Closing words](#9-closing-words)  
 - [9.1. Shoutout](#91-shoutout)  
 - [9.2. Reference](#92-reference)

You may want to checkout the [exploit
code](https://github.com/TrungNguyen1909/ggctf20-teleport).

No IDA/Ghidra were used during the creation of this work. I used only GDB.

Original writeup (https://trungnguyen1909.github.io/blog/post/GGCTF20).# Teleport

> One of our admins plays a strange game which can be accessed over TCP. He's
> been playing for a while but can't get the flag! See if you can help him
> out.

We can connect to a remote server, and the source is given:

```python  
import math

x = 0.0  
z = 0.0  
flag_x = 10000000000000.0  
flag_z = 10000000000000.0  
print("Your player is at 0,0")  
print("The flag is at 10000000000000, 10000000000000")  
print("Enter your next position in the form x,y")  
print("You can move a maximum of 10 metres at a time")  
for _ in range(100):  
   print(f"Current position: {x}, {z}")  
   try:  
       move = input("Enter next position(maximum distance of 10): ").split(",")  
       new_x = float(move[0])  
       new_z = float(move[1])  
   except Exception:  
       continue  
   diff_x = new_x - x  
   diff_z = new_z - z  
   dist = math.sqrt(diff_x ** 2 + diff_z ** 2)  
   if dist > 10:  
       print("You moved too far")  
   else:  
       x = new_x  
       z = new_z  
   if x == 10000000000000 and z == 10000000000000:  
       print("ractf{#####################}")  
       break  
```

## Description

We get a Python code, and we need to move to the flag. We are originally at
position `(0,0)`, can move only of at most `10`, and need to get to
`(10000000000000, 10000000000000)` in less than 100 movements. In other words:
we need to break the code.

When we enter a string, it is split with `,`, then each part is converted to
float. If an exception happens, we reach `continue` and can try again.

If the string translates correctly, then those are our new coordinates, and a
check is performed using `math.sqrt` to verify the new position is not too far
from the previous one. If not, we reach the new coordinates.

## Solution

My first thought was to try to pwn the program by using the `input` function,
which is vulnerable in Python 2. However, the syntax suggest Python 3, so this
did not work.

Then I tried to overflow the float, but this does not work either as in
Python, overflows produce an exception.

The solution found was to use special value `nan` (Not a number), which is
interpreted as float in Python. Moreover, `float('nan') > 10` is `False` as
`nan` cannot be compared to numbers.

Therefore the exploit is as follow:  
- first send `nan, nan`. The new position will be `nan, nan`  
- second send `10000000000000, 10000000000000`. We reach the flag.

Flag: `ractf{fl0at1ng_p01nt_15_h4rd}`

Original writeup (https://github.com/apoirrier/CTFs-
writeups/blob/master/AwesomeCTF2020/Misc/Teleport.md).