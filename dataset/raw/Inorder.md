# Inorder (misc, 308p, 28 solved)

## Description

```  
Our experience with algorithms since high school is quite impressive, and so
is our security expertise. However, I wonder if a good hacker can find
vulnerabilities in this code which may help to leak the flag without
performing a dumb brute force.

Flag format: CTF{message} where:

   message length: 12-20  
   message charset: ASCII 33 - 126

PS: We run this with socat.  
```

In the task we get a simple [python
script](https://raw.githubusercontent.com/TFNS/writeups/master/2020-12-05-DefCampCTF/inorder/inorder.py)

## Task analysis

The idea is pretty simple:

- We can create a binary tree with our own inputs on the server  
- We can add nodes  
- We can search for things in the tree  
- When we quit the server will perform search for the flag in our tree and then send `Bye!`

## Vulnerability

The trick here is that the tree is not balanced automatically.  
We can easily create a very long linear branch by sending identical inputs.

This means that searching in this tree will become slower as the tree grows.  
If we create such long branch, and then exit, the server might need to take
time to search for the "flag" and we can measure this.

## Solution

### Creating test-case

If we create a tree with 10k nodes `x` and then exit, then there are 2 cases:

- exit is slow, therefore `flag < 'x'`  
- exit is quick, therefore `flag >= 'x'`

### Retrieving data

We could try a binary search, but server was not very reliable, so eventually
it was better to make a linear search and observer when we started to get
`slow` responses instead of `quick` ones, and such transition meant we found
right char.

```python  
from time import time

from crypto_commons.netcat.netcat_commons import nc, send,
receive_until_match, receive_until

def main():  
   host = "34.89.211.188"  
   port = 31070  
   known = ''  
   for char in range(33, 127):  
       if char != ord(';') and char != ord(' '):  
           char = chr(char)  
           s = nc(host, port)  
           for i in range(4):  
               x = receive_until_match(s, "Your option: ")  
               payload = "/a " + (';'.join([known + char for _ in range(2047)]))  
               send(s, payload)  
               x = receive_until(s, "\n")  
               x = receive_until_match(s, ".*\\d+")  
           start = time()  
           send(s, '/exit')  
           x = receive_until_match(s, "Bye!")  
           stop = time()  
           print(char, stop - start)  
           s.close()

main()  
```

We need to manually set the `known` part after each character run, but it's
the only way to be sure.  
We can also "verify" by setting `char` we think it is, and also `char+1`.  
If for `char` we're starting with `quick` responses and `char+1` starts
already with `slow` it means we have the right char.

After a while we finally arrive at: `CTF{W3ll_D0N3!$_^_}`  

Original writeup
(https://github.com/TFNS/writeups/tree/master/2020-12-05-DefCampCTF/inorder).