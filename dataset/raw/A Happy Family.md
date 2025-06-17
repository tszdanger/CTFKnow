# A Happy Family (74 solves)

> Clam became a parent and had a child. Or at least he dreamed about it.
> Anyway, clam wrote a program to describe his dream. In fact, he's so happy
> that he provided source!  
>  
> Find it on the shell server at `/problems/2020/a_happy_family`.  
>  
> The sha256 hash (no newline) of the correct input is
> `aa15a7b191ffa943fa602f7472ef294c6b5d138a629ac2bb75cb6ac57bfc3257`.  
>  
> Author: aplet123

Solution:

First, find all possible n1, n2, n3, n4 (check **find_all_possible** function)

Next, apply reverse math on them and convert back to string.

Copy those strings that have all printable characters in them.

In the end, we have 1 in n1, n2, n3 and 4 in n4

```python  
from itertools import zip_longest, product  
import sys  
from struct import *  
import string

alphabet = "angstromctf20"  
alphabet_st = "0123456789ABC"

flags = {  
   'c1' : 'artomtf2srn00tgm2f',  
   'c2' : 'ng0fa0mat0tmmmra0c',  
   'c3' : 'ngnrmcornttnsmgcgr',  
   'c4' : 'a0fn2rfa00tcgctaot'  
}  
  
  
def find_all_possible(inp):  
   th_nums = [[alphabet_st[i] for i, y in enumerate(alphabet) if y == x] for x
in inp]  
   variants = [''.join(x) for x in product(*th_nums) ]  
   nums = [int(x, 13) for x in variants]  
   return nums

def main():  
   n1 = pack('

Original writeup (https://github.com/archercreat/CTF-
Writeups/blob/master/angstromctf/rev/A%20Happy%20Family/README.md).