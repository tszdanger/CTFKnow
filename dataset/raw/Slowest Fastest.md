# Slowest Fastest (500 points)

## Description

This is an emergency, we need you to help us organize our gift building
process. We're in a hurry so let's go!

Target: nc challs.xmas.htsp.ro 6055

Authors: Gabies, Nutu

## Solution

```shell  
$ nc challs.xmas.htsp.ro 6055  
Hey, we've got a problem at the factory! As you well know we have N rooms in
our factory, and in the i-th room we have v[i] gifts that have to be built.  
Also, at the factory we have N mechagnomes of two possible types:  
	K of them are the Fast-O-Bot type, which can build P gifts in a single day  
	The rest of N - K bots are the Speed-O-Tron type which can build Q gifts in a single day.

Each day a mechagnome is assigned to a room, and that day it'll work all by
itself in that room, building as many gifts as it can.  
If there are no gifts to be built or he finishes all of them before the end of
the day, the mechagnome goes idle. There cannot be two mechagnomes in the same
room in the same day.  
Since we're in a hurry, we need the minimum number of days we can build all
gifts. Can you help us?  
Just to be safe, we have to solve 100 such scenarios. We don't want to waste
any time so we'll give you 60 seconds to solve everything.  
Ah, and since our connection is so slow, we'll define v in the following way:
v[i] = (a * v[i - 1] + c) % mod for all i = 2, n

Test number: 1/100  
N = 8, K = 1  
P = 181, Q = 211  
v[1] = 16138, a = 95563, c = 36925, mod = 100001  
```

When I saw the flag, I realized that my decision was not as what was supposed
to be. At first I wrote a fairly clever algorithm (which turned out to be
untrue), but every time some task failed, and the algorithm was honestly slow.
Then I decided to write some straight forward code, which I optimized a little
in order to have time to pass 100 tests in a minute, and, to my surprise, it
worked. Here's my garbage code:

```python  
from pwn import *  
import numpy as np  
import math

def filter_nonzero(arr, k):  
   return arr[np.nonzero(arr > k)]

conn = remote('challs.xmas.htsp.ro', 6055)  
conn.recvuntil("Test number: 1/100\n")

for task in range(100):  
   NandKrecieved = conn.recvline().decode('utf-8').strip().split(', ')  
   NandK = list(map(lambda x: int(x[4:]), NandKrecieved))  
   N = NandK[0]  
   K = NandK[1]

   PandQrecieved = conn.recvline().decode('utf-8').strip().split(', ')  
   PandQ = list(map(lambda x: int(x[4:]), PandQrecieved))  
   P = PandQ[0]  
   Q = PandQ[1]

   def mapVitems(x):  
       res = x[4:]  
       if (x[0:1] == "v"):  
           res = x[7:]  
       elif (x[0:1] == "m"):  
           res = x[6:]  
       return int(res)  
   vItemsRecieved = conn.recvline().decode('utf-8').strip().split(', ')  
   vItems = list(map(mapVitems, vItemsRecieved))  
   v1 = vItems[0]  
   a = vItems[1]  
   c = vItems[2]  
   mod = vItems[3]

   fast_o_bots = K  
   speed_o_trons = N - K

   if (P >= Q):  
       bots = {  
           'fastBots': {'amount': fast_o_bots, 'giftsPerDay': P},  
           'slowBots': {'amount': speed_o_trons, 'giftsPerDay': Q}  
       }  
   else:  
       bots = {  
           'fastBots': {'amount': speed_o_trons, 'giftsPerDay': Q},  
           'slowBots': {'amount': fast_o_bots, 'giftsPerDay': P}  
       }

   roomsGifts = [v1]  
   for x in range(1,N):  
       giftsForRoom = (a * roomsGifts[-1] + c) % mod  
       roomsGifts.append(giftsForRoom)  
  
   roomsGifts = -np.sort(-np.array(roomsGifts))

   def work(roomsGifts, bots, counter, iteration):  
       fastBotsAmount = bots["fastBots"]["amount"]  
       fastBotsGifts = bots["fastBots"]["giftsPerDay"]  
       slowBotsGifts = bots["slowBots"]["giftsPerDay"]

       firstPart = roomsGifts[:fastBotsAmount]  
       secondPart = roomsGifts[fastBotsAmount:]

       currentCounter = counter + 1  
       if (iteration < 17):  
           firstItem = roomsGifts[0]  
           mult = math.floor(firstItem / fastBotsGifts)  
           mult = math.floor(mult / 3)  
           a = np.subtract(firstPart, fastBotsGifts * mult)  
           b = np.subtract(secondPart, slowBotsGifts * mult)

           currentCounter = counter + mult  
       else:  
           a = np.subtract(firstPart, fastBotsGifts)  
           b = np.subtract(secondPart, slowBotsGifts)

       temp = np.concatenate([a, b])  
       leftGifts = filter_nonzero(temp, 0)  
  
       if (len(leftGifts) == 0):  
           return counter

       leftGifts = -np.sort(-leftGifts)

       return work(leftGifts, bots, currentCounter, iteration + 1)

  
   totalCounter = work(roomsGifts, bots, 1, 0)

   conn.sendline(str(totalCounter))  
   conn.recvline()  
   print(conn.recvline())  
   print(conn.recvline())

conn.interactive()  
```

```shell  
[*] Switching to interactive mode  
Thanks for saving Christmas this year!  
Here's the flag: X-MAS{l0l_h0w_15_7h1s_4_b1n4ry_s34rch_pr0bl3m?}  
[*] Got EOF while reading in interactive  
```

Flag: X-MAS{l0l_h0w_15_7h1s_4_b1n4ry_s34rch_pr0bl3m?}

Original writeup
(https://github.com/holypower777/ctf_writeups/tree/main/xmasCTF_2020/slowest_fastest).