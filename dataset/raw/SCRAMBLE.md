# SCRAMBLE

This challenge was kinda like Wordle, with the twist that you had to guess a
completely random string. The game gives you a wordlist of 12000 words and the
requirement to get the flag was, to solve 100 games in less than 500 total
guesses. After failing 5 times for one game, we get a new game but without
getting a new solve.

The server lets us guess 7 times per word and it sends us a string back, which
tells us how close we are.

example:

secret: SEINR  
  
guess: EEONE  
  
comparison: \*\+\-\+\*

\* means that that character in the guess is also in the secret word, + means
that the position is right and - tells us that the character is not inside the
secret.

I wrote a function that removes wrong words from the wordlist by using the
comparison we got back:

```py  
def eliminate(res, guess, wl):  
   result = []  
   for e in wl:  
       flg = True  
       for i in range(5):  
           if res[i] == "*" or res[i] == "+":  
               if guess[i] not in e:  
                   flg = False  
           if res[i] == "+":  
               if guess[i] != e[i]:  
                   flg = False  
           if res[i] == "-":  
               if guess[i] in e:  
                   flg = False  
       if flg and e != guess:  
           result.append(e)  
   return result  
```

And then also some code to communicate with the server (of course I also
tested it locally):

```py  
def pwn():  
   conn = remote("scamble.rumble.host", 2568)

   old_wordlist =
conn.recvuntil(b'>').decode().split("\n[")[1].split("\n")[1:]

   while True:  
       wordlist = old_wordlist  
       while True:  
           choice = ""  
           if len(wordlist) == 12000:  
               choice = rng.choice(wordlist)  
           else:  
               choice = rng.choice(wordlist)  
           conn.sendline(choice)  
           res = conn.recvuntil(b'> ').decode().strip()  
           if "avg" in res:  
               conn.interactive()  
           if "[guess correct]" in res or "[number of guesses exceeded]" in res:  
               conn.recvline()  
               r = conn.recvline().decode()  
               if "avg" in r:  
                   print(r)  
                   try:  
                       print(conn.recvline())  
                   except:  
                       pass  
                   conn.close()  
                   return  
               conn.recvuntil(b'> ').decode()  
               break  
           res = res.split("\n")[0]  
           wordlist = getpossible(res, choice, wordlist)

while True:  
   pwn()  
```

It fetches the wordlist, then randomly chooses a word each time and eliminates
using the feedback from the server.

But that was sadly not enough. I optimized my code a bit by trying to find
good guesses. I tried some things like e.g. choosing guesses that are as far
apart from the previous guess as possible but that did not really improve my
score. Luckily, choosing a good starting guess, which includes one of the
words with the least amount of duplicates possible.

```py  
def getstartinggoodguess(wl):  
   scores = {1: [], 2: [], 3: [], 4: [], 5: []}  
   for e in wl:  
       scores[max([e.count(x) for x in e])].append(e)  
   for j in [1, 2, 3, 4, 5]:  
       if len(scores[j]) != 0:  
           return scores[j][0]  
```

With some additional luck and a few tries later I finally got the flag! (With
a score of 4.82)

Original writeup
(https://github.com/xXLeoXxOne/writeups/blob/main/CyberSecurityRumble%202022/SCRAMBLE.md).# Harekaze 2019 "scramble" writeup

## problem

One binary "scramble" is provided.

## solution

![screen1](screen1.jpg "screen1")

check "puts("Correct!")" address and solve by angr.

<https://docs.angr.io/core-concepts/pathgroups>

```python  
import angr

proj = angr.Project("./scramble")

# puts("Correct!")  
target_addr = 0x40073E

state = proj.factory.entry_state()  
simgr = proj.factory.simgr(state)  
simgr.explore(find=target_addr)  
state = simgr.found[0]  
print(state.posix.dumps(0))  
```

```  
b'HarekazeCTF{3nj0y_h4r3k4z3_c7f_2019!!}'  
```  

Original writeup (https://github.com/wani-hackase/wani-
writeup/tree/master/2019/05-harekaze/rev-scramble).