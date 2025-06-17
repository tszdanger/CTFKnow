Frogs challenge from Fireshell!

This was a fun challenge from fireshell, one of the only challenges I got
clean enought to make a writeup on!

Basically, this was a programming challenge, in which a script had to
communicate with a socket to solve tasks in a limited time.

The first thing to overcome was a Proof of Work:

```  
[+] Proof of Work my friend :)

[+] send the string that sha256(string)[-6:]: 86df4f  
```  
For this I had a little Python 2 script which I adapted from a previous PoW
that requested MD5 hash cracks, that was the easy part.

Then comes the moment to scratch my head.

```  
+++     FireShellCTF - Frogs | By: @Keerok & @K4L1   +++

[+] A frog can even jumps 3 ladder steps. Send the possibility sum of each
step.

Exemple 1:   1  Exemple 4:  7

Answer  1:   1  Answer  4:  44

[+] Send answer mod 13371337.

[+] You have 3 secs.

[+] Press start:  
```

The challenge (or challange? haha) was first and foremost to understand what
was required of us! After some guesses and eye pain due to the orthography and
syntax, we understand that the task is to compute how many different ways can
there be for a frog that jumps either 1,2, or 3 steps at a time, to get to
step N of the ladder. The examples didn't help much though and were more
confusing than anything else at the beginning haha!

After some trial and error on paper, I wrote a function to compute that sum
for any N, which worked, hurray!

```python  
def numb2(N):  
   t = 0  
   for j in range(1,N+1):  
       p = it.product([1,2,3], repeat=j)  
       for l in p:  
           if sum(l) == N:  
               t += 1  
               t %= 13371337  
   return t  
```

But well, there wasn't only one test, and for values of N greater than 20,
that function wasn't quick enough. So here we go again on the path to some
faster function.

I realized then that there was a recursion relationship between the term, and
that `numb(N) = numb(N-1) + numb(N-2) + numb(N-3)`, and without difficulty
here was a second function:

```python  
def numb3(N):  
   if N == 0 or N == 1:  
       return 1  
   elif N == 2:  
       return 2  
   else:  
       return numb2(N-1) + numb2(N-2) + numb2(N-3)  
```

But well, not fast enough either!

Fed up with all this, we decided to create a lookup table with all values of
numb(N) up to 1000000, with the `generate_jumps_list.py` script, using the
recursion relationship.

And well, we did need such high values of N stored!

```  
[+] Challange 1 - N: 7  
        Answer:  
[+] Nice!

...  
...  
...

[+] Challange 50 - N: 4712  
        Answer:  
[+] Nice!  
```

And finally the long-awaited flag:

```  
[+] Congratulations! You got: F#{M4st3r_0F_Tr1pl3N4t1}  
```

So in the end a nice programming challenge, on which I will have lost a bit of
time (damn you, I could have finished the midi chall in time!), but very nice,
and I learnt a lot about a lot of things! The full script can be found in the
folder for more details: [there](https://github.com/arty-hlr/CTF-
writeups/blob/master/2019/fireshell/Frogs/writeup.md)

Muito obrigado, Fireshell!  

Original writeup (https://github.com/arty-hlr/CTF-
writeups/blob/master/2019/fireshell/Frogs/writeup.md).