# UIUCTF 2022 - easy math 1 Writeup  
- Type - pwn  
- Name - easy math 1  
- Points - 88

## Description  
```markdown  
Take a break from exploiting binaries, and solve a few* simple math problems!

$ ssh ctf@easy-math.chal.uiuc.tf, password is ctf

author: kuilin  
```

## Writeup  
This pwn problem was pretty interesting and not too difficult to implement.
Once you signed in to the server using the provided credentials, you were
greeted with four challenge files:

```  
$ ssh ctf@easy-math.chal.uiuc.tf  
ctf@easy-math.chal.uiuc.tf's password:  
== proof-of-work: disabled ==  
ctf@test-center:~$ ls -l  
-rw-r--r-- 1 ctf   ctf     265 Jul 30 18:48 README  
-r-sr-xr-x 1 admin admin 13296 Jul 30 18:50 easy-math  
-rw-r--r-- 1 ctf   ctf    1348 Jul 29 09:01 easy-math.c  
-r-------- 1 admin admin   327 Jul 29 09:01 flag  
ctf@test-center:~$ cat flag  
cat: flag: Permission denied  
ctf@test-center:~$  
```

The `README` contained some information about what programs were installed on
the Ubuntu 18.04 instance to help with on-prem solve scripts. The `flag` file
was only readable by the `admin` user. Then, the source code and binary for
`easy-math` were provided. The whole source code can be found
[here](https://github.com/BYU-CTF-
group/writeups/blob/main/UIUCTF_2022/easy%20math%201/easy-math.c), but the
important parts are below:

```c  
#define MATH_PROBLEMS 10000

int take_test() {  
 int urand = open("/dev/urandom", O_RDONLY);  
 if (!urand) return 1;  
 unsigned char urand_byte;

 for (int i=0; i<MATH_PROBLEMS; i++) {  
   if (read(urand, &urand_byte, 1) != 1) return 1;  
   int a = urand_byte & 0xf;  
   int b = urand_byte >> 4;  
   printf("Question %d: %d * %d = ", i+1, a, b);

   int ans;  
   if (scanf("%d", &ans) != 1) return 1;  
   if (ans != a * b) return 1;  
 }

 close(urand);  
 return 0;  
}

int main() {  
 setreuid(geteuid(), getuid());  
 setvbuf(stdout, NULL, _IONBF, 0);

 // ...

 if (take_test()) {  
   printf("You have failed the test.\n");  
   return 1;  
 }

 setreuid(getuid(), getuid());  
 system("cat /home/ctf/flag");  
 return 0;  
}  
```

The gist of this script is that 10,000 simple math problems will be thrown at
you, and if all of them are solved correctly, then the flag will be printed
out. However, this binary wasn't accessible through a netcat listener, but
rather when signed in to the SSH server. There were two approaches I could
take - develop a script that would sign in to SSH and answer all the problems,
or create a script on the server that would solve it for me. I was lazy, so I
decided to take the first route.

My solve script ([math.py](https://github.com/BYU-CTF-
group/writeups/blob/main/UIUCTF_2022/easy%20math%201/math.py)) hinged on the
Python library [pexpect](https://pexpect.readthedocs.io/en/stable/). This
library allowed you to run system commands, capture the output, and send
custom input dynamically by using the `spawn()`, `expect()`, and `sendline()`
commands. It SSHed into the system, ran the executable, and captured both
numbers. It then passed it into eval and sent the result to the program
through the SSH tunnel. It printed out each question it solved and then the
flag:

```  
$ python3 math.py  
Question 1: 13 * 3 = 39  
Question 2: 6 * 0 = 0  
Question 3: 10 * 9 = 90  
Question 4: 7 * 15 = 105  
Question 5: 14 * 5 = 70  
Question 6: 13 * 12 = 156  
...  
Question 9999: 15 * 8 = 120  
Question 10000: 11 * 9 = 99  
Flag!  
Nice job! Now, the question is, did you do it the fun way, or by hiding behind
your ssh client?

Part 1 flag:  
uiuctf{now do it the fun way :D}

To solve part 2, use `ssh ctf-part-2@easy-math.chal.uiuc.tf` (password is
still ctf)  
This time, your input is sent in live, but you don't get any output until
after your shell exits.  
ctf@test-center:~$  
```

**Flag:** `uiuctf{now do it the fun way :D}`

Original writeup (https://github.com/BYU-CTF-
group/writeups/tree/main/UIUCTF_2022/easy%20math%201).