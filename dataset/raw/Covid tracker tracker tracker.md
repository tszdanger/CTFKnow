# Write-up: COVID tracker tracker tracker  
![badge](https://img.shields.io/badge/CTF%20Writeup-unsolved-red)

## Description

### My Story  
I was working on it for one day (even after CTF finished) and I learned a lot.

I executed the program this way in the directory I downloaded the three files
of challenge:  
```  
$ ./ld-linux-x86-64.so.2 --library-path . ./cttt

COVID tracker tracker tracker  
=============================  
1) Add tracker  
2) Edit tracker  
3) Remove tracker  
4) List trackers  
5) Exit  
>  
```

At the first look I guessed it should be a heap challenge; and it is.

#### Static Analysis

I decompiled `cttt` using Ghidra and found these interesting functions:  
* add  
* edit  
* delete  
* list

and these global variables:  
* urls  
* is_deleted

Functions functionality is obvious. Each is responsible for one of the menu
items. But I analyzed those function statically to find out `urls` and
`is_deleted` use cases. It got cleared:

```  
char *urls[16];  
char is_deleted[16];  
```

And now functions are more clear:  
* add => `urls[index] = malloc(sizeof(char) * 0x40)`  
* edit => `*urls[index] = some_input`  
* delete => `free(urls[index]); is_deleted[index] = 1`  
* list => print every url allocated `char*` if isn't deleted.

The vulnerability is that `delete` doesn't reset the `urls[index]` value to
zero! So it is a use-after-free.

#### Challenging  
I'm not so experienced in heap exploitation. so I started searching about heap
structure and I learned some stuffs. But heap is more complicated to be
understood in one day or two!

I found this amazing resource for learning about heap: [https://heap-
exploitation.dhavalkapil.com/](https://heap-exploitation.dhavalkapil.com/)

It's awesome! But I wanted to solve the challenge quickly. So I skipped a
lot... I just started trial and error!

#### Trial & Error  
I used `add` four times. and used `edit` for each added URL. first one,
`AAAAAAAA`; second one `BBBBBBBB` and ... this is the heap after that:  
```  
-----------------------first-------------------------  
0x4056a0:    0x0000000000000000    0x0000000000000051  
0x4056b0:    0x4141414141414141    0x000000000000000a  
0x4056c0:    0x0000000000000000    0x0000000000000000  
0x4056d0:    0x0000000000000000    0x0000000000000000  
0x4056e0:    0x0000000000000000    0x0000000000000000  
----------------------second-------------------------  
0x4056f0:    0x0000000000000000    0x0000000000000051  
0x405700:    0x4242424242424242    0x000000000000000a  
0x405710:    0x0000000000000000    0x0000000000000000  
0x405720:    0x0000000000000000    0x0000000000000000  
0x405730:    0x0000000000000000    0x0000000000000000  
-----------------------third-------------------------  
0x405740:    0x0000000000000000    0x0000000000000051  
0x405750:    0x4343434343434343    0x000000000000000a  
0x405760:    0x0000000000000000    0x0000000000000000  
0x405770:    0x0000000000000000    0x0000000000000000  
0x405780:    0x0000000000000000    0x0000000000000000  
-----------------------forth-------------------------  
0x405790:    0x0000000000000000    0x0000000000000051  
0x4057a0:    0x4444444444444444    0x000000000000000a  
0x4057b0:    0x0000000000000000    0x0000000000000000  
0x4057c0:    0x0000000000000000    0x0000000000000000  
0x4057d0:    0x0000000000000000    0x0000000000000000  
-----------------------------------------------------  
0x4057e0:    0x0000000000000000    0x0000000000020821  
0x4057f0:    0x0000000000000000    0x0000000000000000  
```  
I was understanding how it works... then I `delete`ed 2 and 3 and 4: (Do you
remember the vulnerability? we still access to each of pointers of deleted
URLs.)  
```  
-----------------------first-------------------------  
0x4056a0:    0x0000000000000000    0x0000000000000051  
0x4056b0:    0x4141414141414141    0x000000000000000a  
0x4056c0:    0x0000000000000000    0x0000000000000000  
0x4056d0:    0x0000000000000000    0x0000000000000000  
0x4056e0:    0x0000000000000000    0x0000000000000000  
----------------------second-------------------------  
0x4056f0:    0x0000000000000000    0x0000000000000051  
0x405700:    0x0000000000000000<-- 0x0000000000405010  
0x405710:    0x0000000000000000  | 0x0000000000000000  
0x405720:    0x0000000000000000  | 0x0000000000000000  
0x405730:    0x0000000000000000  | 0x0000000000000000  
---------------------third-------|-------------------  
0x405740:    0x0000000000000000  | 0x0000000000000051  
0x405750: -->0x0000000000405700--- 0x0000000000405010  
0x405760: |  0x0000000000000000    0x0000000000000000  
0x405770: |  0x0000000000000000    0x0000000000000000  
0x405780: |  0x0000000000000000    0x0000000000000000  
----------|------------forth-------------------------  
0x405790: |  0x0000000000000000    0x0000000000000051  
0x4057a0: ---0x0000000000405750    0x0000000000405010  
0x4057b0:    0x0000000000000000    0x0000000000000000  
0x4057c0:    0x0000000000000000    0x0000000000000000  
0x4057d0:    0x0000000000000000    0x0000000000000000  
-----------------------------------------------------  
0x4057e0:    0x0000000000000000    0x0000000000020821  
0x4057f0:    0x0000000000000000    0x0000000000000000  
```  
Now lets add 2 URLs and edit them to some specific values:  
```  
-----------------------first-------------------------  
0x4056a0:    0x0000000000000000    0x0000000000000051  
0x4056b0:    0x4141414141414141    0x000000000000000a  
0x4056c0:    0x0000000000000000    0x0000000000000000  
0x4056d0:    0x0000000000000000    0x0000000000000000  
0x4056e0:    0x0000000000000000    0x0000000000000000  
----------------------second-------------------------  
0x4056f0:    0x0000000000000000    0x0000000000000051  
0x405700:    0x0000000000000000    0x0000000000405010  
0x405710:    0x0000000000000000    0x0000000000000000  
0x405720:    0x0000000000000000    0x0000000000000000  
0x405730:    0x0000000000000000    0x0000000000000000  
-----------------------third-------------------------  
0x405740:    0x0000000000000000    0x0000000000000051  
0x405750:    0x3131313131313131    0x000000000000000a  
0x405760:    0x0000000000000000    0x0000000000000000  
0x405770:    0x0000000000000000    0x0000000000000000  
0x405780:    0x0000000000000000    0x0000000000000000  
-----------------------forth-------------------------  
0x405790:    0x0000000000000000    0x0000000000000051  
0x4057a0:    0x3030303030303030    0x000000000000000a  
0x4057b0:    0x0000000000000000    0x0000000000000000  
0x4057c0:    0x0000000000000000    0x0000000000000000  
0x4057d0:    0x0000000000000000    0x0000000000000000  
-----------------------------------------------------  
0x4057e0:    0x0000000000000000    0x0000000000020821  
0x4057f0:    0x0000000000000000    0x0000000000000000  
```  
Awesome! Did you get it?! The last `new` I used, caused an allocation on the
same address that forth URL was pointing to. (`0x4057a0` value was `0x405750`
and the last allocation was on the former address.)

#### Idea  
I need to repeat the same inputs. But before the last step (`new` two times)
`edit` the forth URL and set its value to whatever address that I want to
control.

Which address I wanna control?! :thinking:

* What about Global Offset Table (GOT)? But RelRO is fully activated: (I haven't access to write in the .got section!)  
```  
gdb-peda$ checksec  
CANARY    : ENABLED  
FORTIFY   : disabled  
NX        : ENABLED  
PIE       : disabled  
RELRO     : FULL  
```

#### Bypass Full RelRO  
I searched and found the `__free_hook` solution. There is some global
variables that is of function pointer type. ([read
more](https://www.gnu.org/software/libc/manual/html_node/Hooks-for-
Malloc.html))

I need to rewrite the value of one of them. `__free_hook` is a good choice
because when I do `delete` the first argument of `free` function is of type
`char*`. It's like `system` function. So I can change free hook value to
`system` address.

But there is another problem named ASLR! :dizzy_face:  
I don't know the address of `__free_hook`!!

#### Bypass ASLR  
I should leak an address from LIBC to bypass this &%*#$ :shit:!

If I can make some of the `urls` (that is `char*`) point to one of the records
of GOT, I can then use `list` to print that address (that is a specific
address of LIBC).

Now I have all the puzzle pieces. Lets put them together.

### Exploit Time  
I used `add` three time at the first step and `remove` two times at the second
step for smaller exploit code.

I think there are enough comments on the code:  
[exploit.py](./exploit.py)

### Flag  
I got the bash. there was a `flag.txt` file. cat it!  
And this is the flag:  
```  
nactf{d0nt_us3_4ft3r_fr33_zsouEFF4bfCI5eew}  
```

Original writeup (https://github.com/ternary-bits/CTF-
Challenges/blob/master/pwn/2020-nactf-cttt/WRITEUP.md).