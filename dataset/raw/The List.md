### THE LIST

> Points: 452  
>  
> Tags: Binary Exploitation, Buffer Overflow  
>  
> Author: @M_alpha#3534  
>  
> Descrption: We need you to compile a list of users for the event. Here's a
> program you can use to help.  
>

### 4nalysis  
*Static Analysis*  
- As usual lets check the file type and the backend codingstrcspn  
- The file is a `dynamically linked` and `not stripped` file written in `c`  
- Check the for the `imports` and `strings` in the binary. Well I have to admit `strcspn` looked new and intresting  
- Looking it up online this is a function is `C` that : assume strscpn(str1, str2). If str2 is found in str1 this function will  
return the number letters before `str2` get it :)  
- `checksec` show us `no pie` therefore the function addresses are not randomized.  
- No other new or interesting import lets dive in to the favourite part using the debugger.

*Dynamic Analysis*

- Load you favourite debugger and lets get started. This will be an easy binary to anaylse   
since there binary is `not stripped` and its dynamically linked.  
- There are a couple of functions in the binary 

**give_flag**

- This is a function that gives the flag therefore we should find a way to call it.

**Main**  
- This is the entry function and as seen we allocated `0x200` space for local   
variable and `memset` is used to fill up the buffer with `0`'s  
- It then prompts us for our name and uses `strcspn` to find `\n` in the string  
which will be replaced by a null byte. This happens because `fgets` that is
used to  
read in input appends a new line at the end.  
- It then presents us with a menu where we can add, delete and change names and exit.

**Menu**

- This is used to print the menu.

**Add User**

- This is used to add a user on the stack. Our input ends up on the `0x200` space that   
was allocated earlier.  
- This function also does some checks before adding a user of the stack.  
```  
1. It adds each users at an offset of 32 bytes. This is done using the opcode `shl rax, 0x5`  
2. Before adding a user it check if the region in memory starts with a null byte.  
3. There are no limits we can add upto as many users as we want. Can we use this privillege  
and cause a buffer overflow. Well we'll see later.  
4. `strcspn` is also used to eliminate a `\n` character and `fgets` is used to get our input  
but it only allows `0x20` characters.  
```

**Print Users**

- This is used to print users from the buffer allocated earlier.  
- The maximum number of users that can be printed is `0xf`   
- It iterates through the offset of 32 byte from the buffer to find users.  
- If there is a null byte at the start of the buffer then is assumes there are no more users and exists.

**Delete User**  
- This is used to delete a user in that it replaces the buffer with null bytes.  
- It then calls a function `shift back` that is used to shift back a user into   
the previous buffer that was deleted.

**change_uname**  
- This alows us to change the user name of the user.  
- It takes an index and we can edit that buffer win our new user.  
- On amazing thing is that this function uses fgets to get our input but the max  
number of bytes is `0x50` which is diffrent from the usual `0x20` in the
add_user function.  
- Therefore this is where the vulnerability lies.

## Exploit

- We have to add users and fill the buffer so that we can edit a user and overflow to the   
control rip.  
- But there is a problem. `add_user` function checks for a `null` byte at the beginning of  
a buffer to add a user.  
- To mitigate this remember the first prompt. `Enter your name`. Filling this buffer with   
`0x20` bytes `strcspn` will replace the last buffer with a null byte and since
this region  
lies in the 32 byte offset our input will go here.  
- We can then edit the value at this region and since `edit` allows us to enter 0x50 bytes   
we can therefore overflow the saved pointer and call `give_flag` function.  
- Final exploit [exploit](exploit.py)

Original writeup (https://github.com/mutur4/CTF-
WRITEUPS-2021/blob/main/NahamCon%20CTF/Binary%20Exploitation/the_list/solution.md).