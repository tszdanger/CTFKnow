<h1>endless_wait</h1>  
Points: 473

<h1>Category</h1>  
Reverse Engineering

<h1>Problem</h1>  
<h3>Can you wait for eternity? Author:-n1kolai</h3>

<h1>Solution</h1>

Original binary:  
Patched binary:

I found two things that need to be patched in this binary:  
  
- SIGALRM (https://linuxhint.com/sigalarm_alarm_c_language/)   
  
- Anti-Debug linux technique ptrace (https://stackoverflow.com/questions/33646089/using-ptrace-to-detect-debugger)   

![Alt text](https://i.imgur.com/d3OzP6S.png "Title")

![Alt text](https://i.imgur.com/xiEwGLx.png "Title")

After patching(nop slides) our binary looks like:  

![Alt text](https://i.imgur.com/58ZdiS8.png "Title")

![Alt text](https://i.imgur.com/mS11m5o.png "Title")

Now we excluded one function, so we know that second one is valid for our
flag, let's chek  

I was very interested how stack looks after all  

![Alt text](https://i.imgur.com/CHzRfP7.png "Title")

I put the breakpoint a bit further and read what the stack looks like

![Alt text](https://i.imgur.com/ybBsOO5.png "Title")

I read the following string:  
**bqz0wm0qctdn2gbrdmoazosbtsc
{jmpgzadbtjc1amenzngbcnceam_gn1dzsab_ccnhm0nntlx_ackebehmyvn_lzhabencrhmevn}azqazwsxedc**  

After analyzing function strcmp would give us message is our input correct or
not, but generating flag was independent of that  

```C  
   char flag[48];  
   const char* runtimeArray =
"bqz0wm0qctdn2gbrdmoazosbtsc{jmpgzadbtjc1amenzngbcnceam_gn1dzsab_ccnhm0nntlx_ackebehmyvn_lzhabencrhmevn}azqazwsxedc";  
   for (int i = 0; i < 0x23; i++)  
   {  
       flag[i] = *(char*)(runtimeArray + (i * 3));  
   }  
   puts(flag);  
```

Flag: **b00t2root{pat1ence_1s_n0t_key_here}**

Original writeup (https://github.com/TheEasyPeasy/CTF-
writeups/tree/main/boot2root/reverse%20engineering/endless_wait).