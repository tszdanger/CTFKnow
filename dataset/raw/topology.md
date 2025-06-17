# topology (rev)  
Writeup by: [xlr8or](https://ctftime.org/team/235001)

As part of this challenge we get an x86 ELF binary.  
Let's see what `main` does:  
```c  
 char *__s;  
 int iVar1;  
 undefined8 uVar2;  
 size_t sVar3;  
  
 if (argc < 2) {  
   __printf_chk(1,"Usage: %s FLAG\n",*argv);  
   uVar2 = 1;  
 }  
 else {  
   iVar1 = setup_network();  
   if (head == iVar1) {  
     __s = argv[1];  
     sVar3 = strlen(__s);  
     network_main(__s,(int)sVar3 + 1);  
   }  
   else {  
     handle_message();  
   }  
   if (tail != iVar1) {  
     wait((void *)0x0);  
   }  
   destroy_network(iVar1);  
   uVar2 = 0;  
 }  
 return uVar2;  
```

Here we see that this is some sort of network setup. And then some messages
will be passed around in the network.  
`setup_network` is going to fork the process, such that we have 99 *worker*
processes (not including the main process itself).  
I didn't invest much time in how the network works, however I assumes that:  
1. The specific details won't matter to the challenge (or at least I should have a better understanding of the full binary first)  
2. The network is a linked list of nodes, and each node passes messages to its neighbours

So we see, that the first node in the network (the main process) is going to
be the `head`, and it will execute the `network_main` function, which receives
the user input as argument.  
All the other processes will execute the `handle_message` function, that takes
no parameters, this is why I called them the *worker* processes.

Let's see what the main node is responsible for:  
```c  
 send_msg(0x1337cafe,0xffffffff,0,0);  
 iVar3 = recv_msg();  
 if ((iVar3 == 0) && (*(int *)(prev + 8) == 0x1337cafe)) {  
```

After doing some stack setup, and flag copying, we see the first network
operations.  
This essentially acts as a ping of the neighbour of the first node, and we
continue on if the ping is replied to by the neighbour.

Now let's inspect what happens in the rest of the method:  
```c  
   pcVar6 = local_98; // the flag the user enters  
   bVar2 = false;  
   do {  
     iVar5 = 1;  
     iVar3 = 0;  
     do {  
       send_msg(0x1337f146,iVar5,pcVar6,8);  
       iVar4 = recv_msg();  
       if ((iVar4 != 0) || (*(int *)(prev + 8) != 0x1337beef)) {  
         send_msg(0x1337dead,0xffffffff,0,0);  
         goto LAB_001e5cf1;  
       }  
       iVar4 = strcmp((char *)(prev + 0x10),"OK");  
       iVar3 = iVar3 + (uint)(iVar4 == 0);  
       iVar5 = iVar5 + 1;  
     } while (iVar5 != 100);  
     bVar1 = true;  
     if (4 < iVar3) {  
       bVar1 = bVar2;  
     }  
     putc(0x2e,stdout);  
     fflush(stdout);  
     pcVar6 = pcVar6 + 8;  
     bVar2 = bVar1;  
   } while (local_48 != pcVar6);  
```

The outer loop is going to go over the user input in 8-byte blocks, and keep
track of the results of the inner loop.  
Meanwhile the inner loop is going to send the current 8-byte block to each of
the *worker* processes.  
In `iVar3` the number of `OK` responses will be tracked.

The success of the checks depends on the `bVar1` variable:  
```c  
if (bVar1) {  
 puts("\nWrong...");  
} else {  
 puts("\nCorrect!");  
}  
```

In the code block before we see that `bVar1` only becomes `false` if we have
more than 4 `OK` responses from the *worker* processes for the current 8-byte
block.

Therefore our goal can be defined as follows:  
Construct the flag such that each 8-byte block generates more than 4 `OK`
responses from the *worker* processes.

Let's see how the worker process validates the blocks in `handle_message`:  
```c  
   if (iVar1 == 0x1337f146) {  
     iVar1 = (*(code *)f[whoami + -1])(prev + 0x10);  
     if (iVar1 == 0) {  
       send_msg(0x1337beef,0,"OK",3);  
     }  
     else {  
       send_msg(0x1337beef,0,"NG",3);  
     }  
   }  
```

First we check for the op code to differentiate this request from the ping
request.  
Then we call a function based on the ID of the current *worker* process with
the current 8-byte block.  
Then based on the function result we return `OK` (0 value) or `NG` (1 value).

There's a function for each of the 99 *worker* processes, but all of them have
the same structure:  
they do some arithmetic operations on the 8-byte block and compare it to some
value.  
All functions have 10 separate cases (and operations) for the 10 different
8-byte blocks of the flag.

Since each case performs multiple complex operations it is not efficient to
try to solve this manually.  
Therefore I have decided to automate this task using `angr`.  
The general idea of the solution is as follows:  
1. Recover the flag in 8-byte blocks  
2. Use `angr` to get a candidate for the current 8-byte block for all 99 *worker* processes  
3. Rank the results by frequency, and pick the most frequent option as the flag value.

The implementation details can be seen in `solve.py`. As a side note, the
performance could be improved by stopping as soon as we have more than 4 of
the same result from the functions, however I wanted to see all other
solutions as well just in case.  

Original writeup
(https://github.com/sbencoding/zer0pts_ctf_2023_writeups/tree/main/rev/topology).