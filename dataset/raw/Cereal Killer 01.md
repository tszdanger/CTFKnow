## Cereal Killer 01

### Description

> Points: 50  
>  
> Created by: `TheZeal0t`

How well do you know your DEADFACE hackers? Test your trivia knowledge of our
beloved friends at our favorite hactivist collective! We’ll start with
bumpyhassan. Even though he grates on TheZeal0t a bit, we find him to be
absolutely ADORKABLE!!!

Choose one of the binaries below to test your BH trivia knowlege.

Enter the flag in the format: flag{Ch33ri0z_R_his_FAV}.

[Download
file](https://gr007.tech/writeups/2023/deadface/rev/cereal_killer_1/cereal)

### Solution

When the binary is run, it asks for bumpyhassan's favorite breakfast cereal.

```sh  
deadface/rev/cereal1 on  master [?] via ? v3.11.5  
❯ ./cereal  
Bumpyhassan loves Halloween, so naturally, he LOVES SPOOKY CEREALS!  
He also happens to be a fan of horror movies from the 1970's to the 1990's.  
What is bumpyhassan's favorite breakfast cereal? adsf  
Sorry, that is not bumpyhassan's favorite cereal. :(  
```

The following code (after some cleanup) snippets are the interesting parts
from looking at it in ghidra.

```c  
 p_flag = "I&_9a%mx_tRmE4D3DmYw_9fbo6rd_aFcRbE,D.D>Y[!]!\'!q";  
 puts("Bumpyhassan loves Halloween, so naturally, he LOVES SPOOKY CEREALS!");  
 puts("He also happens to be a fan of horror movies from the 1970\'s to the
1990\'s.");  
 printf("What is bumpyhassan\'s favorite breakfast cereal? ");  
 fgets(bf,0xfff,_stdin);  
 for (p_bf = bf; *p_bf != '\0'; p_bf = p_bf + 1) {  
   *p_bf = *p_bf + '\a';  
 }  
 *p_bf = '\0';  
 check = memcmp(&DAT_00012039,bf,14);  
 if (check == 0) {  
   puts("You are correct!");  
   i = flag;  
   for (; *p_flag != '\0'; p_flag = p_flag + 2) {  
     *i = *p_flag;  
     i = i + 1;  
   }  
   *i = '\0';  
   printf("flag{%s}\n",flag);  
 }  
 else {  
   puts("Sorry, that is not bumpyhassan\'s favorite cereal. :( ");  
 }  
```

It can be easily seen that the flag is built on the stack and printed after
the password check is done and our input does not get in the way of our flag
being decrypted. That is, we can jump to the code block inside the `if` check
and get the flag decrypted and stored in the stack and even print it. We can
also zero out the `eax` register inside the debugger after the `memcmp`
function is called to have a correct execution and not get any segfault that
might arise by directly jumping to the address or if the address is hard to
find. I will use this technique whenever I can because it makes reversing with
a particular goal in mind easier and it works most of the time without any
hiss.

```sh  
[ Legend: Modified register | Code | Heap | Stack | String ]  
──────────────────────────────────────────────────────────────────────────────────────────────────
registers ────  
$eax   : 0xffffffff  
$ebx   : 0x56558fc4  →  <_GLOBAL_OFFSET_TABLE_+0> int3  
$ecx   : 0x707c794d ("My|p"?)  
$edx   : 0xffffbd5a  →  0x00000000  
$esp   : 0xffffbcd0  →  0xffffbd58  →  0x00000000  
$ebp   : 0xffffcd58  →  0x00000000  
$esi   : 0xffffce2c  →  0xffffd044  →  "XDG_GREETER_DATA_DIR=/var/lib/lightdm-
data/groot"  
$edi   : 0xf7ffcb80  →  0x00000000  
$eip   : 0x565562e9  →  <main+268> test eax, eax  
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow
resume virtualx86 identification]  
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63  
──────────────────────────────────────────────────────────────────────────────────────────────────────
stack ────  
0xffffbcd0│+0x0000: 0xffffbd58  →  0x00000000    ← $esp  
0xffffbcd4│+0x0004: 0x00000000  
0xffffbcd8│+0x0008: 0x00000000  
0xffffbcdc│+0x000c: 0x56557008  →
"I&_9a%mx_tRmE4D3DmYw_9fbo6rd_aFcRbE,D.D>Y[!]!'!q"  
0xffffbce0│+0x0010: 0x56557039  →   dec ebp  
0xffffbce4│+0x0014: 0x00000000  
0xffffbce8│+0x0018: 0x00000000  
0xffffbcec│+0x001c: 0x00000000  
────────────────────────────────────────────────────────────────────────────────────────────────
code:x86:32 ────  
  0x565562db <main+254>       push   DWORD PTR [ebp-0x1078]  
  0x565562e1 <main+260>       call   0x56556070 <memcmp@plt>  
  0x565562e6 <main+265>       add    esp, 0x10  
●→ 0x565562e9 <main+268>       test   eax, eax  
  0x565562eb <main+270>       jne    0x56556369 <main+396>  
  0x565562ed <main+272>       sub    esp, 0xc  
  0x565562f0 <main+275>       lea    eax, [ebx-0x1eba]  
  0x565562f6 <main+281>       push   eax  
  0x565562f7 <main+282>       call   0x56556090 <puts@plt>  
────────────────────────────────────────────────────────────────────────────────────────────────────
threads ────  
[#0] Id 1, Name: "cereal", stopped 0x565562e9 in main (), reason: BREAKPOINT  
──────────────────────────────────────────────────────────────────────────────────────────────────────
trace ────  
[#0] 0x565562e9 → main()  
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────  
gef➤  set $eax=0  
gef➤  c  
Continuing.  
You are correct!  
flag{I_am_REDDY_for_FREDDY!!!}  
[Inferior 1 (process 8224) exited normally]  
```

flag: `flag{I_am_REDDY_for_FREDDY!!!}`

> Note: Here's the
> [code](https://gr007.tech/writeups/2023/deadface/rev/cereal_killer_1/sol.py)
> for reversing and getting the favourite cereal name correct.  

Original writeup (https://gr007.tech/writeups/2023/deadface/index.html#cereal-
killer-01).