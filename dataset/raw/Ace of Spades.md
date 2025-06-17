## Memory Corruption - Ace of Spades

What we have is a card game. Fooling around with it (under `valgrind` - why  
not?) reveals the following:  
* There is a shuffled deck of 52 cards.  
* We can draw as many cards as we please (even all 52).  
* We can discard drawn cards in FIFO manner.  
* When we are happy with the hand, we can "play" it - this will compute the  
score based on the following table:  
 * Jack: 300  
 * Queen: 600  
 * King: 900  
 * Ace: 1200  
 * Ace of Spades: x2  
* Only some of the cards in the hand are taken into account.  
* After the hand is played, all the cards are shuffled into the deck and we can  
draw again.  
* So the theoretical maximum of points we can achieve is `(1200 * 3 + 900) * 2 =  
9000`. Memez FTW!  
* Winning 1000 or more points results in a prize. We can keep it or we can  
replace it with anything else.  
* Stuff like drawing more than 52 cards and discarding from the empty hand seems  
to be handled correctly. No easy way to crash the program.  
* The only valgrind warning is:

```  
==11086== Source and destination overlap in strcpy(0x10b260, 0x10b261)  
==11086==    at 0x4833537: strcpy (in vgpreload_memcheck-x86-linux.so)  
==11086==    by 0x108D92: ??? (in ace_of_spades)  
==11086==    by 0x109236: ??? (in ace_of_spades)  
==11086==    by 0x109354: main (in ace_of_spades)  
```

Well, this is for sure a lousy non-portable coding practice, but on our  
particular platform this seems to work fine. Moving on.

Reversing the code in IDA raises more eyebrows than I care to count. Spoiler:  
most of them ended up being useless at the end:

* The function that calculates points explicitly handles multiple Aces of  
Spades:

```  
.text:00000DEB                 cmp     al, 28h ; '('  
.text:00000DED                 jnz     short is_not_aos  
.text:00000DEF is_aos:  
.text:00000DEF                 add     [ebp+aos_count], 1  
.text:00000DF3                 jmp     short next_index

...

.text:00000E48 double_points:  
.text:00000E48                 shl     [ebp+points], 1  
.text:00000E4B                 add     [ebp+index], 1  
.text:00000E4F loop_end:  
.text:00000E4F                 mov     eax, [ebp+index]  
.text:00000E52                 cmp     eax, [ebp+aos_count]  
.text:00000E55                 jb      short double_points  
```

A doorway into exceeding the maximum "fair" amount of points?

* The function that shows the hand does not honor the number of cards and  
instead waits for the trailing `\0`:

```  
.text:0000115E                 movzx   eax, byte ptr [eax]  
.text:00001161                 test    al, al  
.text:00001163                 jnz     short loop_body  
```

An opportunity for an arbitrary memory read?

* RNG seed is not discarded, but rather stored into a global variable, which  
lies right after deck, hand and discard pile. Can we read it somehow?

```  
.bss:00003220 deck            db 35h dup(?)

...

.bss:00003260 hand            db 35h dup(?)

...

.bss:000032A0 discard_pile    db 35h dup(?)

...

.bss:000032E0 seed            dd ?  
```

* Prize selection does not handle 11000 points and more correctly. Winning 16000  
points and keeping the prize allows us to read memory pointed to by `rbp`.  
Replacing the prize allows us to write to said memory:

```  
.text:00000FDE                 mov     eax, [ebp+points]  
.text:00000FE1                 mov     edx, 10624DD3h  
.text:00000FE6                 mul     edx  
.text:00000FE8                 mov     eax, edx  
.text:00000FEA                 shr     eax, 6  
.text:00000FED                 mov     [ebp+prize_index], eax  
.text:00000FF0                 mov     eax, [ebp+prize_index]  
.text:00000FF3                 mov     eax, [ebp+eax*4+prizes]  
.text:00000FF7                 sub     esp, 8  
.text:00000FFA                 push    eax  
.text:00000FFB                 lea     eax, (aYourPrizeS - 2F98h)[ebx] ; "Your
prize: %s\n"  
.text:00001001                 push    eax             ; format  
.text:00001002                 call    _printf  
```

But how do we win that much?!

* Winning regular prizes and changing them to `'x' * 0x20` allows us to  
overwrite the trailing '\0' and see the next prize:

```  
.text:00001087 change:  
.text:00001087                 mov     eax, [ebp+prize_index]  
.text:0000108A                 mov     eax, [ebp+eax*4+prizes]  
.text:0000108E                 sub     esp, 4  
.text:00001091                 push    20h ; ' '       ; nbytes  
.text:00001093                 push    eax             ; buf  
.text:00001094                 push    0               ; fd  
.text:00001096                 call    _read  
```

Any possibility to read something useful here?

* Familiar `strcpy` issue:

```  
.text:00000D7D                 lea     eax, (hand+1 - 2F98h)[ebx]  
.text:00000D83                 sub     esp, 8  
.text:00000D86                 push    eax             ; src  
.text:00000D87                 lea     eax, (hand - 2F98h)[ebx]  
.text:00000D8D                 push    eax             ; dest  
.text:00000D8E                 call    _strcpy  
```

Uh huh. I would NACK that in a code review, but this is CTF.

* Only the first 5 cards count towards the score, even if we play an empty hand:

```  
.text:00000E39 loop_header:  
.text:00000E39                 cmp     [ebp+index], 4  
.text:00000E3D                 jbe     short process_card  
```

Can we somehow put Aces of Spades into empty slots?

* Function that asks for a choice reads 4 characters and calls `atoi()` without  
any checking - can we read something useful this way?

* When reading the seed from `/dev/urandom` the code doesn't check the return  
value of `read()`: can we somehow overwhelm the system RNG and make `read()`  
return just 1 byte, making the seed more predictable?

* Why are we given the `xinetd` file? Is the environment the server runs in  
somehow useful?

Two pieces of the puzzle come together: duplicating Aces of Spades will make
it  
possible to exceed the maximum score and gain the ability to read and write to  
the stack. The missing piece is: how to duplicate the cards?

All the issues related to predicting the RNG, even if they would somehow work,  
are useless: we need to actively mess with the deck, not learn stuff about it.

After hours and hours of reading the assembly and experimenting with ideas  
above, I come back to `strcpy` and wrote the following (by this time I've  
developed a bunch of `pyexpect`-based helpers to drive the game):

```  
def strcpy_problem(p):  
   for _ in range(52):  
       draw(p)  
   h = print_hand(p)  
   for _ in range(52):  
       discard(p)  
       h1 = print_hand(p)  
       if h[1:] != h1:  
           print('^^^ BUG ^^^')  
       h = h1  
   fold(p)  
```

Ouch! When working with certain string lengths (29, 44, 45), `strcpy` with  
overlapping buffers duplicates certain characters. So, let's do the following  
in a loop:

* Draw 52 cards.  
* See if some combination of 5 cards gives us the desired score.  
 * Discard until those 5 cards become the first ones and play the hand.  
   * If in rare cases when `strcpy` bug messes with that, tough luck - fold  
and try again.  
* See if `strcpy` bug lets us replace a worthless card with a `Jack` or  
something better.  
 * Discard until the bug is triggered, fold.  
* Fold.

Here are the scores that we want to achieve, in order:

* Some "legal" score in range 1000-10999 in order to change the prize to the  
name of the file containing the flag - `/home/ace_of_spades/flag\0`. This  
actually required some guesswork (`flag` vs `flag.txt` and `/` vs `.` vs  
`$HOME`) - `xinetd` file allowed to learn the name of the home directory.

* 16000-16999 in order to print the prize, which is the stack contents.  
`prize[4:8]` contains the return address, which is always `main+147` -  
so long, ASLR!

* 16000-16999 again in order to change the prize and overwrite the stack.

Where can we return? We have a bunch of libc functions in PLT, but, alas, no  
sweet `exec`. We have to `open` the flag anyway. Then we need to `read` it.

The first step is easy - overwrite the stack with:

* `0` (old `ebp`)  
* `open` address  
* `0` (`open` return address)  
* address of path to `flag`  
* `open` flags

and leave the game in order to pass control to `open`.

When `open` returns, the flag fd will be in `eax` and top of the stack is
going  
to be:

* address of path to `flag`  
* flag length

Can we do anything useful with that? Turns out we can. Let's find all the
`read`  
calls. One of them is in the very beginning and is responsible for reading  
`/dev/urandom`. Let's try jumping there:

* `0` (old `ebp`)  
* `open` address  
* `main + 0x46`:  
```  
.text:00001308                 push    eax             ; fd  
.text:00001309                 call    _read  
```  
* address of path to `flag`  
* `64` which is a valid `open` flag and at the same time a reasonable flag  
length

When we are at the `read` call site, the stack looks like this:

* flag fd  
* address of path to `flag`  
* `64`

The flag will be placed into the prize slot, which used to contain the path.  
After that the game will be restarted, so we just play again, win the prize at  
this slot and get the flag!  

Original writeup
(https://github.com/mephi42/ctf/tree/master/2019.09.28-PwnThyBytes_CTF_2019/memory_corruption-
Ace_of_Spades).