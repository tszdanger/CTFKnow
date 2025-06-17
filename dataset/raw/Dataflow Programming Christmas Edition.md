# __X-MAS CTF 2018__  
## _Dataflow Programming Christmas Edition_

## Information  
**Category:** | **Points:** | **Writeup Author**  
--- | --- | ---  
Reverse | 454 | MiKHalyCH

**Description:**

> Santa's MechaGnomes have invented some new DataFlow language that they code
> the factory robots' instructions. You found a weird string checker, you need
> to interpret the code in order to recover the string! The flag obtained from
> the challenge must be wrapped up like: X-MAS{flag}  
>  
>[chall](src/chall.zip)  
>  
>Authors: Gabies + littlewho

## Solution  
We have a good [manual](src/ChristmasFlow_programming_language_manual.pdf) of
programming language and the [code](src/code.txt).

It was to hard to write a good interpreter for this language (yeah, I spend a
lot of time for it) because of treads (a.k.a. _iteration levels_).

_Get ready for the real_ __EYESOLUTION__!

I noticed that we can split the full code by `EQU 158L -` into blocks like
this:  
```  
17 CLN 19L 27L  
18 SND_2 19R -  
19 EQU 20R -  
20 BRB 26L 30L

21 SND_10 22L -  
22 CLN 24L 25R  
23 SND_1 24R -  
24 ADD 25L -  
25 MUL 26R -  
26 EQU 158L -  
```  
and  
```  
90 CLN 92L 98L  
91 SND_9 92R -  
92 EQU 93R -  
93 BRB 97L 101L

94 SND_204 96L -  
95 SND_2 96R -  
96 SHR 97R -  
97 EQU 158L -  
```

Each block contains two parts:

* The first block compairs some constant with some number from [0, 18] (from 0-1 lines of code). Looks like an index of flag character.

* The second block calculates some integer with differend arithmetic and bitwise operations. All the values are ASCII characters.

The examples above would calculate `flag[2] = chr((10 + 1) * 10) = 'n'` and
`flag[9] = chr(204 >> 2) = '3'`.

Now we need to calculate all characters and collect the flag!

Original writeup (https://github.com/VoidHack/write-
ups/tree/master/X-MAS%20CTF%202018/reverse/Dataflow%20Programming%20Christmas%20Edition).