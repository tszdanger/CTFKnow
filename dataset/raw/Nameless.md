# Nameless

This task was part of the 'Reversing' category at the 2020 Hexion CTF (during
11-13 April 2020).  
It was solved by [or523](https://github.com/or523), in [The
Maccabees](https://ctftime.org/team/60231) team.

The challenge description:

```  
Strip my statically linked clothes off  
```

## The challenge

This is a super-easy reversing challenge.

We get 2 files:

1. Binary named `nameless`: `nameless: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=323839c17d33008400842a9743c7813e8fcb646b, stripped`.

2. 34-bytes binary `out.txt`: 

  ```  
  00000000  16 ec 23 c3 06 01 b1 f0  61 4a f4 81 35 16 ef aa
|..#.....aJ..5...|  
  00000010  5b 3f 38 51 62 0f 21 13  64 e7 67 ee 41 7b 3a b9
|[?8Qb.!.d.g.A{:.|  
  00000020  ec b1                                             |..|  
  ```

The actual challenge is: this is a statically-linked binary (meaning: `libc`
and all other dependencies are statically-compiled into it), and it is
stripped from all symbols and debug information.  
The binary takes a file named `flag.txt`, "encrypts" it and outputs `out.txt`.
We need to reverse this process, and understand how to reverse it in order to
get the original `flag.txt` contents.

The reversing process itself is as follows:

Finding the `main` function is easy by searching for the string `out.txt` in
the binary. From there, the main challenge is to understand the identity of
each standard `libc` functions. Just by inspecting the parameters and
comparing the decompiled input to our own `libc`, we identified these
functions (the real confusing ones were `fgets`, `fputc` and `rand`).  
The main function ends up looking like this:

```c  
int main(void)  
{  
 time_t curr_time = time(NULL);  
 srand(curr_time);  
  
 int c = 0;  
 FILE * flag_file = fopen64("flag.txt", "r");  
 for ( FILE * out_file = fopen64("out.txt", "w"); ; fputc(c, out_file) )  
 {  
   char flag_char = fgetc(flag_file);  
   if ( flag_char == -1 )  
     break;  
   c = ((signed int)rand() % 0x666 + 1) ^ flag_char;  
 }

 fclose(flag_file);  
 fclose(out_file);  
 return 0;  
}  
```

This is a trivial process of "encrypting" flag (of course - this is not a real
encryption by any means...), and the only external input here is the current
time (`time(NULL)`) when this binary was ran.  
Because we know the flag starts with the bytes `hexctf`, we can just write a
simple C program which iterates all possible `time_t` values from the current
time backwards, checking if "decrypting" the first 6 bytes of `out.txt`
results in `hexctf`. The full C program that does it is attached
[here](solve.c).

After running it for a few seconds, we get a solution for `time=1586541672`,
which is `hexCTF{nam3s_ar3_h4rd_t0_r3m3mb3r}`.

~ **or523**

Original writeup (https://github.com/TheMaccabees/ctf-
writeups/blob/master/HexionCTF2020/Nameless/README.md).Check out the writeup on our website!

Original writeup
(https://n00bzunit3d.xyz/writeups/idekctf/crypto/nameless/readme/).