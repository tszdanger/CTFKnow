**Description**

> Fill the grid with L's but avoid the marked spot for the W  
>  
> `nc misc.chal.csaw.io 9000`  
>  
> The origin is at (0,0) on the top left

**Files provided**

- [`description.pdf`](https://github.com/Aurel300/empirectf/blob/master/writeups/2018-09-14-CSAW-CTF-Quals/files/take-an-l-description.pdf)

**Solution**

The challenge is a pretty simple algorithmic question - how to fill a `2^n x
^n` board with 1 hole with L-shaped tiles (each taking 3 squares). On
connection the server always gives us a `n = 6`, i.e. a `64 x 64` board, but
the fact that it is a power of two is significant, since this tiling works
easily for any power of two board. Let's consider first how to tile boards
with the hole in the top-left corner:

   n = 0, board size: 1 x 1  
  
   O  
  
   n = 1, board size: 2 x 2  
   O ║  
   ══╝  
  
   n = 2, board size: 4 x 4  
   O ║ ══╗  
   ══╝ ║ ║  
   ║ ══╝ ║  
   ╚══ ══╝  
  
   n = 4, board size: 8 x 8  
   O ║ ══╗ ╔══ ══╗  
   ══╝ ║ ║ ║ ══╗ ║  
   ║ ══╝ ║ ══╗ ║ ║  
   ╚══ ══╝ ║ ║ ══╝  
   ╔══ ║ ══╝ ║ ══╗  
   ║ ║ ╚══ ══╝ ║ ║  
   ║ ╚══ ║ ║ ══╝ ║  
   ╚══ ══╝ ╚══ ══╝  
  
   ...

Notice that in each step, the top-left quarter is tiled the same as the step
before. Furthermore, look at `n = 4` if we take out the middle tile:

   (     ) ╔══ ══╗  
   ( n-1 ) ║ ══╗ ║  
   (     ) ══╗ ║ ║  
   (     )   ║ ══╝  
   ╔══ ║     ║ ══╗  
   ║ ║ ╚══ ══╝ ║ ║  
   ║ ╚══ ║ ║ ══╝ ║  
   ╚══ ══╝ ╚══ ══╝

All the quarters are actually tiled the same way, as `n - 1`, just turned
differently. We just need to place a tile in the middle to connect them. In
fact, it doesn't matter where the hole is in the board. We just need to
separate the board into quarters and tile each quarter independently.

([Full Haxe script
here](https://github.com/Aurel300/empirectf/blob/master/writeups/2018-09-14-CSAW-
CTF-Quals/scripts/TakeL.hx))

`flag{m@n_that_was_sup3r_hard_i_sh0uld_have_just_taken_the_L}`

Original writeup
(https://github.com/Aurel300/empirectf/blob/master/writeups/2018-09-14-CSAW-
CTF-Quals/README.md#200-misc--take-an-l).