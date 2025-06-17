TUCTF 2018: Professor Plum's Ravenous Researcher  
=============================

## Description

Professor Plum is hiring! Maybe you can get the job!

http://18.223.185.148/

## Solution

Professor Plum wants us to find Mr. Boddy.

There is a page in which we can submit an input. (to find Boddy)  
http://18.223.185.148/search.php

Giving random inputs, the site return:  
`Nice try but he's not there. Maybe try somewhere else in the mansion?`

We have a cookie with 2 fields: `Found_Boddy` and `Location`. In which
Found_Boddy is set to 0.

Knowing that this challenge is a cluedo reference, the location of where Boddy
is probably on of the 10 rooms of the game.

The rooms are: Kitchen, Ballroom, Conservatory, Dining Room, Cellar, Billiard
Room, Library, Lounge, Hall, Study.

Then we tried all those room with the cookie parameter `Found_Boddy` set to 1.

Eventually we found Boddy in the Billiard Room!

`TUCTF{1_4ccu53_pr0f3550r_plum_w17h_7h3_c00k13_1n_7h3_b1ll14rd_r00m}`

Original writeup (https://github.com/ctf-
epfl/writeups/blob/master/tuctf18/Professor%20Plum's%20Ravenous%20Researcher/README.md).