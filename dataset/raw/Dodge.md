# Dodge Writeup

### Defenit CTF 2020 - Misc 906 - 3 solves

> Dodge it! `nc dodge.ctf.defenit.kr 1357`

#### Hints

- This dodge is multi-tasking-dodge(4 tasks), get more than 120 points!  
- You will get your score after the game.  
- You can change the focused game with q, e and moving direction of the player with w, a, s, d.  
Focused game is marked with `*` next to the number.

#### Observation

To start the game, solve 3 byte PoW. Four dodge games start with following
below rules.

1. Map  
   - Map with width 40, height 20.  
2. Player(Marked as `p` on Map)  
   - Player position randomly initialized with random velocity.  
   - Player cannot move diagonally. Only `wasd`.  
   - Player can only move one block at a time.  
   - If no input, player keeps its velocity.  
3. Bullet(Marked as `*` on Map)  
   - Bullets are spawned every 3 rounds starting with 2nd round.  
   - Bullets can move diagonally.  
   - Bullets can be overlapped, even when they are first spawned.  
   - Bullets have constant magnitude of speed.  
4. Collision  
   - If player/bullet collides with wall(Marked as `#`) will bounce with following [elastic collision](https://en.wikipedia.org/wiki/Elastic_collision).  
   - Each of bullets do not collide together. They just overlap.  
   - If player collides with bullet, game ends.

Each rounds give single point. If I get more than 120 points(pass more than
120 rounds), I win and get flag.

#### Exploit

Let me implement heuristic algorithm to dodge. The key point is that, **most
of bullets can be deterministically tracked**.

First two rounds are free. No bullet is spawned. New bullet is added every 3
rounds, starting from third round(`i = 1`). Use these rounds to track player
position and velocity. I can track and verify position and velocity of bullet
by the following algorithm.

1. Round `3 * i`: New bullet is spawned.  
   - If new bullet is not detected, give up tracking, meaning that overlapping occured.  
   - If not, store new bullet position(`y1, x1`).  
2. Round `3 * i + 1`: New bullet moves.  
   - If new bullet is not detected, give up tracking, meaning that overlapping occured.  
   - If not, store new bullet position(`y2, x2`).  
3. Now estimate new bullet's position and velocity.  
   - Past two positions known, so velocity(`y2 - y1`, `x2 - x1`) known.  
   - Since velocity known, future position of new bullet can be estimated.  
4. Round `3 * i + 2`: Check estimated result is true.  
   - Let new bullet position be (`y3, x3`).  
   - Estimated position be (`y2 + (y2 - y1)`, `x2 + (x2 - x1)`)  
   - If estimated result is false, It means that at `3 * i + 1`th round, bounce occurred during previous round. Therefore position/velocity was wrong. Recalculate postition/velocity by using position(`y3, x3`) and (`y2, x2`), so velocity(`y3 - y2`, `x3 - x2`)

By iterating above algorithm, I could mostly track all position the bullets.
After knowing position and velocity of bullets, future positions are
deteministic. Using determined future bullet positions, I could send control
commands to avoid bullets. I easily bypassed over 120 rounds, and got until
more than 150. Example map while dodging 148th round:

```  
##########################################  
#                                        #  
#     *                       **         #  
#  *                             *       #  
#                *      *                #  
#  *                                *    #  
#    *        *                          #  
#                         *              #  
#  *                      *              #  
#              *           *             #  
#      *                                 #  
#                             * **   *   #  
# *     *  *           *                 #  
#                 *    *       *         #  
#             *                   *  *   #  
#                 *p     *       *  *    #  
#    *            *                      #  
#       *** *                            #  
#          *  *                          #  
#    *       *                          *#  
#      *   *                             #  
##########################################  
```

I get flag:

```  
Defenit{dodg3_d0dg3_d0dge_d0dge_dodge}  
```

Exploit code: [solve.py](solve.py)

#### Other interesting solution

`for i in {1..5000}; do {python a.py >/dev/null &} ; done;`. Wait until you
get very lucky :P.

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2020/Defenit/Dodge).