# AstroBot

## The task

`ID: astrobot        (474 points)        [PPC]`

AstroBot

We have found that HARPA is using a game for employee recruitment. It is based
on the old AstroBlast
[https://youtu.be/rn3RPIIC9gM?t=26](https://youtu.be/rn3RPIIC9gM?t=26).

Your mission is to automate a solution (bot) to dodge obstacles and capture
asteroids (represented by asterisks). Hold on for **137 seconds** and you're
hired!

Instructions:

* Use the arrow keys to change the spaceship direction.  
* Use the spacebar to reverse the spaceship direction.  
* Press "q" to exit at any moment.  
* When the game is over, you can close the game with "q" or "spacebar".  
* The screen shows the spaceship position and the number of captured asteroids.

For latency reasons, we recommend you to use a box on DigitalOcean:

**Servers:**

_**New York 3:**_

ssh [email protected] -p2222

eik7avou3yoo9Ohtai4a

_**Amsterdam 3:**_

ssh [email protected] -p2222

eik7avou3yoo9Ohtai4a

## Related news

2019-11-08 22:45:38  | all        | AstroBot is being fixed, wait pls

2019-11-08 23:04:12  | all        | AstroBot (NY3) should be ok now guys. We are working on AMS3

2019-11-08 23:13:05  | all        | AstroBot (AMS3) should be working now as well

2019-11-08 23:18:06  | all        | AstroBot (AMS3) new IP is 178.128.245.211. We will update the description too!

2019-11-09 13:22:08  | all        | [AstroBot] Alternative IP with better latency for brazilians teams: 200.136.213.39

## The server code

The server's source was published: https://github.com/epicleet/astrobot-game

## The solution

Observations:

* Obstacles and asterisks are at the same positions every time. There are cosmetic changes only.

* Reported time is inaccurate and unstable.

* Due to network delays, commands should be sent beforehand.

* The spaceship's position and overall progress in game may be used to send commands reliably. The position plus number of collected asterisks was convenient to use together with pseudo command to skip sending.

* Choosing other server with lower ping, the script became very repeatable.

* Sometimes commands should be sent between screens, not right after screen. Hence the command that sleeps 10 ms before sending actual command. The third asterisk required this trick: the spaceship was one cell off to left or to right from the asterisk.

* It is possible to use pwntools: `p = process("TERM=xterm ssh ...", shell = True, stdin = PTY)`. Maybe `TERM=xterm` is not the best choice. `TERM=xterm screen ssh ...` was used by mistake, but it provided pretty output with pseudographics.

* Left arrow is `\033OD` and right arrow is `\033OC`, not `\033[D` and `\033[C`. (`ncu.py` is a script to print keys seen under curses. It was copy-pasted from SGLE during the CTF.)

* There is a loop in the map: everything repeats after 6 asterisks. So it is possible to repeat commands and collect all other asterisks easily.

In general, the game is similar to [SGLE](https://github.com/pauloklaus/sgle-
game) from Pwn2Win 2018: player needs to dodge obstacles with fixed pattern.
But player needs to collect asterisks, it needs additional precision. With
SGLE, precision and repeatability was a problem. So this time, it was obvious
that it cannot be won without higher precision. So different approaches and
servers were tried, and the script became (almost) 100% reliable after all.

Testing reliability, commands to collect two asterisks were written. After
that, the third asterisk required a delay. Ok, it was interesting. Then there
were two options: either write logic to find path automatically, or continue
writing commands manually. There was a hope that there was a loop, because
obstacles have patterns so it was unlikely that there were no loop. So manual
approach was continued. And after 6 asterisks, the pattern repeated.

It was hard to meet the initial point, so 7th asterisk was chosen as the point
to loop commands. After a bit more work to catch the 7th asterisk, all
commands were obtained. They were copy-pasted and numbers of asterisks were
adjusted `+6`. And it just worked. So commands to collect 100+ asterisks were
populated and they worked too. This part was easy and very satisfying!

The flag: `CTF-BR{HARPA's_PPCs_4r3_cr4zy}`

## Files in repo

* `ab.py` is the player, sender of commands.

* `print_log.py` is printer for `ab.log` based on pyte library.

* `print_map.py` is like `print_log.py` but prints only the bottom line of screen to visualize trace (it was written after the CTF).

* `ab.log` is the full raw output from server for the winning run, so the full output may be produced.

* `output.txt` is the output from the scripts during the winning run, there are not all screens due to `tail`, but the output below should be enough.

* `ncu.py` is the script to test input under curses, derived from SGLE.

## The map

The screen with the first wave of obstacles:  
```  
┌[13:2]───[0.81/0]─────────────────────┐  
│                  W                   │  
│                                      │  
│                                      │  
│             T         U              │  
│                                      │  
│                                      │  
│        W                   T         │  
│                                      │  
│                                      │  
│U  W                             U   U│  
│                                      │  
│                                      │  
│ V                                    │  
└──────────────────────────────────────┘  
```

Pretty map of the loop without gaps:  
```  
...  
│                                      │  
│                  U           T       │  
│                    W       U         │  
│                      W   W           │  
│                        W             │  
│                                      │  
│      U           *                   │  
│        U       U                     │  
│          T   W                       │  
│            U                         │  
│                                      │  
│                  T           U       │  
│                    U       T         │  
│                      W   U           │  
│                        U             │  
│                                      │  
│      U           T                   │  
│        U       T                     │  
│          W   U                       │  
│            T                         │  
│                                      │  
...  
│                                      │  
│T                                    U│  
│   T   U                     W   W    │  
│U          U             T           W│  
│               T     T                │  
│W                 *                  W│  
│               T     W                │  
│W          U             T           W│  
│   T   W                     T   U    │  
│W                                    T│  
│                                      │  
...  
│                                      │  
│                           T U T W T  │  
│                                      │  
│                               W      │  
│                                      │  
│                               T      │  
│                                      │  
│                    W U W      U      │  
│                                      │  
│                    W          U      │  
│                                      │  
│                    T T T             │  
│                                      │  
│           * U T    T                 │  
│                                      │  
│           T        U T T             │  
│                                      │  
│           U T W                      │  
│                                      │  
│  W        T                          │  
│                                      │  
│  W        T W U                      │  
│                                      │  
│  W                                   │  
│                                      │  
│  U                                   │  
│                                      │  
│  T T U W                             │  
│                                      │  
...  
│                                      │  
│     U                                │  
│                                      │  
│           U                          │  
│                                      │  
│                 *                    │  
│                                      │  
│                       U              │  
│                                      │  
│                             W        │  
│                                      │  
│                    T              W  │  
│                                      │  
│              T              T        │  
│                                      │  
│        W              T              │  
│                                      │  
│  W              U                    │  
│                                      │  
│        T                             │  
│                                      │  
│              W                       │  
│                                      │  
│                    W                 │  
│                                      │  
│                          *           │  
│                                      │  
│                                W     │  
│                                      │  
...  
│                                      │  
│                  W                   │  
│                                      │  
│                                      │  
│             T         W              │  
│                                      │  
│                                      │  
│        T                   W         │  
│                                      │  
│                                      │  
│U  U              *              W   T│  
│                                      │  
│                                      │  
│        T                   W         │  
│                                      │  
│                                      │  
│             T         U              │  
│                                      │  
│                                      │  
│                  T                   │  
│                                      │  
│                                      │  
...  
│                                      │  
│                  W                   │  
│                                      │  
│                                      │  
│             T         U              │  
│                                      │  
│                                      │  
│        W                   T         │  
│                                      │  
│                                      │  
│U  W                             U   U│  
│                                      │  
...  
```

## The log

The log below is built from the last line of every screen (using
`print_map.py` with manual adjustments). There are duplicate screens with the
same title. Also obstacles repeat on 2 lines because the ship is faster. Also
the log is upside down, so it does not look pretty.

The log was for the game with ~45.7 ms ping. The delays between sending a
command and respective changes of direction are pretty visible.

The beginning before the first asterisk:  
```  
[13:19]──[0.00/0] │                  V                   │  
[13:18]──[0.02/0] │                 V                    │  
[13:17]──[0.04/0] │                V                     │  
[13:16]──[0.06/0] │               V                      │  
[13:15]──[0.08/0] │              V                       │  
[13:14]──[0.10/0] │             V                        │  
[13:13]──[0.12/0] │            V                         │  
[13:12]──[0.14/0] │           V                          │  
[13:11]──[0.16/0] │          V                           │  
[13:10]──[0.19/0] │         V                            │  
[13:9]───[0.21/0] │        V                             │  
[13:8]───[0.23/0] │       V                              │ 8/0 i  
[13:7]───[0.25/0] │      V                               │  
[13:6]───[0.27/0] │     V                                │  
[13:5]───[0.29/0] │    V                                 │  
[13:4]───[0.31/0] │   V                                  │  
[13:3]───[0.33/0] │  V                                   │  
[13:2]───[0.35/0] │ V                                    │  
[13:1]───[0.37/0] │V                                     │  
[13:1]───[0.39/0] │V                                     │  
[13:2]───[0.41/0] │ V                                    │  
[13:3]───[0.43/0] │  V                                   │  
[13:4]───[0.45/0] │   V                                  │  
[13:5]───[0.47/0] │    V                                 │  
[13:6]───[0.49/0] │     V                                │  
[13:7]───[0.51/0] │      V                               │  
[13:8]───[0.53/0] │       V                              │ 8/0 <  
[13:9]───[0.55/0] │        V                             │  
[13:10]──[0.57/0] │         V                            │  
[13:10]──[0.58/0] │         V                            │  
[13:9]───[0.60/0] │        V                             │  
[13:8]───[0.62/0] │       V                              │  
[13:7]───[0.64/0] │      V                               │  
[13:6]───[0.66/0] │     V                                │  
[13:5]───[0.68/0] │    V                                 │  
[13:4]───[0.70/0] │   V                                  │  
[13:3]───[0.72/0] │  V                                   │  
[13:2]───[0.74/0] │ V                                    │  
[13:1]───[0.76/0] │V                                     │  
[13:1]───[0.78/0] │V                                     │  
[13:2]───[0.81/0] │ V                                    │  
[13:3]───[0.83/0] │  V                                   │  
[13:4]───[0.85/0] │   V                                  │  
[13:5]───[0.87/0] │    V                                 │  
[13:6]───[0.89/0] │     V                                │  
[13:7]───[0.91/0] │U  W  V                          U   U│  
[13:8]───[0.93/0] │U  W   V                         U   U│  
[13:9]───[0.95/0] │        V                             │  
[13:10]──[0.97/0] │         V                            │  
[13:11]──[0.99/0] │          V                           │  
[13:12]──[1.01/0] │           V                          │  
[13:13]──[1.03/0] │        W   V               T         │  
[13:14]──[1.05/0] │        W    V              T         │ 14/0 i  
[13:15]──[1.07/0] │              V                       │  
[13:16]──[1.09/0] │               V                      │  
[13:17]──[1.11/0] │                V                     │  
[13:18]──[1.13/0] │                 V                    │  
[13:19]──[1.15/0] │             T    V    U              │  
[13:20]──[1.17/0] │             T     V   U              │  
[13:21]──[1.19/0] │                    V                 │  
[13:22]──[1.22/0] │                     V                │  
[13:23]──[1.24/0] │                      V               │  
[13:24]──[1.26/0] │                       V              │  
[13:25]──[1.28/0] │                  W     V             │  
[13:26]──[1.30/0] │                  W      V            │  
[13:27]──[1.32/0] │                          V           │  
[13:28]──[1.34/0] │                           V          │  
[13:29]──[1.36/0] │                            V         │  
[13:30]──[1.38/0] │                             V        │  
[13:31]──[1.40/0] │                              V       │  
[13:32]──[1.42/0] │                               V      │  
[13:33]──[1.44/0] │                                V     │  
[13:34]──[1.46/0] │                                 V    │  
[13:35]──[1.48/0] │                                  V   │  
[13:36]──[1.50/0] │                                   V  │  
[13:37]──[1.52/0] │                                    V │  
[13:38]──[1.54/0] │                                     V│  
[13:38]──[1.56/0] │                                     V│  
[13:37]──[1.58/0] │                                    V │  
[13:36]──[1.60/0] │                                   V  │  
[13:35]──[1.63/0] │                                  V   │  
[13:34]──[1.65/0] │                                 V    │  
[13:33]──[1.67/0] │                                V     │  
[13:32]──[1.69/0] │                               V      │  
[13:31]──[1.71/0] │                              V       │  
[13:30]──[1.73/0] │                             V        │  
[13:29]──[1.75/0] │                            V         │  
[13:28]──[1.77/0] │                           V          │  
[13:27]──[1.79/0] │                          V           │  
[13:26]──[1.81/0] │                         V            │  
[13:25]──[1.83/0] │                        V             │  
[13:24]──[1.85/0] │                       V              │  
[13:23]──[1.87/0] │                  T   V               │  
[13:22]──[1.89/0] │                  T  V                │  
[13:21]──[1.91/0] │                    V                 │  
[13:20]──[1.93/0] │                   V                  │  
[13:19]──[1.95/0] │                  V                   │  
[13:18]──[1.97/0] │                 V                    │  
[13:17]──[1.99/0] │             T  V      U              │  
[13:16]──[2.01/0] │             T V       U              │  
[13:15]──[2.04/0] │              V                       │  
[13:14]──[2.06/0] │             V                        │ 14/0 >  
[13:13]──[2.08/0] │            V                         │  
[13:12]──[2.10/0] │           V                          │ (**)  
[13:12]──[2.10/0] │           V                          │ (**)  
[13:13]──[2.12/0] │        T   V               W         │  
[13:14]──[2.14/0] │        T    V              W         │  
[13:15]──[2.17/0] │              V                       │  
[13:16]──[2.19/0] │               V                      │  
[13:17]──[2.21/0] │                V                     │  
[13:18]──[2.23/0] │                 V                    │  
[13:19]──[2.25/0] │U  U              *              W   T│  
```

`(**)` above: we got two screens with the same title.

The loop for asterisks 1-7, plus line before and after:  
```  
[13:18]──[2.23/0] │                 V                    │  
[13:19]──[2.25/0] │U  U              *              W   T│  
[13:20]──[2.27/1] │U  U               V             W   T│  
[13:21]──[2.29/1] │                    V                 │  
[13:22]──[2.31/1] │                     V                │  
[13:23]──[2.33/1] │                      V               │  
[13:24]──[2.35/1] │                       V              │  
[13:25]──[2.37/1] │        T               V   W         │  
[13:26]──[2.39/1] │        T                V  W         │  
[13:27]──[2.41/1] │                          V           │  
[13:28]──[2.43/1] │                           V          │  
[13:29]──[2.45/1] │                            V         │  
[13:30]──[2.47/1] │                             V        │  
[13:31]──[2.49/1] │             T         W      V       │  
[13:32]──[2.51/1] │             T         W       V      │  
[13:33]──[2.54/1] │                                V     │  
[13:34]──[2.56/1] │                                 V    │  
[13:35]──[2.58/1] │                                  V   │  
[13:36]──[2.60/1] │                                   V  │  
[13:37]──[2.62/1] │                  W                 V │  
[13:38]──[2.64/1] │                  W                  V│  
[13:38]──[2.66/1] │                                     V│  
[13:37]──[2.68/1] │                                    V │  
[13:36]──[2.70/1] │                                   V  │  
[13:35]──[2.72/1] │                                  V   │  
[13:34]──[2.74/1] │                                 V    │  
[13:33]──[2.76/1] │                                V     │  
[13:32]──[2.78/1] │                               V      │  
[13:31]──[2.80/1] │                              V       │  
[13:30]──[2.82/1] │                             V        │  
[13:29]──[2.85/1] │                            V         │  
[13:28]──[2.87/1] │                           V          │  
[13:27]──[2.89/1] │                          V           │  
[13:26]──[2.91/1] │                         V            │  
[13:25]──[2.93/1] │                        V             │  
[13:24]──[2.95/1] │                       V              │  
[13:23]──[2.97/1] │                      V               │  
[13:22]──[2.99/1] │                     V                │  
[13:21]──[3.01/1] │                    V                 │  
[13:20]──[3.03/1] │                   V                  │  
[13:19]──[3.05/1] │                  V                   │ 19/1 >  
[13:18]──[3.07/1] │                 V                    │  
[13:17]──[3.09/1] │                V                     │  
[13:17]──[3.10/1] │                V                     │  
[13:18]──[3.12/1] │                 V                    │  
[13:19]──[3.14/1] │                  V                   │  
[13:20]──[3.16/1] │                   V                  │  
[13:21]──[3.18/1] │                    V                 │  
[13:22]──[3.20/1] │                     V                │  
[13:23]──[3.22/1] │                      V         W     │  
[13:24]──[3.24/1] │                       V        W     │  
[13:25]──[3.26/1] │                        V             │  
[13:26]──[3.28/1] │                         V            │  
[13:27]──[3.30/1] │                          *           │  
[13:28]──[3.32/2] │                           V          │  
[13:29]──[3.34/2] │                            V         │  
[13:30]──[3.36/2] │                             V        │  
[13:31]──[3.38/2] │                    W         V       │  
[13:32]──[3.40/2] │                    W          V      │  
[13:33]──[3.42/2] │                                V     │  
[13:34]──[3.44/2] │                                 V    │  
[13:35]──[3.47/2] │              W                   V   │  
[13:36]──[3.49/2] │              W                    V  │  
[13:37]──[3.51/2] │                                    V │  
[13:38]──[3.53/2] │                                     V│ 38/2 >  
[13:38]──[3.55/2] │        T                            V│  
[13:37]──[3.57/2] │        T                           V │  
[13:37]──[3.57/2] │        T                           V │  
[13:38]──[3.59/2] │                                     V│  
[13:38]──[3.61/2] │                                     V│  
[13:37]──[3.63/2] │  W              U                  V │  
[13:36]──[3.66/2] │  W              U                 V  │  
[13:35]──[3.68/2] │                                  V   │  
[13:34]──[3.70/2] │                                 V    │  
[13:33]──[3.72/2] │        W              T        V     │  
[13:32]──[3.74/2] │        W              T       V      │  
[13:31]──[3.76/2] │                              V       │  
[13:30]──[3.78/2] │                             V        │  
[13:29]──[3.80/2] │              T             VT        │  
[13:28]──[3.82/2] │              T            V T        │  
[13:27]──[3.84/2] │                          V           │  
[13:26]──[3.86/2] │                         V            │  
[13:25]──[3.88/2] │                    T   V          W  │  
[13:24]──[3.90/2] │                    T  V           W  │  
[13:23]──[3.92/2] │                      V               │  
[13:22]──[3.94/2] │                     V                │  
[13:21]──[3.96/2] │                    V        W        │  
[13:20]──[3.98/2] │                   V         W        │  
[13:19]──[4.00/2] │                  V                   │  
[13:18]──[4.03/2] │                 V                    │ 18/2 s>  
[13:17]──[4.05/2] │                V      U              │  
[13:16]──[4.07/2] │               V       U              │  
[13:16]──[4.08/2] │               V                      │  
[13:17]──[4.10/2] │                V                     │  
[13:18]──[4.12/2] │                 *                    │  
[13:19]──[4.14/3] │                  V                   │  
[13:20]──[4.16/3] │                   V                  │  
[13:21]──[4.18/3] │                    V                 │  
[13:22]──[4.20/3] │           U         V                │  
[13:23]──[4.22/3] │           U          V               │  
[13:24]──[4.25/3] │                       V              │  
[13:25]──[4.27/3] │                        V             │  
[13:26]──[4.29/3] │     U                   V            │  
[13:27]──[4.31/3] │     U                    V           │  
[13:28]──[4.33/3] │                           V          │  
[13:29]──[4.35/3] │                            V         │  
[13:30]──[4.37/3] │                             V        │  
[13:31]──[4.39/3] │                              V       │  
[13:32]──[4.41/3] │                               V      │  
[13:33]──[4.43/3] │                                V     │  
[13:34]──[4.45/3] │                                 V    │  
[13:35]──[4.47/3] │                                  V   │  
[13:36]──[4.49/3] │                                   V  │  
[13:37]──[4.51/3] │                                    V │  
[13:38]──[4.53/3] │                                     V│  
[13:38]──[4.55/3] │                                     V│  
[13:37]──[4.57/3] │                                    V │  
[13:36]──[4.60/3] │                                   V  │  
[13:35]──[4.62/3] │                                  V   │  
[13:34]──[4.64/3] │                                 V    │  
[13:33]──[4.66/3] │                                V     │  
[13:32]──[4.68/3] │                               V      │  
[13:31]──[4.70/3] │                              V       │  
[13:30]──[4.72/3] │                             V        │  
[13:29]──[4.74/3] │                            V         │  
[13:28]──[4.76/3] │                           V          │  
[13:27]──[4.78/3] │                          V           │  
[13:26]──[4.80/3] │                         V            │  
[13:25]──[4.82/3] │                        V             │  
[13:24]──[4.84/3] │                       V              │  
[13:23]──[4.86/3] │                      V               │  
[13:22]──[4.88/3] │  T T U W            V                │  
[13:21]──[4.91/3] │  T T U W           V                 │  
[13:20]──[4.93/3] │                   V                  │  
[13:19]──[4.95/3] │                  V                   │  
[13:18]──[4.97/3] │  U              V                    │  
[13:17]──[4.99/3] │  U             V                     │  
[13:16]──[5.01/3] │               V                      │  
[13:15]──[5.03/3] │              V                       │  
[13:14]──[5.05/3] │  W          V                        │  
[13:13]──[5.07/3] │  W         V                         │  
[13:12]──[5.09/3] │           V                          │  
[13:11]──[5.11/3] │          V                           │  
[13:10]──[5.13/3] │  W      V T W U                      │  
[13:9]───[5.15/3] │  W     V  T W U                      │  
[13:8]───[5.18/3] │       V                              │ 8/3 >  
[13:7]───[5.20/3] │      V                               │  
[13:6]───[5.22/3] │  W  V     T                          │  
[13:6]───[5.22/3] │  W  V     T                          │  
[13:7]───[5.24/3] │  W   V    T                          │  
[13:8]───[5.26/3] │       V                              │  
[13:9]───[5.28/3] │        V                             │  
[13:10]──[5.30/3] │         V U T W                      │  
[13:11]──[5.33/3] │          VU T W                      │  
[13:12]──[5.35/3] │           V                          │  
[13:13]──[5.37/3] │            V                         │ 13/3 <  
[13:14]──[5.39/3] │           T V      U T T             │  
[13:15]──[5.41/3] │           T  V     U T T             │  
[13:15]──[5.41/3] │           T  V     U T T             │  
[13:14]──[5.43/3] │             V                        │  
[13:13]──[5.45/3] │            V                         │  
[13:12]──[5.47/3] │           * U T    T                 │  
[13:11]──[5.50/4] │          V  U T    T                 │  
[13:10]──[5.52/4] │         V                            │  
[13:9]───[5.54/4] │        V                             │  
[13:8]───[5.56/4] │       V            T T T             │  
[13:7]───[5.58/4] │      V             T T T             │  
[13:6]───[5.60/4] │     V                                │  
[13:5]───[5.62/4] │    V                                 │  
[13:4]───[5.64/4] │   V                W          U      │ 4/4 >  
[13:3]───[5.66/4] │  V                 W          U      │  
[13:2]───[5.68/4] │ V                                    │  
[13:2]───[5.69/4] │ V                                    │  
[13:3]───[5.71/4] │  V                                   │  
[13:4]───[5.73/4] │   V                W U W      U      │  
[13:5]───[5.75/4] │    V               W U W      U      │  
[13:6]───[5.77/4] │     V                                │  
[13:7]───[5.79/4] │      V                               │  
[13:8]───[5.81/4] │       V                       T      │  
[13:9]───[5.83/4] │        V                      T      │  
[13:10]──[5.85/4] │         V                            │  
[13:11]──[5.88/4] │          V                           │  
[13:12]──[5.90/4] │           V                   W      │  
[13:13]──[5.92/4] │            V                  W      │  
[13:14]──[5.94/4] │             V                        │  
[13:15]──[5.96/4] │              V                       │  
[13:16]──[5.98/4] │               V           T U T W T  │  
[13:17]──[6.00/4] │                V          T U T W T  │  
[13:18]──[6.02/4] │                 V                    │  
[13:19]──[6.04/4] │                  V                   │  
[13:20]──[6.06/4] │                   V                  │  
[13:21]──[6.08/4] │                    V                 │  
[13:22]──[6.10/4] │                     V                │  
[13:23]──[6.12/4] │                      V               │  
[13:24]──[6.14/4] │                       V              │  
[13:25]──[6.17/4] │                        V             │  
[13:26]──[6.19/4] │                         V            │  
[13:27]──[6.21/4] │                          V           │  
[13:28]──[6.23/4] │                           V          │  
[13:29]──[6.25/4] │                            V         │  
[13:30]──[6.27/4] │                             V        │  
[13:31]──[6.29/4] │                              V       │  
[13:32]──[6.31/4] │                               V      │  
[13:33]──[6.33/4] │                                V     │  
[13:34]──[6.35/4] │                                 V    │ 34/4 <  
[13:35]──[6.37/4] │                                  V   │  
[13:36]──[6.40/4] │                                   V  │  
[13:36]──[6.40/4] │                                   V  │  
[13:35]──[6.42/4] │                                  V   │  
[13:34]──[6.44/4] │                                 V    │  
[13:33]──[6.46/4] │                                V     │  
[13:32]──[6.48/4] │                               V      │  
[13:31]──[6.50/4] │                              V       │  
[13:30]──[6.52/4] │                             V        │  
[13:29]──[6.54/4] │                            V         │  
[13:28]──[6.56/4] │                           V          │  
[13:27]──[6.59/4] │W                         V          T│  
[13:26]──[6.61/4] │W                        V           T│  
[13:25]──[6.63/4] │   T   W                V    T   U    │  
[13:24]──[6.65/4] │   T   W               V     T   U    │  
[13:23]──[6.67/4] │W          U          V  T           W│  
[13:22]──[6.69/4] │W          U         V   T           W│  
[13:21]──[6.71/4] │               T    VW                │  
[13:20]──[6.73/4] │               T   V W                │  
[13:19]──[6.75/4] │W                 *                  W│ 19/4 >  
[13:18]──[6.77/5] │W                V                   W│  
[13:17]──[6.79/5] │               TV    T                │  
[13:17]──[6.80/5] │               TV    T                │  
[13:18]──[6.82/5] │               T V   T                │  
[13:19]──[6.84/5] │U          U      V      T           W│  
[13:20]──[6.86/5] │U          U       V     T           W│  
[13:21]──[6.88/5] │   T   U            V        W   W    │  
[13:22]──[6.90/5] │   T   U             V       W   W    │  
[13:23]──[6.92/5] │T                     V              U│  
[13:24]──[6.95/5] │T                      V             U│  
[13:25]──[6.97/5] │                        V             │  
[13:26]──[6.99/5] │                         V            │  
[13:27]──[7.01/5] │                          V           │  
[13:28]──[7.03/5] │                           V          │  
[13:29]──[7.05/5] │                            V         │  
[13:30]──[7.07/5] │                             V        │  
[13:31]──[7.09/5] │                              V       │ 31/5 i  
[13:32]──[7.11/5] │                               V      │  
[13:33]──[7.13/5] │                                V     │  
[13:34]──[7.15/5] │                                 V    │  
[13:35]──[7.17/5] │                                  V   │  
[13:36]──[7.19/5] │                                   V  │  
[13:37]──[7.21/5] │                                    V │  
[13:38]──[7.23/5] │                                     V│  
[13:38]──[7.26/5] │                                     V│  
[13:37]──[7.28/5] │                                    V │  
[13:36]──[7.30/5] │                                   V  │  
[13:35]──[7.32/5] │                                  V   │  
[13:34]──[7.34/5] │                                 V    │  
[13:33]──[7.36/5] │                                V     │  
[13:32]──[7.38/5] │                               V      │  
[13:31]──[7.40/5] │                              V       │ 31/5 s>  
[13:30]──[7.42/5] │                             V        │  
[13:29]──[7.44/5] │                            V         │  
[13:29]──[7.46/5] │                            V         │  
[13:30]──[7.48/5] │                             V        │  
[13:31]──[7.50/5] │                              V       │  
[13:32]──[7.52/5] │            T                  V      │  
[13:33]──[7.54/5] │            T                   V     │  
[13:34]──[7.56/5] │          W   U                  V    │  
[13:35]──[7.58/5] │          W   U                   V   │  
[13:36]──[7.60/5] │        U       T                  V  │  
[13:37]──[7.62/5] │        U       T                   V │  
[13:38]──[7.64/5] │      U           T                  V│  
[13:38]──[7.67/5] │      U           T                  V│  
[13:37]──[7.69/5] │                                    V │  
[13:36]──[7.71/5] │                                   V  │  
[13:35]──[7.73/5] │                        U         V   │  
[13:34]──[7.75/5] │                        U        V    │  
[13:33]──[7.77/5] │                      W   U     V     │  
[13:32]──[7.79/5] │                      W   U    V      │  
[13:31]──[7.81/5] │                    U       T V       │  
[13:30]──[7.83/5] │                    U       TV        │  
[13:29]──[7.85/5] │                  T         V U       │  
[13:28]──[7.87/5] │                  T        V  U       │  
[13:27]──[7.89/5] │                          V           │  
[13:26]──[7.91/5] │                         V            │  
[13:25]──[7.94/5] │            U           V             │  
[13:24]──[7.96/5] │            U          V              │  
[13:23]──[7.98/5] │          T   W       V               │  
[13:22]──[8.00/5] │          T   W      V                │  
[13:21]──[8.02/5] │        U       U   V                 │  
[13:20]──[8.04/5] │        U       U  V                  │  
[13:19]──[8.06/5] │      U           *                   │  
[13:18]──[8.08/6] │      U          V                    │  
[13:17]──[8.10/6] │                V                     │  
[13:16]──[8.12/6] │               V                      │  
[13:15]──[8.14/6] │              V         W             │  
[13:14]──[8.16/6] │             V          W             │  
[13:13]──[8.18/6] │            V         W   W           │  
[13:12]──[8.20/6] │           V          W   W           │  
[13:11]──[8.22/6] │          V         W       U         │  
[13:10]──[8.24/6] │         V          W       U         │  
[13:9]───[8.26/6] │        V         U           T       │  
[13:8]───[8.28/6] │       V          U           T       │  
[13:7]───[8.30/6] │      V                               │  
[13:6]───[8.32/6] │     V                                │  
[13:5]───[8.35/6] │    V                                 │  
[13:4]───[8.37/6] │   V                                  │  
[13:3]───[8.39/6] │  V                                   │  
[13:2]───[8.41/6] │ V                                    │ 2/6 <  
[13:1]───[8.43/6] │V                                     │  
[13:1]───[8.45/6] │V                                     │  
[13:1]───[8.45/6] │V                                     │  
[13:1]───[8.47/6] │V                                     │  
[13:2]───[8.49/6] │ V                                    │  
[13:3]───[8.51/6] │  V                                   │  
[13:4]───[8.53/6] │   V                                  │  
[13:5]───[8.55/6] │    V                                 │  
[13:6]───[8.58/6] │     V                                │  
[13:7]───[8.60/6] │      V                               │  
[13:8]───[8.62/6] │       V                              │  
[13:9]───[8.64/6] │        V                             │  
[13:10]──[8.66/6] │         V                            │  
[13:11]──[8.68/6] │          V                           │  
[13:12]──[8.70/6] │           V                          │  
[13:13]──[8.72/6] │            V                         │  
[13:14]──[8.74/6] │             V                        │  
[13:15]──[8.76/6] │              V                       │  
[13:16]──[8.78/6] │               V                      │  
[13:17]──[8.80/6] │                V                     │  
[13:18]──[8.82/6] │                 V                    │  
[13:19]──[8.84/6] │                  V                   │  
[13:20]──[8.86/6] │                   V                  │ 20/6 <  
[13:21]──[8.88/6] │                    V                 │  
[13:22]──[8.91/6] │                     V                │  
[13:22]──[8.91/6] │                     V                │  
[13:21]──[8.93/6] │                    V                 │  
[13:20]──[8.95/6] │                   V                  │ 20/6 i  
[13:19]──[8.97/6] │                  V                   │  
[13:18]──[8.99/6] │                 V                    │  
[13:17]──[9.02/6] │                V                     │  
[13:16]──[9.04/6] │               V                      │  
[13:15]──[9.06/6] │              V                       │  
[13:14]──[9.08/6] │             V                        │  
[13:13]──[9.10/6] │            V                         │  
[13:12]──[9.12/6] │           V                          │  
[13:11]──[9.14/6] │          V                           │  
[13:10]──[9.16/6] │         V                            │  
[13:9]───[9.18/6] │        V                             │  
[13:8]───[9.20/6] │       V                              │  
[13:7]───[9.22/6] │      V                               │  
[13:6]───[9.24/6] │U  W V                           U   U│  
[13:5]───[9.26/6] │U  WV                            U   U│  
[13:4]───[9.28/6] │   V                                  │  
[13:3]───[9.31/6] │  V                                   │  
[13:2]───[9.33/6] │ V                                    │  
[13:1]───[9.35/6] │V                                     │  
[13:1]───[9.37/6] │V       W                   T         │  
[13:2]───[9.39/6] │ V      W                   T         │  
[13:3]───[9.41/6] │  V                                   │  
[13:4]───[9.43/6] │   V                                  │  
[13:5]───[9.45/6] │    V                                 │  
[13:6]───[9.47/6] │     V                                │  
[13:7]───[9.49/6] │      V      T         U              │  
[13:8]───[9.51/6] │       V     T         U              │  
[13:9]───[9.53/6] │        V                             │  
[13:10]──[9.55/6] │         V                            │  
[13:11]──[9.57/6] │          V                           │  
[13:12]──[9.59/6] │           V                          │  
[13:13]──[9.61/6] │            V     W                   │  
[13:14]──[9.64/6] │             V    W                   │  
[13:15]──[9.66/6] │              V                       │  
[13:16]──[9.68/6] │               V                      │  
[13:17]──[9.70/6] │                V                     │  
[13:18]──[9.72/6] │                 V                    │  
[13:19]──[9.74/6] │                  V                   │  
[13:20]──[9.76/6] │                   V                  │  
[13:21]──[9.78/6] │                    V                 │  
[13:22]──[9.80/6] │                     V                │  
[13:23]──[9.82/6] │                      V               │  
[13:24]──[9.84/6] │                       V              │ 24/6 i  
[13:25]──[9.86/6] │                        V             │  
[13:26]──[9.88/6] │                         V            │  
[13:27]──[9.90/6] │                          V           │  
[13:28]──[9.92/6] │                           V          │  
[13:29]──[9.94/6] │                            V         │  
[13:30]──[9.96/6] │                             V        │  
[13:31]──[9.99/6] │                              V       │  
[13:32]──[10.01/6] │                               V      │  
[13:33]──[10.03/6] │                                V     │  
[13:34]──[10.05/6] │                                 V    │  
[13:35]──[10.07/6] │                                  V   │  
[13:36]──[10.09/6] │                                   V  │  
[13:37]──[10.11/6] │                                    V │  
[13:38]──[10.13/6] │                                     V│  
[13:38]──[10.15/6] │                                     V│  
[13:37]──[10.17/6] │                                    V │  
[13:36]──[10.19/6] │                                   V  │  
[13:35]──[10.21/6] │                  T               V   │  
[13:34]──[10.23/6] │                  T              V    │  
[13:33]──[10.25/6] │                                V     │  
[13:32]──[10.28/6] │                               V      │  
[13:31]──[10.30/6] │                              V       │  
[13:30]──[10.32/6] │                             V        │  
[13:29]──[10.34/6] │             T         U    V         │  
[13:28]──[10.36/6] │             T         U   V          │  
[13:27]──[10.38/6] │                          V           │  
[13:26]──[10.40/6] │                         V            │  
[13:25]──[10.42/6] │                        V             │  
[13:24]──[10.44/6] │                       V              │  
[13:23]──[10.46/6] │        T             V     W         │  
[13:22]──[10.48/6] │        T            V      W         │  
[13:21]──[10.50/6] │                    V                 │  
[13:20]──[10.52/6] │                   V                  │ 20/6 >  
[13:19]──[10.55/6] │                  V                   │  
[13:18]──[10.57/6] │                 V                    │  
[13:18]──[10.57/6] │                 V                    │  
[13:19]──[10.59/6] │U  U              *              W   T│  
[13:20]──[10.61/7] │U  U               V             W   T│  
```  

Original writeup (https://github.com/MV9rwGOf08/ctf-
writeups/tree/master/2019/pwn2win/astrobot).