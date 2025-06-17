**Description**

> All CTF players are squares  
>  
> Edit (09/14 8:22 PM) - Uploaded new pcap file  
>  
> Edit (09/15 12:10 AM) - Uploaded new pcap file

**Files provided**

- (before updates) [`output.pcap`](https://github.com/Aurel300/empirectf/blob/master/writeups/2018-09-14-CSAW-CTF-Quals/files/mcgriddle-output.pcap)  
- [`final.pcap`](https://github.com/Aurel300/empirectf/blob/master/writeups/2018-09-14-CSAW-CTF-Quals/files/mcgriddle-final.pcap)

**Solution**

Looking through (either) `pcap`, we can see that a chess game is being played,
and the moves are indicated with [algebraic chess
notation](https://en.wikipedia.org/wiki/Algebraic_notation_%28chess%29). The
server responds with its own moves, and between the moves, SVG files are
uploaded, each containing an `8 x 8` grid of characters, all of which seem to
be Base64.

My first guess was that we treat the SVG grids as chessboards, then for each
move of a piece, we take the squares that the piece moved from or to. The
coordinates are relatively easy to parse from algebraic notation, but this
method seemed to produce no readable text.

The next thing I tried was taking all the characters in the SVG grids and
simply decoding them as they were without modifying them. This produced some
garbage data, but some of it was readable. What I noticed in particular was
that the data decoded from the very first grid has 12 bytes of garbage,
followed by 24 bytes of readable text (some lorem ipsum filling text), then 12
bytes of garbage again.

   x x x x x x x x  
   x x x x x x x x  
   . . . . . . . .  
   . . . . . . . .  
   . . . . . . . .  
   . . . . . . . .  
   x x x x x x x x  
   x x x x x x x x  
  
   (x = garbage, . = data)

Given the presence of chess moves and the fact that this was the first grid,
this was clearly the starting position, and characters covered by pieces
should be ignored.

The chess game (in `final.pcap`) was quite long at 90+ moves, so I didn't feel
like stepping through the moves myself and writing down the board state
manually. Parsing SAN also seemed a bit too slow, so instead I just exported
the moves into a standard format – the moves themselves were already encoded
properly, I just numbered them properly:

   1. Nf3 Nf6 2. d4 e6 3. Nc3 d5 4. Bg5 Bb4 5. e3 h6 6. Bxf6 Qxf6 7. Bb5+ Bd7 8. O-O O-O 9. Ne5 Qe7 10. Bd3 Nc6 11. Nxd7 Qxd7 12. Ne2 Qe7 13. c4 dxc4 14. Bxc4 Qh4 15. Rc1 Rfd8 16. Ng3 a6 17. f4 Bd6 18. Ne4 Kh8 19. Nxd6 Rxd6 20. Be2 Qd8 21. Qb3 Rb8 22. Rf2 Ne7 23. Bh5 Kg8 24. Qd3 Nd5 25. a3 c6 26. Bf3 Qe7 27. Rfc2 Rc8 28. Rc5 Re8 29. Qd2 Qf6 30. Be4 h5 31. Qe2 h4 32. Qf3 Rd7 33. Bd3 Red8 34. Re1 Kf8 35. Qh5 Nxf4 36. exf4 Qxd4+ 37. Kh1 Qxd3 38. Qh8+ Ke7 39. Qxh4+ Kd6 40. Rc3 Qd2 41. Qg3 Kc7 42. f5+ Kc8 43. fxe6 fxe6 44. Rce3 Qxb2 45. Rxe6 Rd1 46. h3 Rxe1+ 47. Rxe1 Qf6 48. a4 Qf7 49. a5 Rd5 50. Qg4+ Kb8 51. Qg3+ Ka8 52. Re5 Qd7 53. Kg1 Ka7 54. Kh2 Rb5 55. Rxb5 axb5 56. Qe3+ Kb8 57. Qc5 Kc7 58. Kg1 Qd1+ 59. Kf2 Qd6 60. Qc3 Qf8+ 61. Kg1 b6 62. Qd4 Qc5 63. Qxc5 bxc5 64. Kf2 Kb7 65. Ke3 Ka6 66. h4 Kxa5 67. h5 c4 68. Kd2 Kb4 69. g4 Kb3 70. g5 Kb2 71. Ke2 c3 72. h6 gxh6 73. gxh6 c2 74. h7 c1=Q 75. h8=Q+ Qc3 76. Qf8 b4 77. Qf4 Qc2+ 78. Kf3 b3 79. Qd6 c5 80. Ke3 c4 81. Qe6 Qd3+ 82. Kf4 c3 83. Qe5 Ka3 84. Qa5+ Kb2 85. Qe5 Kc1 86. Qc5 b2 87. Qg1+ Kd2 88. Qg2+ Kd1 89. Qg4+ Kc2 90. Qg1 Qd6+ 91. Ke4 Qb4+ 92. Kf3 Qb7+ 93. Kf4 b1=Q 94. Qe3 Kb3 95. Kg5 Qd5+ 96. Kf4 Qbf5+ 97. Kg3 Qd6+ 98. Kg2 Qd2+ 99. Qxd2 cxd2 100. Kg1 d1=Q+ 101. Kg2 Qd2+ 102. Kg3 Qdf2#

Then I pasted this into the [analysis board on
Lichess](https://lichess.org/analysis), and with some light Javascript I took
the [FEN](https://en.wikipedia.org/wiki/Forsyth%E2%80%93Edwards_Notation)
value at each turn. FEN notation encodes the momentary state of the game as
opposed to the turn progression, so it is very easy to parse it to see which
squares are occupied and which are not.

With the FENs, I masked each SVG grid and parsed the text. Unfortunately, no
matter how I adjusted the parser, I could only see the end of the flag
(`r3aLLLy_hat3_chess_tbh}`). I tried a couple of guesses but I didn't know how
much of the flag I was missing.

After some frustration, I decided to look at the `output.pcap` file, which I
downloaded earlier but didn't really use until now. The admin of the challenge
said that there were solves on that version as well, so it was clearly not
totally broken.

Since the flag in `final.pcap` was quite late in the chess game, the masking
with chess pieces didn't really hide it and it might have been sufficient to
simply decode the SVG grids without masking – so I tried this on the
`output.pcap` grids and indeed, I found most of the flag there (except for the
last three characters).

I guess a [grille cipher](https://en.wikipedia.org/wiki/Grille_(cryptography))
is not terribly effective when most of the grid is used, as is the case
towards the end of the game.

`flag{3y3_actuAllY_r3aLLLy_hat3_chess_tbh}`

Original writeup
(https://github.com/Aurel300/empirectf/blob/master/writeups/2018-09-14-CSAW-
CTF-Quals/README.md#300-forensics--mcgriddle).