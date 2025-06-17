# [crypto] 0ff Again On Aga1n  
## task  
```  
Created by: Shamel

This note was left after a recent DEADFACE attack; they know how much we love
puzzles. The rest of the team is still dealing with the fallout but maybe you
can figure out what is says. Who knows, there might even be a clue in there.

Submit the flag as flag{H1DD3NM355@G3}.  
```  
![image](https://cdn.discordapp.com/attachments/1162972185988702288/1166313095854047293/image.png?ex=654a08b7&is=653793b7&hm=756f47356b1620e264657516462563959f84e5d04b804a53ee43a0303de03603&)  
## solution  
the first thing to notice is the 0 and 1 in the title, which hints to binary.
we can then assume that each color represents 0 or 1

knowing the result is likely to be english, i assumed each row's first bits
would be 00 or 01, which leads to this guess:  
```  
0 - purple, black  
1 - green, pink  
```  
giving `01010100 00110011 01000011 01001000 01001110 00110000 01000111
00110001`, which decodes to `T3CHN0G1`, but it alone was incorrect.

we then realized that the image can also be read vertically, so using the same
trick, we guessed:  
```  
0 - purple, green  
1 - black, pink  
```  
giving `00110000 00111000 01000000 00110001 01010010 00110011 01001001
01001110`, decoding to `08@1R3IN`

combining both gives our answer:  
## flag  
`flag{T3CHN0G108@1R3IN}`  
## note  
what the hell is a techno global rein :fire::fire::fire: