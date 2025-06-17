# Lost In Transmission 2.0 [500 pts]

-----

## Category  
Misc

## Description  
>```  
>FDFDDDFFDFDDFDDDDFFDFDDFDDFFDFDFFDDFFDFFDDFFDFDDDDDDFFDFDDFFDDFFDFFDDDFFDFFFFFFDDFFDFDDDDDDFFDFDDDDFFDFDDDFFDFDFDDFFDFDDFDDFFDFDDDDDDFFDFFDFDDFFDFFDDDFFDFFFDDDDFFDFFFFDDDDFFDFDDDDDDFFDFFFFFDDFFDFFDDDFFDFFFFFFDDFFDFDFFFDDFFDFDDDDDDFFDFDDDDFFDFFFFDDDDFFDFFDDDFFDFDDFDDFFDFDDDDDDFFDFDFFDDFFDFDDDFFDFDDDDDDFFDFFFDDDDFFDFDDFDDDDFFDFDDFFDDFFDFDDDDDDFFDFFFFFDDFFDFFFFDDDDFFDFDFFFDDFFDFDFFDDFFDFDDDDDDFFDFDFFFDDFFDFDDFDDFFDFDDDDFFDFDDDDDDFFDFFDFDDFFDFFDDDFFDFFFDDFFDFFFDDDDFFDF  
>```  
>  
>*Author: DataFrogman*  
>  
>We heard LostInTransmission last year was everyone's bane so we decided to
one-up it, have fun!  
>Make sure you wrap the flag in RITSEC{}

## Solution  
1. Convert F to `.` and D to `-`.  
2. Looks like morse code but there is no delimiter between letters.  
3. Find a delimiter so that it looks like valid morse letters. `--..-.` is a pattern that repeats quite often. And using this as a delimiter, there are no large morse chunks. It now looks like quite normal morse code!  
4. Replace `--..-.` with a space and you get this code:  
```  
.-.- --.-- --. -.. . ---- --.. .- ..... ---- -- - -. --. ---- .-. .- ..--
...-- ---- .... .- ..... -... ---- -- ...-- .- --. ---- -.. - ---- ..-- --.--
--.. ---- .... ...-- -... -.. ---- -... --. -- ---- .-. .- .. ..--  
```  
5. Find out that nothing makes sense and figure out that it's not morse code but `Bain`.  
6. Convert from Bain to text: `M0RSE&WA5&YOUR&BAN3&LA5T&Y3AR&SO&N0W&L3TS&TRY&BAIN`  
7. Wrap the text with `RITSEC{}`

#### Flag  
`RITSEC{M0RSE&WA5&YOUR&BAN3&LA5T&Y3AR&SO&N0W&L3TS&TRY&BAIN}`

Original writeup
(https://github.com/bootplug/writeups/blob/master/2019/ritsec-
ctf/misc/lost%20in%20transmission%202.0/README.md).