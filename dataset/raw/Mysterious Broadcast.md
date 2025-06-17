# Mysterious Broadcast

I know, I know, there are other more elegant and faster ways... But it's Linux
.... and Bash...

Challenge Description:

```bash  
Mysterious Broadcast  
100  
Hard  
There used to be 8 Models of humanoid cylon but now there are only 7. We've
located one of their broadcast nodes but we can't decode it. Are you able to
decipher their technologies?

http://173.230.134.127

Author: blakato  
```  
We go to the URL of the challenge and we only see a symbol `~`, if we refresh
the page several times, we see that it changes. `~110...` looks like a binary
code.

If we loop over the page by curling it, we may be able to get the complete
message.

We then proceed to test with a bash script (I know, it's not the most elegant
or beautiful, but it works.)

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Web/Mysterious_Broadcast]  
└─$ cat looping.sh  
#!/bin/bash  
loop="http://173.230.134.127/seq/f6456df7-ddc7-473f-89c8-89f083bb938f"  
for i in {1..800}  
do  
  curl $loop  
done  
```  
and the console output of the script is..

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Web/Mysterious_Broadcast]  
└─$ ./looping.sh  
~1100011011001011010001101010110010010001111011010011011110100011011000100111011010101100001101011111011001001010110001101100001000101011001110100011101101110110001100001010101011001110100101101000110001011011011010010110100011000111101101101001001110011000011110011101111010111101~1100011011001011010001101010110010010001111011010011011110100011011000100111011010101100001101011111011001001010110001101100001000101011001110100011101101110110001100001010101011001110100101101000110001011011011010010110100011000111101101101001001110011000011110011101111010111101~110001101100101101000110101011001001000111101101001101111010001101100010011101101010110000110101111101100100101011000110110000100010101100111010001110110111011000110000101010101100111010010110100011000101101101101001011010001100011110110  

```  
We see that what is inside the `~` is repeated, it is a message that repeats.
We save it with the name `sequence.in` to analyze it (yes, I could have done
it directly from the script, but :) ).

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Web/Mysterious_Broadcast]  
└─$ echo
"1100011011001011010001101010110010010001111011010011011110100011011000100111011010101100001101011111011001001010110001101100001000101011001110100011101101110110001100001010101011001110100101101000110001011011011010010110100011000111101101101001001110011000011110011101111010111101"
> sequence.in  
```

We know from the statement of the problem that **There used to be 8 ..... but
now there are only 7**, then we proceed to arrenge the `sequence.in` file,  
for this, we use the linux commands [`fold`](https://linux.die.net/man/1/fold)
and [`tr`](https://linux.die.net/man/1/tr)

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Web/Mysterious_Broadcast]  
└─$ fold -b7 sequence.in | tr "\n" " " > data.in   
```

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Web/Mysterious_Broadcast]  
└─$ cat data.in  
1100011 0110010 1101000 1101010 1100100 1000111 1011010 0110111 1010001
1011000 1001110 1101010 1100001 1010111 1101100 1001010 1100011 0110000
1000101 0110011 1010001 1101101 1101100 0110000 1010101 0110011 1010010
1101000 1100010 1101101 1010010 1101000 1100011 1101101 1010010 0111001
1000011 1100111 0111101 0111101  
```  

Once we have the file arranged in 7-bits words, we transform it to ASCII using
[`xxd`](https://linux.die.net/man/1/xxd). (Again, many ways to do this,
including web tools that are much faster than writing a script, but where's
the fun in that? and the learning?)

For our friend
[StackOverFlow](https://stackoverflow.com/questions/49075346/binary-to-ascii-
conversion-using-xxd) we know this:  

"If you want to stick with `xxd`, then you need to first convert each binary
number to decimal. If you're using bash, and `x` contains you're binary
string, then:

`for a in $x; do printf "%x" $((2#$a)); done | xxd -r -p` 

`$((2#$a))` is binary to decimal conversion in bash, and the `printf` will
convert this to hex. Then just pipe it to `xxd -` and get what you got
before."

Now we only have to re-arrange our statement to execute it and obtain the
desired conversion. For that, we store the data in a variable and do a `for`
to convert each 7-bit word into an ASCII character.

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Web/Mysterious_Broadcast]  
└─$ data=$(cat data.in); for byte in $data; do echo $(printf '%x\n' "$((2#$byte))"); done | xxd -r -p  
c2hjdGZ7QXNjaWlJc0E3Qml0U3RhbmRhcmR9Cg==  
```

This result looks like a base64 encoding, we decode it in the following way

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Web/Mysterious_Broadcast]  
└─$ echo "c2hjdGZ7QXNjaWlJc0E3Qml0U3RhbmRhcmR9Cg==" | base64 -d  
shctf{AsciiIsA7BitStandard}  
```

We have the challenge flag!

- - -

### Final Notes.

Linux plays an incredibly important part in the job of a cybersecurity
professional. Specialized Linux distributions such as Kali Linux are used by
cybersecurity professionals to perform in-depth penetration testing and
vulnerability assessments, as well as provide forensic analysis after a
security breach.

Linux Shell scripts have several required constructs that tell the shell
environment what to do and when to do it. Of course, most scripts are more
complex than the above one.

The shell is, after all, a real programming language, complete with variables,
control structures, and so forth. No matter how complicated a script gets, it
is still just a list of commands executed sequentially

thanks, [FITSEC
Team](https://floridatech.campuslabs.com/engage/organization/fitsec) for the
excellent CTF.

For fun and knowledge, always think out of the box! :)

Original writeup (https://leonuz.github.io/blog/Mysterious-Broadcast/).