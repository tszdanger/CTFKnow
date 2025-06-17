# Intergalactic Cinema

## Description  
```  
I was partaking in a fun viewing of some show/movie with my alien bros but
couldn't understand anything due to the alien voice dubbing present in the
movie.

I've managed to download a script of what was said during the viewing but it
seems to be encrypted, can you help me decrypt it?

Follow this link to get started: http://intergalactic.martiansonly.net  
```

## Writeup

Looking at the website we can see some encrypted text and some `letter/number
mapping`.  
These clues should indicate that it is most likely a `substitution cipher`.  
Copying the `ciphertext` into an [online-solver](https://planetcalc.com/8047/)
returns some plaintext although it isn't able to map everything correctly.  
```py  
# frqdq wdq 87 s2mr fr38zs ws zr7sfs, bwbq.  
# there are no such things as ghosts, babe.  
```  
Mapping some letters we can make our own script to decrypt the whole thing.  
```py  
known_chars = {  
   'f': 't',  
   'r': 'h',  
   'q': 'e',  
   'd': 'r',  
   'w': 'a',  
   '8': 'n',  
   '7': 'o',  
   's': 's',  
   '2': 'u',  
   'm': 'c',  
   'r': 'h',  
   '3': 'i',  
   'z': 'g',  
   'b': 'b',  
}

# frqdq wdq 87 s2mr fr38zs ws zr7sfs, bwbq.  
# there are no such things as ghosts, babe.

with open('ct.txt', 'r') as file:  
   out = ''  
   for line in file:  
       for char in line:  
           if char in known_chars.keys():  
               out += known_chars[char]  
           elif char == ' ':  
               out += ' '  
           elif char in ['!', ',', ':', '.', "'", '"', '#', '?', '-', '_', '{', '}']:  
               out += char  
           elif char == '\n':  
               out += '\n'  
           else:  
               out += '$'

print(out)  
```

Executing the script, we can see certain words which are only missing single
letters.  
Applying this method we can get the correct `mapping` letter by letter.  
```  
### line $$$$ ###  
in a strange galaxy.

### line $$$$ ###  
$aybe right no$

### line $$$$ ###  
she's settling in $or the long na$...  
```

Mapping all correct letters reveals the flag.  
The numbers can be mapped via the lines `### line $$$$ ###` (starts off with
1).  
```py  
known_chars = {  
   'f': 't',  
   'r': 'h',  
   'q': 'e',  
   'd': 'r',  
   'w': 'a',  
   '8': 'n',  
   '7': 'o',  
   's': 's',  
   '2': 'u',  
   'm': 'c',  
   'r': 'h',  
   '3': 'i',  
   'z': 'g',  
   'b': 'b',  
   '6': 'l',  
   'o': 'x',  
   '1': 'y',  
   'y': 'f',  
   'v': 'm',  
   'i': 'w',  
   'k': 't',  
   '9': 'l',  
   'a': 'd',  
   '4': 'p',  
   'c': '1',  
   'p': '2',  
   'g': '3',  
   'h': '4',  
   't': '5',  
   '0': '6',  
   '5': '7',  
   'n': '8',  
   'l': '9',  
   'x': '0',  
   'e': 'z',  
   'j': 'q',  
}

# frqdq wdq 87 s2mr fr38zs ws zr7sfs, bwbq.  
# there are no such things as ghosts, babe.

with open('ct.txt', 'r') as file:  
   for line in file:  
       line_out = ''  
       for char in line:  
           if char in known_chars.keys():  
               line_out += known_chars[char]  
           elif char == ' ':  
               line_out += ' '  
           elif char in ['!', ',', ':', '.', "'", '"', '#', '?', '-', '_', '{', '}']:  
               line_out += char  
           elif char == '\n':  
               line_out += '\n'  
           else:  
               line_out += '$'

       if line_out.startswith('shctf{'):  
           print(line_out)  
```

Executing the script reveals the flag which concludes this writeup.  
```sh  
$ python3 solver.py  
shctf{d0_n0t_g0_g3ntle_into_that_g0od_n1ght}  
```

Original writeup
(https://github.com/Aryt3/writeups/tree/main/jeopardy_ctfs/2024/space_heroes_ctf_2024/intergalactic_cinema).