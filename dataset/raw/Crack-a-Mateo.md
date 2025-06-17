After reading the description of the challenge, the conversation of the
message, and seeing the hint, it was more than evident that the solution to
the problem would be to perform a dictionary attack, but a dictionary attack
profiled towards the target.

There are several tools to do this but none that I know of is as easy to
implement as [CUPP - Common User Passwords
Profiler](https://github.com/Mebus/cupp)

```  
┌──(leonuz㉿sniperhack)-[~/…/jersey24/crypto/crack-a-mateo/cupp]  
└─$ python3 cupp.py -i  
___________  
cupp.py!                 # Common  
     \                     # User  
      \   ,__,             # Passwords  
       \  (oo)____         # Profiler  
          (__)    )\  
             ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]  
                           [ Mebus | https://github.com/Mebus/]

[+] Insert the information about the victim to make a dictionary  
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: Mateo  
> Surname:  
> Nickname:  
> Birthdate (DDMMYYYY): 10051979

> Partners) name: Jennifer  
> Partners) nickname:  
> Partners) birthdate (DDMMYYYY): 16091979

> Child's name: Melia  
> Child's nickname:  
> Child's birthdate (DDMMYYYY): 13092011

> Pet's name:  
> Company name:

> Do you want to add some key words about the victim? Y/[N]: Y  
> Please enter the words, separated by comma. [i.e. hacker,juice,black],
> spaces will be removed: Louis Vuittons  
> Do you want to add special chars at the end of words? Y/[N]: Y  
> Do you want to add some random numbers at the end of words? Y/[N]:Y  
> Leet mode? (i.e. leet = 1337) Y/[N]: Y

[+] Now making a dictionary...  
[+] Sorting list and removing duplicates...  
[+] Saving dictionary to mateo.txt, counting 16592 words.  
> Hyperspeed Print? (Y/n) : n  
[+] Now load your pistolero with mateo.txt and shoot! Good luck!

┌──(leonuz㉿sniperhack)-[~/…/ctf/jersey24/crypto/crack-a-mateo]  
└─$ john --wordlist=mateo.txt pdf.hash  
Using default input encoding: UTF-8  
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])  
Cost 1 (revision) is 3 for all loaded hashes  
Will run 4 OpenMP threads  
Press 'q' or Ctrl-C to abort, almost any other key for status  
m3l14!@'#'       (flag.pdf)  
1g 0:00:00:00 DONE (2024-03-24 10:33) 2.941g/s 29364p/s 29364c/s 29364C/s
jennifer@*!..m3l14$@%  
Use the "--show --format=PDF" options to display all of the cracked passwords
reliably  
Session completed.  
```

full write up [here](https://leonuz.github.io/blog/Crack-a-Mateo/)

Original writeup (https://leonuz.github.io/blog/Crack-a-Mateo/).