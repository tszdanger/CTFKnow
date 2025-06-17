# The Substitution Game (Misc)  
We're given a server to ```nc``` to and the [source
code](https://github.com/redpwn/redpwnctf-2021-challenges/blob/master/misc/the-
substitution-game/chall.py) for the challenge. My solution script is in the
python file called
[substitution_game.py](https://github.com/qsctr/ctf/blob/master/redpwnCTF-2021/the-
substitution-game/substitution_game.py) and I piped the print output to
```nc``` to automate our solution.

## Explanation  
The challenge gives 6 levels of initial and target strings, where we have to
provide string replacements rules in order to turn the initial strings into
target strings.

Reading the source code, we find that when we supply a string replacement
rule, it uses python's str.replace() function, meaning it will replace all
instances of the string to replace. In addition, we realize that the
replacement rules are called in order and only stops when either the max
iterations has been reached or there are none of the rules cause a
substitution.

For example given:  
```  
aaaaQQaa  
```  
with the rules  
```  
aa => a  
a => c  
```  
leads to the replacements:  
```  
aaaaQQaa # initial  
aaQQa # from rule aa => a  
aQQa # from rule aa => a  
cQQc # rom rule a => c  
cQQc # Final result as the rules don't cause anymore replacements  
```  
### Level 1  
Given the initial and target strings from level 1 (Note this is only a subset
of the strings given):  
```  
Initial string: 00000000000initial000000000000  
Target string: 00000000000target000000000000

Initial string: 00000000000000000initial0000000000  
Target string: 00000000000000000target0000000000

Initial string: 0initial0  
Target string: 0target0  
```  
We can see that if we replace the string 'initial' with 'target', we would
have successfully solved this level. We can provide these string replacement
rules after the prompt  
```  
initial => target  
```

### Level 2  
We are given the strings (again a only a subset is shown):  
```  
Initial string:
ginkoidginkoidginkoidginkoidginkoidginkoidhelloginkoidhelloginkoidginkoidhellohelloginkoidhelloginkoidhello  
Target string:
ginkyginkyginkyginkyginkyginkygoodbyeginkygoodbyeginkyginkygoodbyegoodbyeginkygoodbyeginkygoodbye

Initial string:
hellohellohelloginkoidginkoidginkoidhelloginkoidhellohelloginkoid  
Target string:
goodbyegoodbyegoodbyeginkyginkyginkygoodbyeginkygoodbyegoodbyeginky

Initial string:
helloginkoidhelloginkoidginkoidginkoidginkoidginkoidhelloginkoid  
Target string: goodbyeginkygoodbyeginkyginkyginkyginkyginkygoodbyeginky  
```  
Looking carefully through the texts, we can see giving the rules below should
solve the challenge  
```  
hello => goodbye  
ginkoid => ginky  
```  
### Level 3  
```  
Initial string: aaaaaaaaaaaaaaaaaaaaaaaaaaaa  
Target string: a

Initial string:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  
Target string: a

Initial string:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  
Target string: a  
```  
This level looks interesting, but it was also very easily solved using the
rules:  
```  
aa => a  
aaa => a  
```  
(later I found out that the latter rule wasn't even necessary but this was how
I solved it during the actual challenge)

### Level 4  
```  
Initial string: gggggggggggggg  
Target string: ginkoid

Initial string:
ggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg  
Target string: ginkoid

Initial string: ggggggggggggggggggggggggggg  
Target string: ginkoid  
```  
This level was more interesting, if we just mapped 'g' to 'ginkoid' it would
result in ginkoidinkoidinkoid... as 'g' exists in the word 'ginkoid'. Perhaps
a better approach is needed. Ah, of course! We can map the 'g's to a different
character first. So with this idea, we can first map 'gg' to a different
character (in this case 'zz'), then shrink that character as we did in Level 3
and then convert it to ginkoid:  
```  
gg => z  
zz => z  
zg => ginkoid  
z => ginkoid  
```

### Level 5  
```  
Initial string: ^0100111111110010111100001001001000011110100111111110010$  
Target string: palindrome

Initial string:
^00101101101100000100001010111000101011001101010001110011100110110010101110110100100110101$  
Target string: not_palindrome

Initial string:
^000101100000010100111001110001111011110110010001010100010011011110111100011100111001010000001101000$  
Target string: palindrome

Initial string:
^0001101011011101010100101001000011101000110100101110000100001110011111100101100110$  
Target string: not_palindrome  
```  
Uh oh. This looks significnatly more difficult than level 4. We tried a few
ideas with trying to check if both ends of the string were the same character,
but that failed. Then we remembered that the one way of checking for
palindromes was find the middle of the string and check outwards. Now with our
string replacement rules, checking outwards should be easy as we can check via
'1anything1' and '0anything0', and simply change the middle to something else
(thus marking the string as not a palindrome). But moving the caret and the
dollar sign to the middle of the string was a more daunting task than we
expected.

The clever idea came to me of shifting the caret by one character, shifting
the dollar sign by one character while marking both of them so they don't keep
moving, and finally reset both of them to its orginal state.

```  
# Handle not_palindrome state  
1not_palindrome0 => not_palindrome  
0not_palindrome1 => not_palindrome  
1not_palindrome1 => not_palindrome  
0not_palindrome0 => not_palindrome

# Handle palindrome case, if two sides don't match goto not_palindrome state  
1palindrome0 => not_palindrome  
0palindrome1 => not_palindrome  
1palindrome1 => palindrome  
0palindrome0 => palindrome

# If the caret and dollar sign are in the middle of the string, goto
palindrome state  
^$ => palindrome  
^1$ => palindrome  
^0$ => palindrome

# Shift caret and dollar sign towards center and using the character 'z' to
shift only by one character  
^0 => 0^z  
0$ => z$0  
^1 => 1^z  
1$ => z$1

# If it's not palindrome or not_palindrome state and the caret and dollar sign
have both moved one character, then flush 'z' so the caret and dollar sign can
move again  
z =>  
```

### Level 6  
```  
Initial string: ^110101+011010000=100000101$  
Target string: correct

Initial string: ^110001+10101011=1011011100$  
Target string: incorrect

Initial string: ^11110010+1001101=10110101$  
Target string: incorrect

Initial string: ^111000+101000=1100000$  
Target string: correct  
```  
Huhh? Checking if binary addition is correct? Where in the world would we even
begin? This level took me several hours as my teammates started working on
other challenges. The key to do the addition was realize that for string
replacements, the only way to check for things like equality is if they are
right next to each other (at least I couldn't think of a way to do so). Thus
this observation gives us that in order to do the addition, we need the least
significant digits right next to each other.

So the idea is this, say we have the binary digits in the form of
'^abc+def=xyz$' (assume each alphabet is either a 1 or 0). We want 'c' and 'f'
to be next to each other. We can do this by shifting 'def' past 'c' until 'c'
and 'f' are adjacent like the following (Note the spaces are used for
clarification and not actually part of the solution):  
```  
^abc+def=xyz$  
^ab+de fcadd=xyz$  
```  
where 'fcadd' means we want to add 'f' and 'c'.

This in essence, allows us to add the last two digits (along with any
carries!) before we proceed to the next signficant digit. For my answer, I
used the notations ans0, ans1 to represent 0 and 1 respectively, and car0 to
represent a carry. We can repeat this process (Note the spaces are used for
clarification and not actually part of the solution):  
```  
^ab+de ans0 =xyz$ # say we get 0 from 'f' + 'c'  
^a+d ebadd ans0=xyz$ # shift the new least signficant number  
^a+d ans1 ans0=xyz$ # say we get 1 from 'e' + 'b'  
^adadd ans1 ans0=xyz$ # shift the new least significant number  
^car0 ans1 ans0=xyz$ # say we get a carry from 'd' + 'a'  
```  
Now all we have to do is look at the answers, do the carries and then do the
equality check. Seems simpler right?

The carries and binary addition was manipulating a lot of states that I won't
get into too much detail as it's just binary addition. You can look at my
final solution below to get a better sense of it. Essentially, I convert
everything into symbols like ans0, ans1, car0, car1 (where ans are normal 0s
and 1s and car are for carries). Then I clean up the ans and cars by
converting it to normal binary, while dealing with the carries, thus we are
left with: '^abc=def$'

For checking equality, unlike the palindrome, we have to check starting at the
ends and not the middle. I couldn't think of anything fancy and so I did the
same thing I did for addition and essentially shifted 'def' forwards into
'abc' but kept the least signficant digits, so I can test for equality. (Note
the spaces are used for clarification and not actually part of the solution)  
```  
^abc=def$ # after summing  
^abc eqZ def$ # add delimiter 'Z' to separate 'abc' from 'def'

# Equal case:  
^abZde faeq$ # Shift second number left, leaving least signficant digit  
^abZde$ # if 'f' == 'a' then flush 'faeq'  
^abZeqde$ # add 'eq' back into the string to repeat  
^aZe dbeq$ # if 'd' == 'b' then flush 'dbeq'  
^aZeqe$ # add 'eq' back and repeat  
^Z aeeq$ # if 'e' == 'q' then flush 'aeeq'  
^Z$ # The two strings are equal!, so replace this with 'correct'!

# Unequal case:  
^abZde faeq$ #  if 'f' != 'a' then turn into 'incorrect'  
^abZde incorrect$ # Let 'incorrect' eat all characters in front of it  
^abZd incorrect$ # gobble those characters!  
^abZ incorrect$  
^ab incorrect$  
^a incorrect$  
^incorrect$ # now remove the '^' and '$' and voila! 'incorrect'!  
```

Our final solution looks like this:  
```  
# add extra symbols so we can manipulate them more, 'T' is used to mark how
far have we converted our ans/car symbols into 0s and 1s  
= => TeqZ  
^+ => ^

# f will help us denote the most significant digit of our second number (so we
can place the + back here after we finished adding the least significant
digit)  
+ => addf

# Shift all the digits from the second number ahead of the 'add', 'f' is used
as a separater between the first and second number  
0addf => f0add  
1addf => f1add  
0add0 => 00add  
0add1 => 10add  
1add0 => 01add  
1add1 => 11add

# Add the digits accordingly  
00add => ans0  
01add => ans1  
10add => ans1  
11add => car0

# This implies we are done adding so we can just directly convert to its
respective 0/1  
1add => 1  
0add => 0

# If we hit f, this means the first number is longer than the second number,
so extend the second number with a 0  
fans => f0ans  
fcar => f0car

# Reset 'f' with '+' so we can add the more significant digits  
f => +

# This means we are done adding as the first number is used up, and so we can
just place 0  
^f => ^0

# Convert the respective ans0, ans1, car0, car1 cases while shifting 'T',
which marks our progress of our translation from our symbols to actual 0s and
1s  
ans0T => T0  
ans1T => T1  
car0car0T => car1T0  
ans0car0T => T10  
ans1car0T => car0T0  
ans0car1T => T11  
ans1car1T => car0T1  
car1car0T => car1T0  
car0car1T => car1T1

# Handle carries when the first number is longer than the second number  
0car0 => 10  
1car0 => car00  
0car1 => 11  
1car1 => car01  
car0 => 10  
car1 => 11

# Flush 'T' as we don't need it anymore  
T =>

# Shift all the digits from the second number ahead of the 'eq', 'Z' is used
as a separater between our summed and number checked in the equality  
0eqZ => Z0eq  
1eqZ => Z1eq  
0eq0 => 00eq  
0eq1 => 10eq  
1eq0 => 01eq  
1eq1 => 11eq

# If all digits have matched up, then it is correct!  
^Z$ => correct

# Gobble up those digits if a digit didn't match up!  
0incorrect => incorrect  
1incorrect => incorrect  
Zincorrect => incorrect  
^incorrect$ => incorrect

# Flush the 'eq' if the digits match up  
00eq =>  
11eq =>

# Enter an incorrect state if the digits don't match up  
10eq => incorrect  
01eq => incorrect

#  
^Z => ^0Z  
Z$ => Z0$

# reset 'Z' so we can do more equality checkings  
Z => eqZ  
```  
And that's it! After solving these six levels (phew that took a while), we
finally get our flag:  
```  
flag{wtf_tur1n9_c0mpl3t3}  
```

Huhh?? Turing complete? I didn't know that... hmm guess I should work up my CS
theory.  

Original writeup (https://github.com/qsctr/ctf/tree/master/redpwnCTF-2021/the-
substitution-game).