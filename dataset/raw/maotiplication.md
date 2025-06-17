## Task  
```diff  
its time to get funky and maotiply

This interpreter takes a series of string substitutions and executes them on
input strings sequentially.

Please enter your substitution rules in sequential order, one per line.
Terminate your rules sequence with the string 'EOF'. DO NOT SEND AN ACTUAL
EOF.

The rule format is SEARCH:REPLACE. A double colon (SEARCH::REPLACE) can be
used to create a terminating rule. If a terminating substitution rule is
executed, the interpreter will not process any further substitutions.

If SEARCH is an empty string, then REPLACE will be inserted at the beginning
of the input string instead.

For further clarification of interepter behavior, feel free to read the
source.

For each round, a short description of the intended behavior will be provided.
Additionally, several examples will be supplied. Your task is to devise a
series of substitutions to accomplish this behavior.

Good luck!  
```  
Note. "interepter" is a typo.  
## General Analysis

In `interpreter.py` we can see how string replacement works. It iterates each
rule one by one, **by input order**. Remember, that **order of applying rules
is quite important.**

Both `SEARCH` and `REPLACE` can be empty string. This is useful in _Round 1_,
and also in other rounds!

## Before You Read

### This writeup is quite long.

- Maybe you can understand the whole logic by reading **Summary** and **Examples** only; so I brought it to the top.  
- If not, quickly read the bold things of **Drawing the Picture**.  
- If still not, read everything.  
- **In any case, I recommend you to copy-paste the answer part and open it at the right;** that's how I wrote this writeup.

Take a deep breath!

Are you ready? Let's go.

## Round 1

### Description  
```diff  
Round 1:

Replace (possibly repeated) instances of "strellic" with a single instance of
"jsgod".

'strellicstrellicstrellicstrellicstrellicstrellicstrellicstrellic' => 'jsgod'

'strellic' => 'jsgod'

'strellicstrellic' => 'jsgod'

'strellicstrellicstrellicstrellicstrellicstrellicstrellicstrellicstrellic' =>
'jsgod'

'strellicstrellicstrellicstrellicstrellicstrellicstrellicstrellic' => 'jsgod'

Constraints: 5 rules, 20 substitutions  
```  
### Explanation  
We can make this string empty, by repeating Rule `strellic:`. After that,
apply Rule `::jsgod`, which adds `jsgod` in string and terminates.  
### Answer (2/5 rules, max 11/20 substitutions)  
```diff  
strellic:  
::jsgod  
EOF  
```

## Round 2  
### Description  
```diff  
Round 2:

Perform XOR on the two supplied numbers.

'11010001^1101000' => '10111001'

'10101010^11111100' => '1010110'

'110101^11000011' => '11110110'

'11011110^1111110' => '10100000'

'1001110^10001' => '1011111'

Constraints: 50 rules, 120 substitutions  
```  
### Explanation  
For _Round 2_ and _Round 3_, we need to draw a big picture. This stuff is
something like _a Turing Machine_. We will use **various characters** so that
we can identify the current state by the first rule that match.

#### Summary  
- `^`: The initial XOR operator. Sends the last digit of `P` as `0^:#a, 1^:#b`  
   - `#`: Alt form of `^`. `#:^` is applied when the digit process is finished.  
- `%`: Separates `Q` and current answer.  
- `ab`: The (encrypted?) last digit of `P`.

#### Examples  
```diff  
1101000 1^ 1101000  
1101000 #b 1101000      (Rule 1-2)  
1101000 # 110100 0b     (Rule 3-6)  
1101000 # 110100 %1     (Rule 11-14)  
110100 0^ 110100 % 1    (Rule 20)  
110100 # 11010 0a% 1    (Rule 1-6)  
110100 # 11010 %0 1     (Rule 7-10)  
110100 ^ 11010 % 01     (Rule 20)  
...  
1#% 0111001             (Rule 1-14, 20)  
#%1 0111001             (Rule 15-16)  
10111001                (Rule 17, TERMINATED)  
------------------------------------------------------------  
110101 ^ 11000011  
...  
^ 11 % 110110           (Rule 1-14, 20)  
* 11 % 110110           (Rule 21)  
11 *% 110110            (Rule 22-23)  
11110110                (Rule 24, TERMINATED)  
------------------------------------------------------------  
1111 ^ 1111  
...  
#% 0000                 (Rule 1-14, 20)  
#%                      (Rule 17-18)  
0                       (Rule 19, TERMINATED)  
```

#### Drawing the Picture  
Let the first number `P`, and second number `Q`. Last digit of `P` should be
XORed with last digit of `Q`. So we will **"send" the last digit of `P` to the
end of the string**. While sending, **replace them as `0->a, 1->b`**, so that
we can distinguish that digit from original digits of `Q`. Also, **change `^`
to `#`** and we can know if the "sending process" is in progress.

After that, we will **XOR** the last two. This digit is indeed the last digit
of answer, so fix it. But how? **Use character `%` to represent the "done
part".** Digits after `%` indicates the last digits of answer.

Now check how the string changes. (Added spaces just for readability; in
actual answer I do NOT use spaces)  
```diff  
11010001 ^ 1101000  
1101000 #b 1101000  
1101000 # 110100 0b  
1101000 # 110100 % 1  
```  
We do this over and over, by changing `#` to `^`, until:  
1. `P` is empty (i.e. no `0^` nor `1^`), or  
1. `Q` is empty (i.e. `#%`), or  
1. both `P` and `Q` is empty (also `#%`)

```diff  
11010001 ^ 1101000  
1101000 # 110100 % 1  
...  
1 # % 0111001  
-----------------------  
110101 ^ 11000011  
^ 11 % 110110  
```

For _Case 1_, we replace `^` to `*`, and let `*` meet `%` at the middle. Add
terminate rule `*%::` and we are finished.  
```diff  
^ 11 % 110110  
* 11 % 110110  
11 *% 110110  
11110110  
```  
For _Case 2_ and _Case 3_, we send remaining digits of `P` (if exists). Then,
remove some leading zeros. Be careful when the answer is exactly 0, since the
final string should be `0`, not the empty string. Hence we need 2 terminate
rule: `#%1::1` and `#%::0`  
```diff  
1 # % 0111001  
#% 10111001  
10111001  
-----------------------  
#% 0000000  
#%  
0  
```

#### Solution Details  
##### Rule 1-2: `0^:#a 1^:#b`  
- Begin the sending process.

##### Rule 3-6: `a0:0a a1:1a b0:0b b1:1b`  
- Send `a` or `b` to the back of `Q`.

##### Rule 7-10: `0a%:%0 0b%:%1 1a%:%1 1b%:%0`  
- **Calculate XOR** of last digit of `P` and `Q`, and add it to current answer.  
- There are 2 groups of this type. Difference is **the existence of `%` in the current string.**  
- **These rules should come before Rule 11-14**, since their `SEARCH` string, `0a 0b 1a 1b`, is a prefix of these.

##### Rule 11-14: `0a:%0 0b:%1 1a:%1 1b:%0`  
- Same as **Rule 7-10**. Difference explained above as well.

##### Rule 20: `#:^`  
- Indicates that the current "wave" is over, and go on for the next digit.  
- `#%` indicates the wrap-up process. Since `#` is prefix of `#%`, `#%`-related rules should go first. (**Rule 15-19**)

##### Rule 15-16: `0#%:#%0 1#%:#%1`  
- **Wrap-up process for _Case 2_ and _Case 3_.**  
- Send remaining digits of `P` to the right, if exists.

##### Rule 17-19: `#%1::1 #%0:#% #%::0`  
- Remove **leading zeros** of answer. Whenever `#%` meets `1`, remove itself and terminate.  
- If all the digits are removed and only `#%` left, **the answer is 0.** Replace it to `0` and terminate.

##### Rule 21: `^:*`  
- **Wrap-up process for _Case 1_.**

##### Rule 22-24: `*0:0* *1:1* *%::`  
- Move `*` to the right until it meets `%`.  
- Remove `*%` together and terminate.

### Answer (24/50 rules, max 68/120 substitutions)  
```diff  
0^:#a  
1^:#b  
a0:0a  
a1:1a  
b0:0b  
b1:1b  
0a%:%0  
0b%:%1  
1a%:%1  
1b%:%0  
0a:%0  
0b:%1  
1a:%1  
1b:%0  
0#%:#%0  
1#%:#%1  
#%1::1  
#%0:#%  
#%::0  
#:^  
^:*  
*0:0*  
*1:1*  
*%::  
EOF  
```  
## Round 3: THE ULTIMATE TASK  
### Description  
```diff  
Round 3:

Perform multiplication on the two provided numbers.

'101011x11000101' => '10000100010111'

'11101000x111111' => '11100100011000'

'11011x101011' => '10010001001'

'1100111x110110' => '1010110111010'

'1111111x11011101' => '110110110100011'

Constraints: 100 rules, 2500 substitutions  
```  
### Explanation  
#### Rule of Thumb: How to _maotiplicate_ two numbers  
Simple math. We do something like this...  
```diff  
     11011  
x    101011  
------------  
     11011  
    11011  
       0  
  11011  
     0  
11011  
------------  
10010001001  
```

Unfortunately, we need **addition**. Addition is similar to XOR, **except that
we need to take care of the carry**. Anyways it takes only 24+2 rules for our
addition. :)

#### Summary  
```diff  
P x Q * Q' % R    ------------>    P x Q * P' + Q' % R    (P' = Q or 0...0)  
```  
- `x`: The initial _MAOTIPLY_ operator. Sends the last digit of `P` as `0x:#a, 1x:#b`.  
   - `#`: Alt form of `x`. `#:x` is applied when the digit process is finished.  
- `*`: Separates `Q` and "flexible part" of answer.  
   - `&`: Alt form of `*`. Moves `c` and `d` to the right, and after the addition, change to `*$` so that we can fix the rightmost digit.  
   - `$`: Temporal character to fix the rightmost digit.  
- `+`: _THE PLUS OPERATOR_. Adds two numbers, literally. Sends the last digit of `P'` as `0+:@g, 1+:@h`.  
   - `@`: Alt form of `+`. `@:+` is applied when the digit process is finished.  
   - `~`: Separates `Q'` and the "fixed part" of addition result.  
- `%`: Separates "flexible part" and "fixed part" of answer.  
- `ab`: Indicates the last digit of `P`.  
- `cd`: Product of `Q` and "last digit of `P`".  
- `ghi`: Indicates the last digit of `P'` (plus the carry)  
- `p`: Carry (Addition).

#### Examples  
```diff  
1101 1x 101011  
1101 #b 101011                      (Rule 1-2)  
1101 # 1d0c1d0c1d1d b               (Rule 3-6)  
1101 # 101011 dcdcd db              (Rule 7-10)  
1101 # 101011 dcdcd &1              (Rule 15-18)  
1101 # 101011 & 101011              (Rule 19-20)  
1101 # 101011 *$ 101011             (Rule 47)  
1101 # 101011 * 10101 1$            (Rule 48-49)  
1101 # 101011 * 10101 %1            (Rule 52-53)  
110 1x 101011 * 10101 % 1           (Rule 54)  
110 #b 101011 * 10101 % 1           (Rule 1-2)  
110 # 101011 dcdcd db* 10101 % 1    (Rule 3-10)  
110 # 101011 dcdcd &1+ 10101 % 1    (Rule 11-14)  
110 # 101011 & 101011 + 10101 % 1   (Rule 19-20)  
+--------A d d i t i o n--------+   [Rule 21-46]  
| 10101 1+ 10101                |  
| 10101 @h 10101                |   (Rule 23-24)  
| 10101 @ 1010 1h               |   (Rule 25-28)  
| 10101 @ 1010 p~0              |   (Rule 37-40)  
| 1010 1+ 1010p ~ 0             |   (Rule 44)  
| 1010 @ 1010 hp ~ 0            |   (Rule 23-28)  
| 1010 @ 101 0i~ 0              |   (Rule 29-30)  
| 1010 @ 101 p~0 0              |   (Rule 31-36)  
| 101 0+ 101p ~ 00              |   (Rule 44)  
| ...                           |  
| 1+ p ~ 00000                  |   (Rule 23-40, 44)  
| @ hp ~ 00000                  |   (Rule 23-24)  
| @i~ 00000                     |   (Rule 30)  
| 1000000                       |   (Rule 41-43)  
+--E n d  O f  A d d i t i o n--+  
110 # 101011 & 1000000 % 1  
110 # 101011 *$ 1000000 % 1         (Rule 47)  
110 # 101011 * 100000 0$% 1         (Rule 48-49)  
110 # 101011 * 100000 %0 1          (Rule 50-51)  
110 x 101011 * 100000 % 01          (Rule 54)  
...  
x101011 * 100100 % 01001  
x*100100 % 01001                    (Rule 55-56)  
x*10010001001                       (Rule 57)  
10010001001                         (Rule 58-60, TERMINATED)  
```  
omitted some special rules like 21-22, 45-46.  
#### Drawing the Picture  
```diff  
P x Q * Q' % R    ------------>    P x Q * P' + Q' % R    (P' = Q or 0...0)  
```  
**Basics are same. Details(`a b c d` things) are almost same.** Send last
digit of `P` to the back, _do some process_, fix the last digit, and again.
The thing is that **_THE PROCESS_ is a little bit harder...**

**_Maotiply_ last digit of `P` with `Q`.** This process is easy(_but still 8
rules required_), since the result is always `Q` or `0`. Let `P'` the result
of this _maotiplication_. Calculate `P' + Q'`(_oh, that's an **addition**_).
Now we got **the last digit of the answer. Fix it with `%`.**

We will talk about _addition_ later. For now, just think about how to wrap-up.
We do the process above, over and over, by changing `#` to `x`, **until... `P`
is empty.** (_No case work! hooray!_)  
```text  
11011 x 101011  
1101 x 101011 * 10101 % 1  
110 x 101011 * 100000 % 01  
...  
x 101011 * 100100 % 01001  
```  
Okay, so what's the answer? `10010001001`. Yes! **Just concatenate the last
two numbers and terminate!** (Q: Why does it work? A: _The Rule of Thumb._)

Addition of `P'` and `Q'`. Almost same as XOR, except for two additional
alphabets, `i` and `p`. First, `p` is **the carry of the addition.** Every
time the sum of single digit exceeds 2, carry is set and there will be `p` in
somewhere. `p` **upgrades the last digit of `P'`.** `g(=0)` to `h(=1)`, and
`h(=1)` to... `i(=2)`.

If we make `P'=0...0` when _maotiplying_ 0, we can prove that `len(P') =
len(Q')` or `len(P') = len(Q') + 1`. This can possibly reduce some case work.  
```diff  
101011 + 11011  
10101 @h 11011  
10101 @ 1101 1h  
10101 @ 1101 p~0  
1010 1+ 1101 p ~ 0  
1010 @h 1101 p ~ 0  
1010 @ 1101 hp ~ 0  
1010 @ 110 1i~ 0  
1010 @ 110 p~1 0  
1010 + 110 p ~ 10  
101 + 11 ~ 110  
10 + 1 p ~ 0110  
1 + p ~ 00110  
@ hp ~ 00110  
@i~ 00110  
10 00110  
```  
#### Solution Details

##### Rule 1-2: `0x:#a 1x:#b`  
- Begin the sending process for _maotiplication_.

##### Rule 3-6: `a0:0ca a1:1ca b0:0cb b1:1db`  
- Send `a` or `b` to the back of `Q`, but this time for each digit **we _maotiply_ and make something like `c` or `d`.**

##### Rule 7-10: `c0:0c c1:1c d0:0d d1:1d`  
- Send the _maotiply_ results to the back of `Q`.

##### Rule 11-14: `ca*:&0+ cb*:&0+ da*:&1+ db*:&1+`  
- Initial process of moving `P'`. In this case `*` exists, so `+` sign goes together.(`P # Q & P' + Q' % R`)  
- **These rules should come before Rule 15-18.**

##### Rule 15-18: `ca:&0 cb:&0 da:&1 db:&1`  
- Initial process of moving `P'`. In this case `*` does not exist, so no addition needed.(`P # Q & P'`)

##### Rule 19-20: `c&:&0 d&:&1`  
- move the remaining parts of `P'`.

#### Rule 21-46: ADDITION (`P' + Q'`)

##### Rule 21-22: `&0+%:*%0 &1+%:*%1`  
- handling zero-length numbers. This happens when `Q < 2`.

##### Rule 23-24: `0+:@g 1+:@h`  
- Begin the sending process for addition.

##### Rule 25-28: `g0:0g g1:1g h0:0h h1:1h`  
- Send `g` or `h` to the back of `Q'`.

##### Rule 29-30: `gp:h hp:i`  
- Update last digit of `P'` with `p`.

##### Rule 31-36: `0g~:~0 1g~:~1 0h~:~1 1h~:p~0 0i~:p~0 1i~:p~1`  
- Add last digit of `P'` and `Q'`. and put it back to the `~`.

##### Rule 37-40: `0g:~0 1g:~1 0h:~1 1h:p~0`  
- Add last digit of `P'` and `Q'`, and make `~` to put the result to the back.

##### Rule 44: `@:+`  
- Indicates the end of current "wave" **for addition**, and go on for the next digit  
- `@g~, @h~, @i~` rules should go first (**Rule 41-43**)

##### Rule 41-43: `@g~:0 @h~:1 @i~:10`  
- Terminate the addition process. (Case when `len(P') = len(Q') + 1`)

##### Rule 45-46: `+p~:1 +~:`  
- Terminate the addition process (Case when `len(P') = len(Q')`)

(End of Addition)

##### Rule 47-49: `&:*$ $0:0$ $1:1$`  
- Send `$` to the back of `Q'`.

##### Rule 50-53: `0$%:%0 1$%:%1 0$:%0 1$:%1`  
- Fix the last digit. We can check the last digit by `$`.

##### Rule 54: `#:x`  
- Indicates the end of current "wave" **for _maotiplication_**, and go on for the next digit.

##### Rule 55-56: `x0:x x1:x`  
- **Now `x` becomes a monster.** It removes all digits between `x` and `*`.

##### Rule 57: `%:`  
- Remove `%` so that we **concatenate** the two numbers.

##### Rule 58-60: `x*0:x* x*1::1 x*::0`  
- Remove **leading zeros** of answer. Whenever `x*` meets `1`, remove itself and terminate.  
- If all the digits are removed and only `x*` left, **the answer is 0.** Replace it to `0` and terminate.

### Answer (60/100 rules, max 931/2500 substitutions)  
```diff  
0x:#a  
1x:#b  
a0:0ca  
a1:1ca  
b0:0cb  
b1:1db  
c0:0c  
c1:1c  
d0:0d  
d1:1d  
ca*:&0+  
cb*:&0+  
da*:&1+  
db*:&1+  
ca:&0  
cb:&0  
da:&1  
db:&1  
c&:&0  
d&:&1  
&0+%:*%0  
&1+%:*%1  
0+:@g  
1+:@h  
g0:0g  
g1:1g  
h0:0h  
h1:1h  
gp:h  
hp:i  
0g~:~0  
1g~:~1  
0h~:~1  
1h~:p~0  
0i~:p~0  
1i~:p~1  
0g:~0  
1g:~1  
0h:~1  
1h:p~0  
@g~:0  
@h~:1  
@i~:10  
@:+  
+p~:1  
+~:  
&:*$  
$0:0$  
$1:1$  
0$%:%0  
1$%:%1  
0$:%0  
1$:%1  
#:x  
x0:x  
x1:x  
%:  
x*0:x*  
x*1::1  
x*::0  
EOF  
```  
Spending lot of time solving the problem, and writing this stuff, but still I
love this problem :)  
## Flag  
`corctf{qu1nt3c_w0u1d_b3_pr0ud}`