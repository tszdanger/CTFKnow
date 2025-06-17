# LYCH King  
[Original writeup
here](https://ohaithe.re/post/624092576653426688/rgbctf-2020-writeups/)

In retrospect, perhaps this should have been done black-box, like almost
everything in this category (ARM1/ARM2/SadRev1/SadRev2) was. But hey, who
doesn't want to reverse compiled Haskell?

Yeah, this binary is Haskell that was compiled by GHC. That might be
reasonably accessible to you, if you (1) know Haskell, (2) know how STG
machines work, and (3) know GHC's conventions for storing thunks and STG type
data. I meet, like, 0.5/3 requirements.

Goolging for "Haskell decompiler" quickly turns up
[https://github.com/gereeter/hsdecomp] as exactly what we need: a decompiler
for GHC-compiled 64-bit executables. Great! Let's try it out!

```  
$ python3 runner.py ../../rgbctf/lych/lich  
Error in processing case at c3uZ_info  
   Error:  
   Error Location: 140  
   Disassembly:  
       mov	rax, qword ptr [rbp + 8]  
       mov	rcx, rbx  
       and	ecx, 7  
       cmp	rcx, 1  
       jne	0x407d33  
       add	r12, 0x18  
       cmp	r12, qword ptr [r13 + 0x358]  
       ja	0x407d48  
       mov	qword ptr [r12 - 0x10], 0x407c28  
       mov	qword ptr [r12], rax  
       lea	rbx, [r12 - 0x10]  
       mov	rsi, rbx  
       mov	r14, rax  
       mov	ebx, 0x4bd600  
       add	rbp, 0x10  
       jmp	0x49cf08

Main_main_closure = >>= $fMonadIO getArgs (\s3mc_info_arg_0 -> $ putStrLn
((\Main_a_info_arg_0 -> !!ERROR!!) (head s3mc_info_arg_0))  
```

The results are a bit disappointing. It got as far as recognizing that the
program is printing out some function of the input, but then it errored. How
do we handle errors? We comment them out!

[https://github.com/Timeroot/hsdecomp/commit/a9244145d89019b2e8b0f45a9e23f5c043ec8155]

Basically forcing the decompiler to plow through broken stuff. (We also fix
one incorrect assumption about `jae` being the only branch used in a certain
type of case statement.) We definitely don't get correct decompilation, but we
get a lot more than before.

```  
Main_main_closure = >>= $fMonadIO  
   getArgs  
   (\s3mc_info_arg_0 ->  
       $  
           putStrLn  
           ((\Main_a_info_arg_0 ->  
               case == r3jo_info Main_a_info_arg_0 [] of  
                   c3uZ_info_case_tag_DEFAULT_arg_0@_DEFAULT -> zipWith (on (\s3m3_info_arg_0 s3m3_info_arg_1 s3m3_info_arg_2 s3m3_info_arg_3 s3m3_info_arg_4 -> . (\s3m1_info_arg_0 s3m1_info_arg_1 s3m1_info_arg_2 s3m1_info_arg_3 s3m1_info_arg_4 -> fmap $fFunctor-> chr) (\s3m2_info_arg_0 s3m2_info_arg_1 s3m2_info_arg_2 s3m2_info_arg_3 s3m2_info_arg_4 -> xor $fBitsInt)) ord)  
                       Main_a_info_arg_0  
                       ((\Main_g_info_arg_0 Main_g_info_arg_1 ->  
                           case == r3jo_info Main_g_info_arg_0 [] of  
                               c3se_info_case_tag_DEFAULT_arg_0@_DEFAULT -> take (length $fFoldable[] Main_g_info_arg_0) (intercalate [] (map (\s3lV_info_arg_0 s3lV_info_arg_1 s3lV_info_arg_2 s3lV_info_arg_3 s3lV_info_arg_4 -> show $fShowInteger) (Main_v_info Main_g_info_arg_1 (length $fFoldable[] Main_g_info_arg_0) (S# 0))))  
                       )  
                           Main_a_info_arg_0  
                           (S# 1997)  
                       )  
           )  
               (head s3mc_info_arg_0)  
           )  
   )  
r3jo_info = $fEq[] $fEqChar

Main_v_info = \Main_v_info_arg_0 Main_v_info_arg_1 Main_v_info_arg_2 ->  
   case == $fEqInteger Main_v_info_arg_0 (Main_r_info Main_v_info_arg_0) of  
       c3qB_info_case_tag_DEFAULT_arg_0@_DEFAULT -> case >= $fOrdInteger Main_v_info_arg_2 (toInteger $fIntegralInt Main_v_info_arg_1) of  
           c3qM_info_case_tag_DEFAULT_arg_0@_DEFAULT -> : Main_v_info_arg_0 (Main_v_info ((\Main_p_info_arg_0 -> + $fNumInteger Main_p_info_arg_0 (Main_r_info Main_p_info_arg_0)) Main_v_info_arg_0) Main_v_info_arg_1 (+ $fNumInteger Main_v_info_arg_2 (Main_mag_info Main_v_info_arg_0)))

Main_mag_info = \Main_mag_info_arg_0 ->  
   case == $fEqInteger Main_mag_info_arg_0 (S# 0) of  
       c3mD_info_case_tag_DEFAULT_arg_0@_DEFAULT -> case > $fOrdInteger Main_mag_info_arg_0 (S# 0) of  
           c3mI_info_case_tag_DEFAULT_arg_0@_DEFAULT -> case < $fOrdInteger Main_mag_info_arg_0 (S# 0) of  
               c3nk_info_case_tag_DEFAULT_arg_0@_DEFAULT -> patError 4871050

Main_r_info = \Main_r_info_arg_0 ->  
   case == $fEqInteger Main_r_info_arg_0 (S# 0) of  
       c3oc_info_case_tag_DEFAULT_arg_0@_DEFAULT -> + $fNumInteger (* $fNumInteger (mod $fIntegralInteger Main_r_info_arg_0 (S# 10)) (^ $fNumInteger $fIntegralInteger (S# 10) (- $fNumInteger (Main_mag_info Main_r_info_arg_0) (S# 1)))) (Main_r_info (div $fIntegralInteger Main_r_info_arg_0 (S# 10)))  
```

Even if you know Haskell, this is pretty unreadable, because  
* Everything is named very obtusely  
* Everything is pretty in prefix notation (e.g. `+ (f X) ((g h) Y))` instead of `f X + g h Y`)  
* A good chunk of code is missing.

We can't fix the third part, but we can fix the first two, and use our
pRoGraMmErs inTUiTioN to fill in the blanks for the third. Cleaned up:

```  
Main_main_closure = >>= $fMonadIO  
   getArgs  
   (\ARGS ->  
       $  
           putStrLn  
           ((\ARG0 ->  
               case (ARG0 == "") of  
                   __default -> zipWith (on (. (fmap $fFunctor-> chr) (xor $fBitsInt)) ord)  
                       HEAD  
                       ((\HEAD0 YY ->  
                           case (XX == "") of  
                               __default -> take (length HEAD0) (intercalate [] (map show (Function_V YY (length HEAD0) 0)))  
                       )  
                           HEAD  
                           1997  
                       )  
           )  
               (head ARGS)  
           )  
   )

String_Eq = $fEq[] $fEqChar

-- Adds X to its digital reversal, repeatedly, in a loop  
-- Each time it adds the current number of digits in X to Z, a running counter
(starts at 0)  
-- Continues until Z exceeds Y, the limit. Y is the length of HEAD0.  
Function_V X Y Z =  
   case (X == (Function_R X)) of  
       __default -> case (Z >= (toInteger Y)) of  
           __default -> : X (Function_V ((X + (Function_R X))) Y (Z + (Function_mag X)))

-- decompilation broke down here entirely  
-- but based on context, will guess it's the magnitude (Base 10) of A0.  
Function_mag A0 =  
   case (A0 == 0) of  
       __default -> case (A0 > 0) of  
           __default -> case (A0 < 0) of  
               __default -> patError "lich_cipher.hs:(20,1)-(23,15)|function mag"

-- returns R(X/10) + (X%10)*(10^mag(X)).  
-- this computes the _base 10 digit reversal_ of X.  
Function_R X =  
   case (X == 0) of  
       __default -> ( (X mod 10) * (10 ^ ((Function_mag X) - 1))) + (Function_R (X div 10))  
```

So now the operation is pretty clear. It takes a number, 1997, and repeatedly
adds it to its own base-10 reversal. It continues this until (a) it reaches a
palindromic sum or (b) we have more terms than we have characters in our input
string. This is what `Function_V` accomplishes, using `Function_mag` and
`Function_R` as components.

Then `intercalate [] (map show ...)` turns these integers into strings and
joins them. So for the sequence `1997 -> 1997 + 7991 = 9988 -> 9988 + 8899 =
18887 -> ...`, we get the list `["1997", "9988", "18887", ...]`, and then the
string `"1997998818887"...`. The `zipWith ... fmap` structure is a bit obtuse,
but we see `xor`, and `HEAD` (the input) and the digit string, so we can guess
that it's XORing the input with the magic digit string.

A quick trial of the program confirms this. Wow, so it's just XORing the input
with this magic string. Maybe I should have noticed that the program was its
own inverse...? Nah.

So, we have encrypted text, and the program undoes itself. But we're told the
problem "has been changed very slightly" since it was first written. Two
options: patch the program, or reimplement it. Patching it in IDA is easy,
since searching for the bytes `CD 07` (1997 in hex) turns it up right away.
The relevant instruction is at 0x407C57 for those curious. I try a few
different values (1997 is a year, right? So maybe 2020? 2019? 2000? 1996?
1998? Or maybe 2008, the year that the Lich King came out for WoW?) but none
work, and it's kind of slow doing this by patching it in IDA over and over.

So I reimplement the code to try a wide variety of seeds:

```  
img = "./lich"

fh = open('./cipher', 'rb')  
goal = bytearray(fh.read())

fh = open('./uncipher', 'rb')  
other = bytearray(fh.read())

def revDig(num):  
	rev_num=0  
	while (num > 0):   
		rev_num = rev_num*10 + num%10  
		num = num//10  
	return rev_num   
  
# Function to check whether the number is palindrome or not  
def isPalindrome(num):  
	return (revDig(num) == num) 

def getPad(seed):  
	res = ""  
	while not isPalindrome(seed) and len(res) < 1000:  
		res += str(seed)  
		seed += revDig(seed)  
	return res

def xor_b_str(a,b):  
	xored = []  
	for i in range(min(len(a), len(b))):  
		xored_value = a[i%len(a)] ^ ord(b[i%len(b)])  
		xored.append(chr(xored_value))  
	return ''.join(xored)

for seed in range(0,2000):  
	pad = getPad(seed)  
	#print(pad)  
	out = xor_b_str(goal, pad)  
	print(seed)  
	print(out)  
```

Then `python3 reimpl_lich.py | grep -B1 rgb` gives

```  
1495  
Khm'jaeden created the Lich King ages ago from the spirit of the orc shaman
Ner'zhul to raise an undead army to conquer Azeroth for the Burning Legion.
rgbctf{the flag is just rgb lol} Initially trapped within the Frozen Throne
with Frostmourne, the Lich King eventually betrayed Kil'jaeden and merged with
the human Arthas Menethil. When Frostmourne was destroyed and Arthas perished,
Bolvar Fordragon became the new Lich King, imprisoning the master of the
Scourge within the Frozen Throne once more in order to protect the world from
future threats.:  
--  
1585  
Kil'jaeden created the Lich King ages ago from the spirit of the orc shaman
Ner'zhul to raise an undead army to conquer Azeroth for the Burning Legion.
rgbctf{the flag is just rgb lol} Initially trapped within the Frozen Throne
with Frostmourne, the Lich King eventually betrayed Kil'jaeden and merged with
the human Arthas Menethil. When Frostmourne was destroyed and Arthas perished,
Bolvar Fordragon became the new Lich King, imprisoning the master of the
Scourge within the Frozen Throne once more in order to protect the world from
future threats.:  
--  
1675  
Kjc'jaeden created the Lich King ages ago from the spirit of the orc shaman
Ner'zhul to raise an undead army to conquer Azeroth for the Burning Legion.
rgbctf{the flag is just rgb lol} Initially trapped within the Frozen Throne
with Frostmourne, the Lich King eventually betrayed Kil'jaeden and merged with
the human Arthas Menethil. When Frostmourne was destroyed and Arthas perished,
Bolvar Fordragon became the new Lich King, imprisoning the master of the
Scourge within the Frozen Throne once more in order to protect the world from
future threats.:  
--  
1765  
Kkb'jaeden created the Lich King ages ago from the spirit of the orc shaman
Ner'zhul to raise an undead army to conquer Azeroth for the Burning Legion.
rgbctf{the flag is just rgb lol} Initially trapped within the Frozen Throne
with Frostmourne, the Lich King eventually betrayed Kil'jaeden and merged with
the human Arthas Menethil. When Frostmourne was destroyed and Arthas perished,
Bolvar Fordragon became the new Lich King, imprisoning the master of the
Scourge within the Frozen Throne once more in order to protect the world from
future threats.:  
--  
1855  
Kda'jaeden created the Lich King ages ago from the spirit of the orc shaman
Ner'zhul to raise an undead army to conquer Azeroth for the Burning Legion.
rgbctf{the flag is just rgb lol} Initially trapped within the Frozen Throne
with Frostmourne, the Lich King eventually betrayed Kil'jaeden and merged with
the human Arthas Menethil. When Frostmourne was destroyed and Arthas perished,
Bolvar Fordragon became the new Lich King, imprisoning the master of the
Scourge within the Frozen Throne once more in order to protect the world from
future threats.:  
--  
1945  
Ke`'jaeden created the Lich King ages ago from the spirit of the orc shaman
Ner'zhul to raise an undead army to conquer Azeroth for the Burning Legion.
rgbctf{the flag is just rgb lol} Initially trapped within the Frozen Throne
with Frostmourne, the Lich King eventually betrayed Kil'jaeden and merged with
the human Arthas Menethil. When Frostmourne was destroyed and Arthas perished,
Bolvar Fordragon became the new Lich King, imprisoning the master of the
Scourge within the Frozen Throne once more in order to protect the world from
future threats.:  
```

and we have a flag. And in fact, a number of other seeds would have worked
too, it seems. It was just shortly after solving that I realized why 1997:
googling "reverse digits and add" yields
[https://en.wikipedia.org/wiki/Lychrel_number], which is about the process
involved here. 1997 is a seed that generates an (apparently) infinite sequence
of numbers. The functioning seeds are all also *Lych*rel numbers, hence the
name of the challenge.

Original writeup
(https://ohaithe.re/post/624092576653426688/rgbctf-2020-writeups).