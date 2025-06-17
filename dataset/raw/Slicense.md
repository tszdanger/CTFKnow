# Slicense  
Rev, 60 points

## Description  
Break the egg! https://ctf.kaf.sh:1160

## Solution  
We used jadx to disassemble the app. Searching for strings we saw in the UI we
found that the app gui is in a webview.  
Looking at the code we found the javascript interfaces and other strings which
pointed us to potentialy interesting functions.  
We looked for functions that received input and checked if it was valid.  
Then we found the object `a.c.a.a.i` and its function `a`. This functions
receives a string input and returs a boolean. Using frida we could see that if
we changed the return value to true the gui would show a fake success.

We analyzed the function and concluded:  
1. The input is made out of 8 parts seperated by a `-`  
2. Each part is made out of 4 bytes   
3. The last byte of the 4 is derrived from bytes 2 and 3  
4. the first byte is prefined from some value which is set to `F00Bar?!F00Bar?!`  
If not following these rules, the function will return false immediately
skipping most of the functionallity

So now we know to build an input but what input is the correct input?  
The second half seems to be encrypting something. Hooking the relevant
functions in frida revealed that they used AES/CBC with no padding. This iv is
set to (again) to `F00Bar?!F00Bar?!` and the key is static even though it
looks like it might be random.  
All we need to do is decrypt the value from the end of the function and see
the corresponding input!  
Doing that shows a success message, the app shuts down and when openning it
again the flag is displayed.

The Flag: `KAF{S0_many_layr3s_399_crack3d}`  

Original writeup
(https://github.com/bitterbit/ctf/tree/master/kipofafterfree-2019/slicense).