# yellsatjavascript - Misc (364 pts)

## Description  
> JavaScript is cursed :(  
>  
> nc yellsatjavascript.wolvctf.io 1337

### Provided files  
chall.js - the node JavaScript source code for the server
\[[download](https://ctfnote.shinmai.wtf:31337/files/downloadFile?id=K0CJi1HlYMoAuEz)\]

## Ideas and observations  
1. the code gets an input from the user, does some checks on it and if they pass, passes it to `eval()`  
2. the flag is stored in a variable called `flag`  
3. the checks are:  
   1. input musn't contain the character sequence "flag"  
   2. input musn't contain the character `.`  
   3. input musn't containt curly braces

## Notes  
1. we need access to `console.log()` to print output  
2. we need to obfuscate `flag` to pass it to `console.log()`  
3. besides the dot notation, another way to access prototype members/object properties in JavaScript is array keys: `object['property']`  
4. `btoa()` and `atob()` are built-in functions for base64

## Solution  
1. combining the previous knowledge, seding `console['log'](eval(atob('ZmxhZw==')))`, with `ZmxhZw==` being `flag` base64 encoded, gets us the flag

`wctf{javascript_!==_java}`

Original writeup
(https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469#yellsatjavascript
---misc-364-pts).