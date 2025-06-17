# escaped - Beginner (50 pts)

## Description  
> nya  
>  
> nc escaped.wolvctf.io 1337

### Provided files  
`jail.py` - the Pyhon script running on the server
\[[download](https://ctfnote.shinmai.wtf:31337/files/downloadFile?id=scxfFwUWyt42tUf)\]  
`Dockerfile` - the Dockerfile for the container hosting the script
\[[download](https://ctfnote.shinmai.wtf:31337/files/downloadFile?id=mV6tR8MaFrMs3Am)\]

## Ideas and observations  
1. the script is a very simple Pyhon jail that takes user input, checks if for some syntax requirements, passes it to `eval()` inside an `ast.compile()` call that compiles an AST that prints the return value of the `eval()` and then runs the compiled result  
2. the syntax checks are:  
   1. the input must start with a double quote  
   2. the input must end with a double quote  
   3. no character in between can be a literal double quote  
3. Must break out of quotes and read `flag.txt`

## Solution  
1. since any escape sequences in the input won't be evaluated until the call to `eval()` we can break out of our opening double quotes with `\x22`  
2. sending an input like `" \x22+open('flag.txt').read()+\x22 "` will concatenate the contents of `flag.txt` with two whitespace characters and print the result, giving us the flag

`wctf{m30w_uwu_:3}`

Original writeup
(https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469#escaped---
beginner-50-pts).