# nodb

Welcome to the future. The future of no data breaches!

## Solution

You are given a link to a tron-like website with a single "password" field.

Inspecting the source shows:

```javascript  
   ptr = allocate(intArrayFromString( TEXTBOX_INPUT ), 'i8', ALLOC_NORMAL);  
   ret = UTF8ToString(_authenticate(ptr));  
   if (ret == "success") document.getElementsByClassName("text")[0].innerText
= "SUCCESS"  
```

The check `_authenticate` is implemented in the binary wasm file `wasm.wasm`.

Using `jeb` (free version: https://www.pnfsoftware.com/jeb/demowasm) we get
the following info by decompiling `_authenticate`:

![Jeb decompiling WASM](jeb-screenshot.png?raw=true)

The code is pretty complicated, but in the end we just need variable `v6` to
be `69`.  
It seems like `v6` is a counter of how many characters of the password is
correct, so instead of inverting `_authenticate`, we can patch it to return
`v6` and bruteforce one character at a time!

Using `wasm2wat` (https://webassembly.github.io/wabt/demo/wasm2wat/) we can
convert `wasm.wasm` to `wasm.wat` (which is still confusing to work with, but
its text instead of binary).

Searching through the code we can see the constant `1245` is only used once,
and just above is the comparison with `69`, so we change `(i32.const 1245)` to
`(local.get $l51)`:

![Patching the WAT code](patching-wat-screenshot.png?raw=true)

Now we can use `wat2wasm` (https://webassembly.github.io/wabt/demo/wat2wasm/)
and the build-in firefox javascript console to bruteforce each character of
the flag!  (`_authenticate` will return the number of correct characters, or
`success`).

![Bruteforcing the JavaScript, using ugly-but-quickly-made code](bruteforce-
screenshot.png?raw=true)

Flag: `OOO{ifthereisnodataontheserverthereisnodatabreachproblemsolvedkthxbb}`  

Original writeup (https://github.com/NicolaiSoeborg/ctf-
writeups/tree/master/2019/DEF%20CON%20Qualifier/nodb).