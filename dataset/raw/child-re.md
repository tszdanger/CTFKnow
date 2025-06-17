# child-re - Reverse (100 pts)

## Description

> You've graduated from baby, congrats!

### Provided files  
`child-re` 64-bit ELF executable
\[[download](https://ctfnote.shinmai.wtf:31337/files/downloadFile?id=8RjgVE010Y9w8Cl)\]  
`Dockerfile` Docker configuration for the remote endpont
\[[download](https://ctfnote.shinmai.wtf:31337/files/downloadFile?id=gEuNR09Iii3kvBe)\]

## Ideas and observations  
1. main() is a red herring with a Hitchhiker's Guide reference  
2. there's another function at 0x1165 that never get's called, but pushes some bytes to the stack, XORs them with a value and prints the result

## Solution  
1. Pull the bytes from the binary  
2. XOR them with some value; we know it's 0x42 - references. Even if we didn't, we could brute-force it

### Solution script

```python  
from Crypto.Util.numbers import long_to_bytes

# copied from the binary in Binary Ninja  
enc_flag =
bytes.fromhex('5d495e4c51621b5e4942421b4119581f756d5f1b4e19755e1a755e4219756d1e461e52530b0b751e1857')  
for c in enc_flag:  
   print(end=chr(c ^ 42))  
print()  
```

This gets us the flag: `wctf{H1tchh1k3r5_Gu1d3_t0_th3_G4l4xy!!_42}`

Original writeup
(https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469#child-re---
reverse-100-pts).