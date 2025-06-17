# theyseemerolling - Beginner (50 pts)

## Description  
> they hatin my cryptosystem

### Provided files  
theyseemerolling.zip - a ZIP archive containing two files
\[[download](https://ctfnote.shinmai.wtf:31337/files/downloadFile?id=RhJ4JTh03T710fo)\]  
- `output.txt` - the ciphertext a hex digest \[[download](https://ctfnote.shinmai.wtf:31337/files/downloadFile?id=6itv0WlvB57iGJh)\]   
- `enc.py` - the Python code used to generate the ciphertext \[[download](https://ctfnote.shinmai.wtf:31337/files/downloadFile?id=ICFzAe7KidyaIm3)\]

## Ideas and observations  
1. the sript generates a random 8-byte key with `os.urandom(8)`  
2. it then reads the plaintet from a file as bytes and pads it to `length % 4 * 4 + 4` with NULL bytes  
3. the resulting byte-array is then encrypted with the key in blocks of 4 bytes  
   - a four byte index is prepended to each block 

## Notes  
1. because of the four byte index, the first 4 bytes of the random key are always only used to encrypt the padding bytes, so only the last 4 bytes of the key interest us  
2. the key will start with `wctf{` meaning we can just XOR the lower 4 bytes of the first block with `wctf` to recover the lower 4 bytes of the key

## Solution CyberChef recipe  
Because Register operators don't work inside Subsections, there's a manual
cleanup Find / Replace operators at the end to restore the beginning of the
flag.  
[CyberChef
link](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')Subsection('%5E(........)',false,false,false)XOR(%7B'option':'Latin1','string':'wctf'%7D,'Standard',false)Merge(false)Register('%5E....(....)',false,false,false)XOR(%7B'option':'Latin1','string':'$R0'%7D,'Standard',false)Find_/_Replace(%7B'option':'Regex','string':'....(....)'%7D,'$1',true,false,false,false)Find_/_Replace(%7B'option':'Regex','string':'%5E....'%7D,'wctf',true,false,true,false)&input=OTgzZjY4N2YwM2Y4ODRhOTk4M2Y2ODdlMGZmMmFmYmM5ODNmNjg3ZDAzYTg5MWJkOTgzZjY4N2MyYmY2ODk5MDk4M2Y2ODdiMDRlOWMwYTk5ODNmNjg3YTJiZThjNGE2OTgzZjY4NzkxMGM0ODJmZjk4M2Y2ODc4MThmN2FmYjY5ODNmNjg3NzQ0ZWU4MjkwOTgzZjY4NzY0NGVjOWU5MDk4M2Y2ODc1MTdlOTg5YmY5ODNmNjg3NDAwYWI4ZGNmCg)

`wctf{i_sw3ar_my_pr0f_s4id_r0ll_y0ur_0wn_crypt0}`

Original writeup
(https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469#theyseemerolling
---beginner-50-pts).