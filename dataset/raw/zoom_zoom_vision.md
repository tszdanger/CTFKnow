# zoom_zoom_vision - corCTF2021

- Category: Reverse  
- Points: 482  
- Solves: 40  
- Solved by: drw0if

## Description

Something is wrong, I'm losing my vision. Please help me recover my vision.

## Solution

We are given a windows executable, using strings we can guess it is compiled
from C++ since we can see strings like:  
```bash  
bad allocation  
Unknown exception  
bad array new length  
string too long  
bad cast  
```

Reversing C++ with Ghidra is almost always painful, so let's execute it first:  
```powershell  
> .\zoom_zoom_vision.exe  
Enter serial: 123  
784 800 816  
Try again, son!  
```

It takes our characters and give us back some kind of encrypted sequence.
Let's try again:  
```powershell  
> .\zoom_zoom_vision.exe  
Enter serial: aaa  
1552 1552 1552  
Try again, son!  
```

So it seems that it is just a substitution. Looking more at the strings inside
the binary we can spot another useful sequence:  
```bash  
1584 1776 1824 1584 1856 1632 1968 1664 768 1728 784 784 784 784 784 1520 1840
1664 784 784 784 784 784 784 816 816 816 816 816 816 1856 1856 1856 1856 1856
1520 784 1856 1952 1520 1584 688 688 528 2000  
```

We can make a map of each character simply running the program with the
characters we want to translate and parsing the output, than we can use a
reverse lookup table to decode the string.

And we got the flag!

```  
corctf{h0l11111_sh111111333333ttttt_1tz_c++!}  
```

Original writeup
(https://github.com/r00tstici/writeups/tree/master/corCTF_2021/zoom_zoom_vision).