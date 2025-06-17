ghidra and IDA didn't like the PLT of this binary, idk why. Rather than static
analyzing first, I choose to do this blackbox. The binary read from flag.txt
then output some numbers, see syscall trace below.  
```  
$ strace ./znfl  
...  
openat(AT_FDCWD, "flag.txt", O_RDONLY)  = 3  
fstat(3, {st_mode=S_IFREG|0644, st_size=43, ...}) = 0  
...  
```

Running the binary couple of times with same flag.txt content, you'll notice
that the output doesn't stay the same every run, but somewhere if you have run
the binary fast enough, (like really fast, 2 times in a second) you'll notice
that the output is the same. Here's an example  
```  
$ ./znfl  
1224429843 1224429840 1224429855 1224429840 1224429847 1224429855 1224429855
1224429852 1224429847 1224429855 1224429855 1224429852 1224429847 1224429855
1224429855 1224429852 1224429847 1224429855 1224429855 1224429852 1224429847
1224429855 1224429855 1224429852 1224429847 1224429855 1224429855 1224429852
1224429847 1224429855 1224429855 1224429852 1224429847 1224429855 1224429855
1224429852 1224429847 ...  
$ ./znfl  
1224429843 1224429840 1224429855 1224429840 1224429847 1224429855 1224429855
1224429852 1224429847 1224429855 1224429855 1224429852 1224429847 1224429855
1224429855 1224429852 1224429847 1224429855 1224429855 1224429852 1224429847
1224429855 1224429855 1224429852 1224429847 1224429855 1224429855 1224429852
1224429847 1224429855 1224429855 1224429852 1224429847 1224429855 1224429855
1224429852 1224429847 ...  
```

We could guess It's using something random as a key. To make things easier, I
created a `LD_PRELOAD` lib to patch `rand()` nad make it not "random".  
```C  
// gcc -shared -fPIC -o libunrandom.so unrandom.c  
int rand() {  
 return 0;  
}  
```  
After this the output is not changed anymore after every run.  
```  
$ LD_PRELOAD=./libunrandom.so ./znfl  
4 7 8 7 0 8 8 11 0 8 8 11 0 8 8 ...  
$ LD_PRELOAD=./libunrandom.so ./znfl  
4 7 8 7 0 8 8 11 0 8 8 11 0 8 8 ...  
```

Now, on to how the numbers are generated. I still didn't bother to do static
analysis. At this point, I started to try out some different input from
flag.txt content.  
```  
$ echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > flag.txt &&
LD_PRELOAD=./libunrandom.so ./znfl  
0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8
11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8
8 11 0 8 8 11 0 8 8 11 0 8 8 11  
```  
You'll notice that the number is repeated every 4 number. From that
Information, we could change our first four character from input to something
else  
```  
$ echo "BBBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > flag.txt &&
LD_PRELOAD=./libunrandom.so ./znfl  
12 13 1 7 12 13 1 7 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8
8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0
8 8 11 0 8 8 11 0 8 8 11 0 8 8 11  
```  
And to our surprise, It became another repeated number `12 13 1 7 12 13 1 7
...`. Because of that, we could try to lower our input guess to 2 character
patern.  
```  
$ echo "CCBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > flag.txt &&
LD_PRELOAD=./libunrandom.so ./znfl  
7 3 6 15 12 13 1 7 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8
11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8
8 11 0 8 8 11 0 8 8 11 0 8 8 11  
$ echo "CBBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > flag.txt &&
LD_PRELOAD=./libunrandom.so ./znfl  
6 8 6 7 12 13 1 7 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8
11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8
8 11 0 8 8 11 0 8 8 11 0 8 8 11  
```  
From this, we could guess that every 2 character is mapped to 4 number at
output. Try changing the input some more if you need to make sure It's the
behaviour of the program.

Since every 2 character of input is perfectly mapped to 4 number output, we
could use dictionary to recover the flag. There's still a problem though, we
still didn't know what's the key used for the output.txt. To get the key, we
could start from the flag format, we know that flag format is `FwordCTF{...}`
with that we could get the different from our `Fw` output and output.txt.  
```  
$ echo "FworAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > flag.txt &&
LD_PRELOAD=./libunrandom.so ./znfl  
6 7 10 9 4 9 10 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8
11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8 8 11 0 8
8 11 0 8 8 11 0 8 8 11 0 8 8 11  
$ cat output.txt  
1155306822 1155306823 1155306826 1155306825 1155306820 1155306825 1155306826
1155306827 1155306821 1155306819 1155306831 1155306823 1155306821 1155306831
1155306816 1155306823 1155306818 1155306820 1155306829 1155306816 1155306823
1155306818 1155306828 1155306822 1155306824 1155306816 1155306826 1155306826
1155306819 1155306821 1155306819 1155306830 1155306819 1155306819 1155306825
1155306826 1155306828 1155306816 1155306826 1155306826 1155306825 1155306821
1155306822 1155306823 1155306821 1155306818 1155306825 1155306819 1155306816
1155306828 1155306822 1155306821 1155306820 1155306824 1155306829 1155306827
1155306816 1155306831 1155306830 1155306825 1155306820 1155306830 1155306818
1155306829 1155306831 1155306829 1155306830 1155306830 1155306827 1155306822
1155306822 1155306828 1155306831 1155306829 1155306816 1155306831 1155306819
1155306817 1155306818 1155306831 1155306821 1155306830 1155306820 1155306825  
```  
Since `6 7 10 9` has `0 +1 +4 +3` pattern, and the output.txt doesn't have the
same addition/subtraction pattern, we could guess that xor is used in this
program. Just xor the first number from both output, `1155306822 ^ 6 =
1155306816`,  and we got `1155306816` as key to translate output.txt to our
patched program output.

From here on, you'll just need to get the dictionary for every 2 character of
input, then recover the flag using our dictionary.  
```py  
from pwn import *

def conn(level="info"):  
   return process("./znfl", env={"LD_PRELOAD": "./libunrandom.so"},
level=level)

dic = {}

p = log.progress("get dict")  
for first in range(0x21, 0x7F):  
   for second in range(0x21, 0x7F):  
       with open("flag.txt", "wb") as f:  
           pload = bytes([first, second]) + b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"  
           f.write(pload)  
       r = conn("warn")  
       a = int(r.recvuntil(" ", 1))  
       b = int(r.recvuntil(" ", 1))  
       c = int(r.recvuntil(" ", 1))  
       d = int(r.recvuntil(" ", 1))  
       r.close()  
       # print(f"{a} {b} {c} {d} = {chr(first)}{chr(second)}")  
       p.status(f"{first:02x}{second:02x}")  
       dic[(a,b,c,d)] = (first, second)  
p.success("done")

with open("output.txt") as f:  
   item = f.read().split()

data = []  
for c in item:  
   data.append(int(c))

for pos in range(0, len(data), 4):  
   key = (data[pos], data[pos+1], data[pos+2], data[pos+3])  
   if key in dic:  
       print(f"{chr(dic[key][0])}{chr(dic[key][1])}", end="")  
   else:  
       print(key, "not found")  
```

Run the script, and we will get the flag at the end.  
```  
$ python solve.py  
[+] get dict: done  
FwordCTF{n0t_4_bad_id3a_4ft3r_All_semah!!}  
```