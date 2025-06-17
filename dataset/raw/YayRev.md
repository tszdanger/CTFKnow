# YayRev

## Task

Let’s brush up sum pythan skillz… (no flag wrapper)

File: yayrev.py

## Solution

This one is a bit harder to understand:

```python  
proficuous =flag  
saxicolous = [ord(excogitate) for excogitate in proficuous]  
ebullient  = (saxicolous[-5:]);  import random  
second = (saxicolous[:-5])  
sesquipedalian = ''.join(map(chr,ebullient)) + ''.join(map(chr,second))

vravar = ''.join([chr(permutation.islower() and ((ord(permutation) - 84) % 26)
+ 97  
                       or permutation.isupper() and ((ord(permutation) - 52) % 26) + 65  
                       or ord(permutation))  
                   for permutation in sesquipedalian])

auspicious = []  
for luminescent in vravar:  
   auspicious.append(luminescent)

for cupidity in range(200):  
   second = []  
   superabundant=random.choice(auspicious)  
   print( "mac>>>[" + str(auspicious.index(superabundant)) + "] " + "== " +
"\"" + superabundant + "\"" + " and")  
```

1. The last 5 chars are moved to the start

2. Something happens

3. The joined chars are moved into a list

4. 200 Random values are chosen from that list and we get their index and value

The 200 outputs are given so lets clean that up with a regex and do a `sort
-u`. We now have only 18 values.

We need to reverse step 2 now.

```python  
for c in [  
   chr(c.islower() and ((ord(c) - 84) % 26) + 97  
   or c.isupper() and ((ord(c) - 52) % 26) + 65  
   or ord(c))  
   for c in flagSwapped]:  
   out.append(c)  
```

At first I didn't realize this, but it's just ROT13. If it's not upper or
lowercase we just take the char.

```python  
>>> chr((ord("Z") - 52) % 26 + 65)  
'M'  
>>> chr((ord("A") - 52) % 26 + 65)  
'N'  
```

All we have to do now:

```python  
import codecs  
...  
print(codecs.encode(''.join(crypt[5:]) + ''.join(crypt[:5])), 'rot_13')  
```

`Wh0a_l3gEnD-PytHON`  

Original writeup (https://github.com/klassiker/ctf-
writeups/blob/master/2020/cyberyoddha/reverse-engineering/yayrev.md).