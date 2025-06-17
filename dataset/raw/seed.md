# rev/seed

Author: m0x

## Description

```  
Having a non-weak seed when generating "random" numbers is super important!
Can you figure out what is wrong with this PRNG implementation?

seed.py is the Python script used to generate the flag for this challenge.
log.txt is the output from the script when the flag was generated.

What is the flag?  
```

Downloads: `seed.py` `log.txt`

## Analysis

`seed.py` generated the flag by creating a bunch of sha256 hashes in a loop
and then writing out the one with `b9ff3ebf` in the string as the flag:

```python3  
def seed():  
   return round(time.time())

def hash(text):  
   return hashlib.sha256(str(text).encode()).hexdigest()

def main():  
   while True:  
       s = seed()  
       random.seed(s, version=2)

       x = random.random()  
       flag = hash(x)

       if 'b9ff3ebf' in flag:  
           with open("./flag", "w") as f:  
               f.write(f"dam{{{flag}}}")  
           f.close()  
           break

       print(f"Incorrect: {x}")  
   print("Good job <3")

if __name__ == "__main__":  
  sys.exit(main())  
```

This is what happened when the author ran the script:

```  
$ cat log.txt  
Incorrect: 0.3322089622063289  
Incorrect: 0.10859805708337256  
Incorrect: 0.39751456956943265  
Incorrect: 0.6194981263678604  
Incorrect: 0.32054505821893853  
Incorrect: 0.2674908181379442  
Incorrect: 0.5379388350878211  
Incorrect: 0.7799698997586163  
Incorrect: 0.6893538761284775  
Incorrect: 0.7171513961367021  
Incorrect: 0.29362186264112344  
Incorrect: 0.06571100672753238  
Incorrect: 0.9607588522085679  
Incorrect: 0.33534977507836194  
Incorrect: 0.07384192274198853  
Incorrect: 0.1448081453121044  
Good job <3  
```

The problem with this, is the seed is based on time and rounded to the nearest
integer:

```python3  
def seed():  
   return round(time.time())  
```

## Solution

Since our current time is later than when the author ran it, we just have to
make a minor change to that script to start the seed with the current time,
and decrement the seed each iteration until we find one that generates the
flag:

```  
$ diff seed.py solve.py  
14,15c14,16  
<     while True:  
<         s = seed()  
---  
>     s = seed()  
>     while s > 0:  
>         s = s - 1  
```

```  
$ python3 ./solve.py  
...  
$ cat flag  
dam{f6f73f022249b67e0ff840c8635d95812bbb5437170464863eda8ba2b9ff3ebf}  
```  

Original writeup
(https://github.com/dobsonj/ctf/tree/master/writeups/2021/damctf/seed).