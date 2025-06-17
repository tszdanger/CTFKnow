```text  
Prison Break  
119 Points

Author: FeDEX

Your friend has been captured by some country's secret services and is being
held in a prison. Having reached the prison, you realise there is a code there
that you need to break.  
The enemies have been kind enough to leave a large file containing 3 numbers
on each line and the following message for you:  
"Start with a list of 10^7 zeros and for every line containing a,b,c separated
by a space in the given file, add c modulo 10 to every number in your list
between indices a and b (a included only).  
Indices start at 1 in the list. At the end, compute the product modulo
999999937 of the nonzero digits in your list and you will obtain the password
needed to free your friend".  
The problem is that your friend needs medication within the next 3 days so can
you break the password soon enough?

Flag Format: HackTM{CODE}

Challenge Files:
https://drive.google.com/file/d/1CNwGf_lKq8wHA8qYQJFkqP5HCybmYBel/view  
```

We got a huge file (138Mb) with a lot of lines:

```bash  
$ wc -l Given_File.txt  
9999999 Given_File.txt  
```

Each line is composed by three numbers as evoqued in the description (a, b and
c):

```text  
183 183 0  
548 3000548 5  
91 8000091 5  
41 2000041 8  
95 1000095 1  
296 296 4  
625 625 2  
```

With the same description, we can clean the file to got less lines and speed
up the computation time to get code the code:

```bash  
$ cat Given_File.txt | sort -n -k 1 | uniq -c | sed 's/^[ \t]*//;s/[ \t]*$//' | grep -v ' 0' > clean_file  
```

* sort the line by the first number (and not the entire line)  
* count each line to add before it the occurence number  
* replace the tabulation added before  
* remove all the line ended by 0 since no loop will be done with it

```python  
file = open("clean_file", 'r')  
l = []  
for i in range(9000999):  
   l.append(0)

for line in file:  
   o,a,b,c = line.split(' ')  
   value = (int(c) % 10) * int(o)  
   if value == 0:  
       continue  
   for i in range(int(a), int(b)):  
       l[i] += value

f = []  
f.append(0)  
for v in l:  
   current = int(v) % 10  
   if current != 0:  
       f.append(int(v) % 10)

final = 1  
for a in f:  
   if a == 0:  
       continue  
   final = (a * final) % 999999937

print("Flag is : HackTM{" + str(final) + "}")  
```

Since Python is not really fast for doing it, I choose to use
[pypy](https://pypy.org/). You can use it with your python script but pypy
handle it with a different approach than regular Python interpretor.

```bash  
$ pypy3 prison_break.py  
Flag is : HackTM{585778044}  
```

My script took `948,21s user 0,69s system 99% cpu 15:50,45 total`. I guess I
can make it better and improve the input file too.

PS : I tried to compile my python script to C code with
[cython](https://cython.org/) but I can't get a working binary :(.

Original writeup (https://blog.nlegall.fr/hacktm-quals20-prison-break.html).