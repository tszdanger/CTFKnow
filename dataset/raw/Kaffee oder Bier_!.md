# Kaffee oder Bier (re, 164p, 25 solved)

## Description

In the task we get a
[binary](https://raw.githubusercontent.com/TFNS/writeups/master/2020-07-03-ASIS-
quals/kaffee/COB) and [encrypted
flag](https://raw.githubusercontent.com/TFNS/writeups/master/2020-07-03-ASIS-
quals/kaffee/flag.enc)  
The binary seems to be just a simple encryptor.  
You can pass input and output files and it will perform the encryption.  
The main issue is that it takes quite a while to execute...

We follow our mantra that `every RE is just a blackbox crypto if you're brave
enough`, and load this into Ghidra only for a moment.  
Sadly it's C++ so Ghidra frowns a bit and spits out not-so-nice code.  
But it's enough to figure out the general idea.  
The important part of main is:

```c  
 this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"Now grab
some coffee ☕, it would take a while...");  
 operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--
char_traits<char>>);  
 input_char = get();  
 not_first_value = '\x01';  
 while( true ) {  
   boolean_flag = eof();  
   if (boolean_flag == '\x01') break;  
   if (not_first_value == '\0') {  
     operator+=(final_result,"0000");  
   }  
   else {  
     not_first_value = '\0';  
   }  
   result = bork((long)input_char);  
   int_to_string_llu(string_number,result,result);  
   operator+=(final_result,string_number);  
   ~basic_string((basic_string<char,std--char_traits<char>,std--
allocator<char>>*)string_number);  
   input_char = get();  
 }  
 this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"DONE! ? (Of
course, beer is way better than coffee!)");  
 operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--
char_traits<char>>);  
 close();  
 operator<<<char,std--char_traits<char>,std--
allocator<char>>(local_428,(basic_string *)final_result);  
 close();  
```

What is important to notice here is that `bork` function takes only a single
char from our input every time it's called.  
Then it returns some number, this number is turned into string, added to the
result string, and `0000` is added to separate each result.

We could peek into `bork` function, but what it really does is to calculate
some values based on input char and call:

```c  
 uint result;  
 int i;  
  
 result = 0;  
 i = 1;  
 while ((ulong)(long)i < input_char) {  
   if (input_char % (long)i == 0) {  
     result = result ^ 1;  
   }  
   i = i + 1;  
 }  
 return (ulong)result;  
```

Many many many times over.

## Solution

One could consider re-writing this algorithm into some other language, putting
results of this function to some map, and use this to recover the flag...

But we know the encryption is done char by char, and we know that the
encryption is ECB-like, so the same char will be encrypted into identical
result every time it appears.  
So why not just use the binary to generate ciphertext of every symbol in flag
charset and use this for substitution table?

```python  
import codecs  
import multiprocessing  
import os  
import string

def brute(worker, data_list, processes=8):  
   pool = multiprocessing.Pool(processes=processes)  
   result = pool.map(worker, data_list)  
   pool.close()  
   return result

def worker(c):  
   input_file = str(ord(c)) + ".txt"  
   output_file = str(ord(c)) + ".enc"  
   with codecs.open(input_file,'wb') as f:  
       f.write(c)  
   os.system("./COB " + input_file + " " + output_file)

def main():  
   charset = [c for c in "_!" + string.digits + string.uppercase +
string.lowercase + "{}"]  
   brute(worker, charset, processes=6)

main()  
```

Now this takes a while, a single character takes minutes to compute, and
larger the ascii code the longer it takes.  
Still, we can just run this in background for a moment.  
After that we just do:

```python  
   for encfile in glob.glob(base_path+"/*.enc"):  
       if os.stat(encfile).st_size > 0:  
           o = re.findall("(\\d+)\\.enc", encfile)[0]  
           with codecs.open(encfile) as f:  
               mapping[f.read()] = chr(int(o))  
   res = ''  
   for c in enc.split("0000"):  
       print(c)  
       if str(int(c)) in mapping:  
           res += mapping[str(int(c))]  
       else:  
           res += '?'  
   print(res)  
```

And we can observe the flag slowly appear the more characters we can grab.  
After some time get can recover: `ASIS{S1mPl3_R3vEr5e_w17H_Numb3r5!}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-07-03-ASIS-
quals/kaffee/README.md).