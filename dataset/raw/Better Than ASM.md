# Bamboo Fox Better Than Assembly Write Up

This challenge yet again had  very little detail, only providing the .ll file
and the title "Better than ASM". Not knowing what type of file .ll was my
first step was using file, this however was not the most useful as I got the
following:

``` bash  
$ file task.ll  
task.ll: ASCII text  
```

Simply running the file also did not seem to work so I turned to Google, a
simple search for .ll file however was not the most useful since the only
information that turned up was that it was a List and Label preview file for
Combit List & Label, this seemed highly unlikely so I searched .ll file
assembly since the title referenced assembly and the contents of the file
looked similar to assembly. This lead to results coming up for LLVM Static
Compiler, finally something useful.

After some more research I had two paths to choose from, converting the file
to assembly since I was more comfortable with that or compiling the file so I
had something to run. I chose to compile it since I was planning on throwing
it into IDA anyways.

After some research I found out that I could compile the file using clang with
the following command:

``` bash  
clang task.ll -mllvm -W -g -W1,-pie -o task.out  
```

I then ran the file which resulted in the following output:

``` bash  
$ ./task.out  
Only the chosen one will know what the flag is!  
Are you the chosen one?  
flag:  
```

Entering a random value caused the program to print out a rather mean message
and exit:

``` bash  
flag: t

?????? You are not the chosen one! ??????

```

At this point I threw the compiled program into IDA so that I could see
psuedocode for the program and debug through it.

The psuedocode produced by ida for the main function was:

``` c  
int __cdecl main(int argc, const char **argv, const char **envp)  
{  
 char v4; // [rsp+14h] [rbp-94h]  
 char v5; // [rsp+34h] [rbp-74h]  
 size_t v6; // [rsp+40h] [rbp-68h]  
 int j; // [rsp+58h] [rbp-50h]  
 int i; // [rsp+5Ch] [rbp-4Ch]  
 char s[68]; // [rsp+60h] [rbp-48h] BYREF  
 int v10; // [rsp+A4h] [rbp-4h]

 v10 = 0;  
 printf("Only the chosen one will know what the flag is!\n");  
 printf("Are you the chosen one?\n");  
 printf("flag: ");  
 __isoc99_scanf("%64s", s);  
 v6 = strlen(s);  
 if ( v6 == strlen(&what) )  
 {  
   if ( (unsigned int)check(s) )  
   {  
     for ( i = 0; i < strlen(s); ++i )  
     {  
       v5 = s[i];  
       s[i] = secret[i % strlen(secret)] ^ v5;  
     }  
   }  
   else  
   {  
     for ( j = 0; j < strlen(s); ++j )  
     {  
       v4 = flag[j];  
       s[j] = secret[j % strlen(secret)] ^ v4;  
     }  
   }  
   printf(format, s);  
   v10 = 0;  
 }  
 else  
 {  
   printf(asc_40205A);  
   v10 = 1;  
 }  
 return v10;  
}  
```

As you can see this matches with what the program outputted when it was run.
The program reads in a string (max 64 chars), if it is the same length as what
it then checks the string and if it passes it xor's the string with secret, if
not it xor's some string (flag) with secret.

I then went through and got the values for the different variables:

``` python  
what =
b"\x17/'\x17\x1DJy\x03,\x11\x1E&\x0AexjONacA-&\x01LANH'.&\x12>#'Z\x0FO\x0B%:(&HI\x0CJylL'\x1EmtdC\x00\x00\x00\x00\x00\x00\x00\x00"

secret =
b'B\x0A|_\x22\x06\x1Bg7#\x5CF\x0A)\x090Q8_{Y\x13\x18\x0DP\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

flag =
b'\x1DU#hJ7.8\x06\x16\x03rUO=[bg9JmtGt`7U\x0BnNjD\x01\x03\x120\x19;OVIaM\x00\x08,qu<g\x1D;K\x00}Y\x00\x00\x00\x00\x00\x00\x00\x00'

format =
b'\x0A\xF0\x9F\x98\x82\xF0\x9F\x91\x8C\xF0\x9F\x98\x82\xF0\x9F\x91\x8C\xF0\x9F\x98\x82\xF0\x9F\x91\x8C
flag{%s}
\xF0\x9F\x91\x8C\xF0\x9F\x98\x82\xF0\x9F\x91\x8C\xF0\x9F\x98\x82\xF0\x9F\x91\x8C\xF0\x9F\x98\x82\x0A\x0A\x00\x00\x00'

asc_40205A =
b'\x0A\xF0\x9F\x98\xA0\xF0\x9F\x98\xA1\xF0\x9F\x98\xA0\xF0\x9F\x98\xA1\xF0\x9F\x98\xA0\xF0\x9F\x98\xA1
You are not the chosen one!
\xF0\x9F\x98\xA1\xF0\x9F\x98\xA0\xF0\x9F\x98\xA1\xF0\x9F\x98\xA0\xF0\x9F\x98\xA1\xF0\x9F\x98\xA0\x0A\x0A\x00'  
```

asc_40205A was obviously the string that was printed when I put in a random
value, however I noticed that the format string included the flag{} component
of the flag meaning that I would not simply be able to solve the flag by
assuming the first 5 characters and the last character since the wrapper was
added later.

Now that I had all the values I was also able to test the different
components, my first step was the see what the length of what was, this ended
up being 56 meaning the code we would need to put in needed to be that long,
the next thing I wanted to figure out was what would be printed if check
returned false. To test that I first wrote some c++ code and then remembered
that c++ is not always the most fun for quick scripting so I wrote the
following python code instead:

``` python  
newStr = ""  
for i in range(0, 56):  
   newStr += chr(secret[i % len(secret)] ^ flag[i])  
print(newStr)  
```  
Once ran this code output the following value:

``` bash  
___7h15_15_4_f4k3_f14g_y0u_w1ll_f41l_1f_y0u_subm17_17___  
```

I hadn't expected this to work so this allowed me to confirm that the actual
flag depended on the correct string being xor'd with secret leading me to look
into the check function.

``` c  
__int64 __fastcall check(__int64 a1)  
{  
 int v2; // [rsp+1Ch] [rbp-1Ch]  
 int i; // [rsp+28h] [rbp-10h]  
 unsigned int v4; // [rsp+2Ch] [rbp-Ch]

 v4 = 1;  
 for ( i = 0; i < strlen(what); ++i )  
 {  
   v2 = *(char *)(a1 + i);  
   v4 = (unsigned __int8)v4 & ((*(char *)(a1 + (i + 1) % strlen(what)) ^ v2)
== what[i]);  
 }  
 return v4;  
}  
```

This code goes through what and checks to see if each ith character in what is
equal to the ith character in the input string xor'd with the ith + 1
character in the input string with the mod allowing the string to wrap back
around to the start.

I sadly went down a rabbithole here for a bit of trying to brute force
combinations since I realized that if I was able to solve for one character I
would be able to solve for the entire key. Then I realized I could just
generate the 90 (127 - 30, writable characters) keys possible since the rest
of the key would be based on the first character.

From here I created a script that iterated through the possible writeable
characters and then went through each value in what and appended the ith value
xor'd with the ith value in what to generate the ith + 1 value since `A ^ B =
C <==> A ^ C = B`. The script then went through and xor'd each ith value with
the ith value of secret to generate a list of potential flags. I also went
ahead and removed all of the end of line characters from the strings.

``` python  
what =
b"\x17/'\x17\x1DJy\x03,\x11\x1E&\x0AexjONacA-&\x01LANH'.&\x12>#'Z\x0FO\x0B%:(&HI\x0CJylL'\x1EmtdC\x00\x00\x00\x00\x00\x00\x00\x00"  
secret =
b'B\x0A|_\x22\x06\x1Bg7#\x5CF\x0A)\x090Q8_{Y\x13\x18\x0DP\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

what = what.rstrip(b'\0')  
secret = secret.rstrip(b'\0')

for i in range(30, 127):  
   flag = []  
   flag.append(i)

   for j in range(len(what)):  
       flag.append(flag[j]^what[j])

   newFlag = ""  
   for j in range(len(what)):  
       newFlag += chr(flag[j]^secret[j%len(secret)])

   print(newFlag)  
```

This create a list of potential flags in which I spotted:

``` bash  
7h15_f14g_15_v3ry_v3ry_l0ng_4nd_1_h0p3_th3r3_4r3_n0_7yp0  
```

However having the script print out so much junk was annoying me a bit so I
went and added a sanity check to the print, only printing values that were
between 30 and 127 on the ascii table:

``` python  
what =
b"\x17/'\x17\x1DJy\x03,\x11\x1E&\x0AexjONacA-&\x01LANH'.&\x12>#'Z\x0FO\x0B%:(&HI\x0CJylL'\x1EmtdC\x00\x00\x00\x00\x00\x00\x00\x00"  
secret =
b'B\x0A|_\x22\x06\x1Bg7#\x5CF\x0A)\x090Q8_{Y\x13\x18\x0DP\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

what = what.rstrip(b'\0')  
secret = secret.rstrip(b'\0')

for i in range(30, 127):  
   flag = []  
   flag.append(i)

   for j in range(len(what)):  
       flag.append(flag[j]^what[j])

   newFlag = ""  
   for j in range(len(what)):  
       char = chr(flag[j]^secret[j%len(secret)])  
       if ord(char) not in range(30, 127):  
           continue  
       else:  
           newFlag += char

   print(newFlag)  
```

Original writeup
(https://github.com/Kasimir123/CTFWriteUps/tree/main/2021-01-BambooFox/better-
than-asm).