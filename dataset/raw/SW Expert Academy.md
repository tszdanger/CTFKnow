## Intro  
**SW Expert Academy** was a web challenge at Hacker's Playground 2021 by SSTF.  

You were given a URL where you should prove your algorithmic skills by solving
some dice roll problem. At the bottom of the page is a text field where you
can inject C-Code into the body of a main-function. Upon submitting the form,
your algorithm is executed on the server side and tested against some input.

## Investigation  
By inspecting the source code of the page we learn that the flag can be found
in a text file on the servers root directory. A quick look at the linked
javascript also reveals that error responses, when received from the server,
are alerted. That's how to possibly leak information from the server - and
indeed, when writing to _stderr_ and exiting the program with an error, we are
presented with the error output in the alert.

So, my idea was to just open the _/flag.txt_, read its content, print it to
_stderr_ and then exit the main function with an error to report the
information back. But, obviously some source code filter gets applied and I
got notified that the _dangerous keyword 'fopen' has been detected_ and my
code therefore wouldn't run. After trying a few other approaches I quickly
realized most of the interesting functions found in _stdio.h_ were prohibited.

I then tried to close the main function early with a ```}``` and ```#include
"/flag.txt"``` afterwards, provoking a compilation error leaking the contents
of the file in the error output. But again, no luck - ```include``` as well as
the ```#```-symbol were considered dangerous, too.

## Solution  
My final solution was to bypass the source code filter by inserting the
dangerous functions at compile time. The key here was to use macros and let
the preprocessor concatenate the dangerous function names with the
```##```-directive. To deal with the prohibition of the ```#```-symbol itself,
I used [digraphs](https://en.wikipedia.org/wiki/Digraphs_and_trigraphs#C).

##### payload:  
```C  
   leak_flag();  
   return 1;  
}

%:define OPEN(path, mode) fop%:%:en(path, mode)  
%:define SCAN(f, fmt, buf) fsca%:%:nf(f, fmt, buf)

int leak_flag() {  
   char buf[128];  
   FILE *f;  
   f = OPEN("/flag.txt", "r");  
   SCAN(f, "%s", buf);  
   fprintf(stderr, buf);  
```

##### flag:  
```  
SCTF{take-care-when-execute-unknown-code}  
```  

Original writeup
(https://github.com/dystobic/writeups/tree/main/2021/SSTF/SW%20Expert%20Academy).