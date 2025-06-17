## Generic Flag Checker 1  
![date](https://img.shields.io/badge/date-11.01.2020-brightgreen.svg)
![Reverse Engineering category](https://img.shields.io/badge/Category-
Reverse%20Engineering-lightgrey.svg)
![score](https://img.shields.io/badge/score-75-blue.svg)

### Description  
```  
Flag Checker Industries™ has released their new product, the Generic Flag
Checker®! Aimed at being small, this hand-assembled executable checks your
flag in only 8.5kB! Grab yours today!  
```

### Files  
- gfc1 (ELF File)

### Solution  
I'm pretty new to reverse engineering so I won't be have the intelligence of
explaining what is going on. But this challenge was not difficult to solve.
When running the "file" command, we knew that it was an elf executable.  
```  
> file gfc1  
gfc1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked,
BuildID[sha1]=7d4bbad2b6eeb736abec4fd52079781dcc333781, stripped  
```  
**ELF (Executable Linkable Format)**: Similar to binary files but with
additional information such as possible debug info, symbols, distinguishing
code from data within the binary.

All I had to do to find this flag was cat the file  
OR display strings using the string command  
```  
cat gfc1  
OR  
strings gfc1  
```  
This is the operation is called static analysis.  
**Static Analysis**: A method of computer program debugging that is done by
examining the code without executing the program.  
We didn't execute this program, we only displayed the contents of them.  
> Tip: This is the single way to analyze executable files. If you were to
> analyze larger and more complex files, you would need a tool for static
> analysis. I recommend [Ghildra](https://ghidra-sre.org/) *You can find the
> flag using this tool as well!

> Ghildra is a "software reverse engineering suite of tools developed by NSA's
> Research Directorate in support of the Cybersecurity mission"

### Flag  
```  
nactf{un10ck_th3_s3cr3t5_w1th1n_cJfnX3Ly4DxoWd5g}  
```

Original writeup (https://github.com/JoshuEo/CTFs/tree/master/NACTF_2020).