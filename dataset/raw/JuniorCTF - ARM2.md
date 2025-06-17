# Junuior ARM2 - easy

**Category:** rev  
**Points:** 150  
**Solves:** 30  
**Description:**

Can you reverse engineer this code and get the flag?

This code is ARM Thumb 2 code which runs on an STM32F103CBT6. You should not
need such a controller to solve this challenge.

There are 5 stages in total which share all the same code base, so you are
able to compare code from the first stage with all the other stages to see
what code is actually relevant.

If you should need a datasheet, [you can get it
here](http://www.st.com/content/ccc/resource/technical/document/reference_manual/59/b9/ba/7f/11/af/43/d5/CD00171190.pdf/files/CD00171190.pdf/jcr:content/translations/en.CD00171190.pdf).

In case you need to refresh your ARM assembly, [check out Azeria's cool
articles](https://azeria-labs.com/writing-arm-assembly-part-1/).

[Challenge binary](arm_stage2.bin)

## Write-up

We can:  
1. reverse it! :D

Load file in IDA, set "Processor type" to "ARM little-endian", then set "ROM
start address" and "Loading address" to 0x8000000.

sub_8000108 - is first function(entry point), and only call function
sub_80004A8, sub_80004A8 call sub_8000290, sub_8000290 is main.

In main we have code like this  
```C  
void main(void) {  
 sub_8000428();  
 sub_8000334();  
 print_text("The flag is: ");  
 for ( char *i = g_xored_bytes; *i; ++i )  
   print_char(*i ^ 0x55);  
 print_text("\r\n");  
 while ( 1 )  
   ;  
}  
```

Solver  
```python  
xored_bytes = [ 0x66, 0x61, 0x16, 0x66, 0x0A, 0x0D, 0x65, 0x27, 0x0A, 0x66,
0x3B, 0x36, 0x27, 0x2C, 0x25, 0x21, 0x3C, 0x65, 0x3B, 0x0A, 0x64, 0x26, 0x0A,
0x37, 0x66, 0x26, 0x21, 0x0A, 0x36, 0x27, 0x2C, 0x25, 0x21, 0x65 ]  
flag = ""

for i in xored_bytes:  
 flag += chr(i ^ 0x55)

print flag # 34C3_X0r_3ncrypti0n_1s_b3st_crypt0  
```

2. After reverse we found out that we could just run file(in emulator)

Flag is: **34C3_X0r_3ncrypti0n_1s_b3st_crypt0**  

Original writeup (https://github.com/KosBeg/ctf-
writeups/tree/master/34C3_CTF/arm_stage2).