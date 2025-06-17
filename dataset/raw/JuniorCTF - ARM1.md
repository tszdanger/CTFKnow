# Junuior ARM1 - easy

**Category:** rev  
**Points:** 41  
**Solves:** 269  
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

[Challenge binary](arm_stage1.bin)

## Write-up

We can:  
1. get strings from file  
```  
pc@pc:~/Desktop$ strings arm_stage1.bin | grep 34C3  
FpGThe flag is: 34C3_I_4dm1t_it_1_f0und_th!s_with_str1ngs  
```  
2. reverse it! :D

Load file in IDA, set "Processor type" to "ARM little-endian", then set "ROM
start address" and "Loading address" to 0x8000000.

sub_8000108 - is first function(entry point), and only call function
sub_8000478, sub_8000478 call sub_8000290, sub_8000290 is main.

In main we have code like this  
```C  
void main(void) {  
 sub_80003F8();  
 sub_8000304();  
 print_text("The flag is: 34C3_I_4dm1t_it_1_f0und_th!s_with_str1ngs\r\n");  
 while ( 1 )  
   ;  
}  
```  
3. After reverse we found out that we could just run file(in emulator)

Flag is: **34C3_I_4dm1t_it_1_f0und_th!s_with_str1ngs**  

Original writeup (https://github.com/KosBeg/ctf-
writeups/tree/master/34C3_CTF/arm_stage1).