# Warmup (re, 600p, 31 solved)

## Description

In the task we get [ELF
binary](https://raw.githubusercontent.com/TFNS/writeups/master/2020-07-31-InCTF/re_warmup/warmup).  
It's pretty large and statically compiled, but by looking at `strings` we
immediately notice that (ironically) it's `strings`!  
We suspect that there is some added secret functionality and we need to locate
this patch.

## Analysis

Initially we thought about something like Diaphora or just bindiff, but for
statically compiled binary this could be rather hard to do.

Fortunately we quickly noticed one strange quirk - the usage was providing
description for the parameters, as it normally should!  
From this clue we looked at available parameters in the binary ->
`adfhzHn:wot:e:T:s:Vv0123456789`

If we compare this with original strings binary, you will notice there is a
special `z` parameter which normally is not present.

We can now follow this thread and see what exactly does this parameter do.  
Sadly ghidra didn't like the `switch` expression which parses the parameters,
so we switched to gdb for a moment, just to follow the switch, and we hit:

```  
004010a8 MOV dword ptr [magic_flag ],0x1  
```

So we know that special parameter sets this flag to 1.  
Now we follow x-refs to this flag, to see where it's used.  
There is only one function at `0x00400e10`.

This code reads input file, allocates memory and eventually we arrive at:

```c  
 index = 0;  
 do {  
   allocated_buffer[index] =  
        ((file_content[index] ^ (byte)index) + 0x41) - (char)(0x42 % (long)((int)index + 1));  
   index = index + 1;  
 } while ((ulong)(iVar3 - 1) + 1 != index);

 cVar2 = *allocated_buffer;  
 lVar5 = 0x2d;  
 pointer_to_consts = &some_consts;  
 pcVar6 = acStack72;  
 while (lVar5 != 0) {  
   lVar5 = lVar5 + -1;  
   *pcVar6 = *pointer_to_consts;  
   pointer_to_consts = pointer_to_consts + (ulong)bVar7 * -2 + 1;  
   pcVar6 = pcVar6 + (ulong)bVar7 * -2 + 1;  
 }  

 if (cVar2 == -0x56) {  
   lVar5 = 1;  
   do {  
     if (lVar5 == index) goto LAB_00400f06;  
     pcVar6 = allocated_buffer + lVar5;  
     pcVar1 = acStack72 + lVar5;  
     lVar5 = lVar5 + 1;  
   } while (*pcVar6 == *pcVar1);  
 }  
```

- First part is clearly some encryption/decryption process on the input file.  
- Second part is just `strcpy` of some constant values to the stack buffer.  
- Third part is just `strcmp` of input file encryption/decryption result with the loaded stack buffer

## Solution

We want now to simply invert the logic -> get the constants and apply inverse
of the encryption operation to, hopefully, recover the flag:

```python  
def main():  
   data = [0xAA, 0xB0, 0xA2, 0xB6, 0xA2, 0x91, 0x71, 0xB1, 0xA7, 0x80, 0x96,
0x97, 0x78, 0xB6, 0x9E, 0x99, 0x72, 0x97, 0x85, 0x98, 0x8F, 0x91, 0x7F, 0x77,  
           0x7C, 0x80, 0x9D, 0x61, 0xAB, 0x95, 0x8A, 0x7F, 0xB4, 0x8F, 0x9F, 0x35, 0x9F, 0x87, 0x8D, 0x98, 0x95, 0x9F, 0x8D, 0xAA]  
   result = ''  
   for i, d in enumerate(data):  
       result += chr((d + 0x42 % (i + 1) - 0x41) ^ i)  
   print(result)

main()  
```

And we get: `inctfU5uaL_W4rmUPs_NEED_STr1nGS_SO_1_GAVE_IT`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-07-31-InCTF/re_warmup/README.md).