The task has a quite meaningless description: "I love reversing!" and an
archive with a binary file attached.

Opening the fine in IDA Pro after some basic analysis we can see, that user is
requested to input a string (let's call it `input`), which is then transformed
in some way (via `transform_input`) and then compared with another string
(`target_string`), that is constructed from some embedded data by XOR-ing each
byte with some mysterious value called ``magic`. Here is some decompiled code
from IDA with some comments and formatting:

```c  
// Input flag  
printf("flag > ");  
__isoc99_scanf("%s", input);

// Transform flag  
input_len = strlen(input);  
transform_input(input, input_len, (void **)&transformed_input);

// Calculate a reference value for transformed flag  
sub_15D8(1886873447);  
x = a4;  
v8 = (int)pow(a4, 2.0);  
y = *(double *)&qword_4028 * *(double *)&qword_4020;  
magic = (int)fmod((double)v8, *(double *)&qword_4028 * *(double
*)&qword_4020);  
for ( i = 0; i <= 0x2B; ++i )  
 target_string[i] ^= magic;

// Compare transformed flag with its reference value and print result  
if ( !strcmp(transformed_input, target_string) )  
 puts("congrats!");  
else  
 puts("try again :)");  
```

Looking deeper into `transform_input` function we can find out some
interesting things. It uses some `alphabet` constant to perform a
transformation:  
```c  
...  
HIBYTE(v23) = v22 & 0x3F;  
(*transformed_input)[v14] = alphabet[(unsigned __int8)v21 >> 2];  
...  
```

This alphabet looks as follows:
`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`. Very
similar to BASE64 alphabet, isn't it? Let's assume, that `transform_input`
performs a BASE64 encoding.

So, `target_string` probably contains a BASE64 encoded flag. Let's try to leak
this value. Consider the call of `puts` function:

```assembly  
48 8D 3D F1 06 00 00                 lea     rdi, s          ; "congrats!"  
E8 A1 F7 FF FF                       call    _puts  
```

As we can see, address of a string that will be printed is loaded into `rdi`
register and then `puts` function is called. Let's try to load into `rdi` the
`target_string` and call `puts` by patching the binary. Here is a bit wider
code snippet from the binary:  
```assembly  
48 8D 35 D9 26 00 00                 lea     rsi, target_string ;
"sZ\\xvUH%vUzzp"     ; (1)  
48 89 C7                             mov     rdi, rax        ;
transformed_input  
E8 11 F8 FF FF                       call    _strcmp  
85 C0                                test    eax, eax  
75 0E                                jnz     short loc_1981  
48 8D 3D F1 06 00 00                 lea     rdi, s          ; "congrats!"  
E8 A1 F7 FF FF                       call    _puts
; (2)  
EB 0C                                jmp     short loc_198D  
                    ; ---------------------------------------------------------------------------

                    loc_1981:                               ; CODE XREF: main+149↑j  
48 8D 3D ED 06 00 00                 lea     rdi, aTryAgain  ; "try again :)"  
E8 93 F7 FF FF                       call    _puts
; (2)  
```

We are interested in the following lines: (1) here the address of
`target_string` is loaded into `rsi` register, and here (2) the function
`puts` is called. The first line must be changed to load the address of
`target_string` into `rdi` instead of `rsi`, and there must not be any other
instructions, that affect this register between the modified line and the
closest `puts` call.

First of all let's change the register the address of `target_string` is
loaded in. This can be done just by replacing the third byte of the
instruction with the value of `0x3D`. We got the following line of code:  
```assembly  
48 8D 3D D9 26 00 00                 lea     rdi, target_string ;
"sZ\\xvUH%vUzzp"  
```

But what shall we do with the rest of instructions up to the closest call of
`puts`? Well, just set these bytes to `0x90`, i.e. `nop` instruction. I got
the following code:

```assembly  
48 8D 3D D9 26 00 00                 lea     rdi, target_string ;
"sZ\\xvUH%vUzzp"  
90                                   nop  
90                                   nop                     ;
transformed_input  
90                                   nop  
90                                   nop  
90                                   nop  
90                                   nop  
90                                   nop  
90                                   nop  
85 C0                                test    eax, eax  
75 0E                                jnz     short loc_1981  
90                                   nop  
90                                   nop  
90                                   nop  
90                                   nop  
90                                   nop  
90                                   nop  
90                                   nop  
E8 A1 F7 FF FF                       call    _puts  
EB 0C                                jmp     short loc_198D  
                    ; ---------------------------------------------------------------------------

                    loc_1981:                               ; CODE XREF: main+149↑j  
90                                   nop  
90                                   nop  
90                                   nop  
90                                   nop  
90                                   nop  
90                                   nop  
90                                   nop  
E8 93 F7 FF FF                       call    _puts  
```

Now we need to save patched binary and just run it:

```bash  
┌──(z㉿z)-[~/reverse]  
└─$ ./ezrev  
flag > test  
aHNjdGZ7dGhhbmtzX2Zvcl9lbmpveWluZ19oc2N0ZiF9  
```

We got a string, let's decode it from BASE64 to obtain a flag:

```bash  
┌──(z㉿z)-[~/reverse]  
└─$ echo aHNjdGZ7dGhhbmtzX2Zvcl9lbmpveWluZ19oc2N0ZiF9 | base64 -d                                                                                                                                                      1 ⨯  
hsctf{thanks_for_enjoying_hsctf!}  
```Decompiling the class file:

```java  
import java.util.Arrays;

//  
// Decompiled by Procyon v0.5.36  
//

public class EZrev  
{  
   public static void main(final String[] array) {  
       if (array.length != 1) {  
           System.out.println("L");  
           return;  
       }  
       final String s = array[0];  
       if (s.length() != 31) {  
           System.out.println("L");  
           return;  
       }  
       final int[] array2 = s.chars().toArray();  
       for (int i = 0; i < array2.length; ++i) {  
           if (i % 2 == 0) {  
               array2[i] = (char)(array2[i] ^ 0x13);  
           }  
           else {  
               array2[i] = (char)(array2[i] ^ 0x37);  
           }  
       }  
       for (int j = 0; j < array2.length / 2; ++j) {  
           if (j % 2 == 0) {  
               final int n = array2[j] - 10;  
               array2[j] = (char)(array2[array2.length - 1 - j] + 20);  
               array2[array2.length - 1 - j] = (char)n;  
           }  
           else {  
               array2[j] = (char)(array2[j] + 30);  
           }  
       }  
       if (Arrays.equals(array2, new int[] { 130, 37, 70, 115, 64, 106, 143, 34, 54, 134, 96, 98, 125, 98, 138, 104, 25, 3, 66, 78, 24, 69, 91, 80, 87, 67, 95, 8, 25, 22, 115 })) {  
           System.out.println("W");  
       }  
       else {  
           System.out.println("L");  
       }  
   }  
}  
```

Reverse the process using the script to get the flag (credits to my
[teammate](https://github.com/hollowcrust))

```py  
a = [130, 37, 70, 115, 64, 106, 143, 34, 54, 134, 96, 98, 125, 98, 138,  
104, 25, 3, 66, 78, 24, 69, 91, 80, 87, 67, 95, 8, 25, 22, 115]

s = []

for i in range(15):  
   if(i%2!=0):  
       a[i] -= 30  
   else:  
       a[i], a[30-i] = a[30-i]+10, a[i]-20  
for i in range(31):  
   if(i%2 == 0):  
       a[i] ^= 0x13  
   else:  
       a[i] ^= 0x37  
for i in range(31):  
   print(chr(a[i]), end="")  
```

Flag: `n00bz{r3v_1s_s0_e4zy_r1ght??!!}`

Original writeup (https://jp-ch.gq/reverse/n00bzCTF-2023.html#ezrev).