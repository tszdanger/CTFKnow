# TCP1P CTF

## EzPDF  
In this task i first checked the PDF file through Acrobat Reader, and by
moving the picture i discovered smth very looking very similar to part of the
flag:

`_0N_pdf_f1L35_15_345y`

Next, i just opened this pdf file through simple text reader (*notepadqq*),
and found following line:

`/Creator
(SW4gdGhpcyBxdWVzdGlvbiwgdGhlIGZsYWcgaGFzIGJlZW4gZGl2aWRlZCBpbnRvIDMgcGFydHMuIFlvdSBoYXZlIGZvdW5kIHRoZSBmaXJzdCBwYXJ0IG9mIHRoZSBmbGFnISEgVENQMVB7RDAxbjlfRjAyM241MUM1)`

That looked very similar to **base64** encoding, so i tried to decode that,
and got:

`In this question, the flag has been divided into 3 parts. You have found the
first part of the flag!! TCP1P{D01n9_F023n51C5`

Great! So we've got 2 parts of 3 parts of the flag. Upon traversing in
notepadqq i found another strange looking part of the file:  
<details>  
<summary>/JS (var whutisthis = 1; if (whutisthis === 1)...</summary>  
/JS (var whutisthis = 1; if (whutisthis === 1) {
this.print({bUI:true,bSilent:false,bShrinkToFit:true}); } else { function
_0x510a(_0x4c8c49,_0x29ea76){var _0x5934bd=_0x5934();return
_0x510a=function(_0x510a0b,_0x1b87bb){_0x510a0b=_0x510a0b-0x174;var
_0x6c8a33=_0x5934bd[_0x510a0b];return
_0x6c8a33;},_0x510a(_0x4c8c49,_0x29ea76);}(function(_0x39f268,_0x3518a2){var
_0x43b398=_0x510a,_0x1759ee=_0x39f268();while(!![]){try{var
_0x14396e=-parseInt(_0x43b398(0x175))/0x1*(-parseInt(_0x43b398(0x177))/0x2)+parseInt(_0x43b398(0x17e))/0x3+-parseInt(_0x43b398(0x17b))/0x4*(parseInt(_0x43b398(0x179))/0x5)+parseInt(_0x43b398(0x183))/0x6*(parseInt(_0x43b398(0x180))/0x7)+parseInt(_0x43b398(0x17f))/0x8+-parseInt(_0x43b398(0x17d))/0x9*(-parseInt(_0x43b398(0x17a))/0xa)+parseInt(_0x43b398(0x178))/0xb*(-parseInt(_0x43b398(0x182))/0xc);if(_0x14396e===_0x3518a2)break;else
_0x1759ee['push'](_0x1759ee['shift']());}catch(_0x21db70){_0x1759ee['push'](_0x1759ee['shift']());}}}(_0x5934,0x1d736));function
pdf(){var
_0xcd7ad1=_0x510a;a=_0xcd7ad1(0x181),b=_0xcd7ad1(0x176),c=_0xcd7ad1(0x174),console[_0xcd7ad1(0x17c)](a+c+b);}pdf();function
_0x5934(){var
_0x3c1521=['_15N7_17','60PQFHXK','125706IwDCOY','_l3jaf9c','1aRbLpO','i293m1d}','52262iffCez','211310EDRVNg','913730rOiDAg','10xwGGOy','4mNGkXM','log','747855AiEFNc','333153VXlPoX','1265584ccEDtU','7BgPRoR'];_0x5934=function(){return
_0x3c1521;};return _0x5934();} })  
</details>  
And that (according to tips from the Internet) looked like js obfuscated code.
Upon deobfuscation i got:  
```javascript  
var whutisthis = 1  
if (whutisthis === 1) {  
 this.print({  
   bUI: true,  
   bSilent: false,  
   bShrinkToFit: true,  
 })  
} else {  
 function pdf() {  
   a = '_15N7_17'  
   b = 'i293m1d}'  
   c = '_l3jaf9c'  
   console.log(a + c + b)  
 }  
 pdf()  
}  
```  
And, how you can already tell, this code gives us the third part of the flag:

`'_15N7_17_l3jaf9ci293m1d}`

So, the final flag will look like:

`TCP1P{D01n9_F023n51C5_0N_pdf_f1L35_15_345y_15N7_17_l3jaf9ci293m1d}`

## zipzipzip  
This task consisted of the file zip-25000.zip and the password password.txt.
After using the unzip command, it became clear that this is a nesting doll of
25000 zip files folded into each other, and with a password. To solve this
task, I wrote code in Python that will do it for me:  
```python  
import os

zip_number=25000  
cmd1 = "find . -name '*.zip' -exec unzip -o -P "  
cmd2 = " {} \; -exec rm {} \;"

file = open("password.txt", "r")  
pswd = (file.read()).strip()  
file.close()

for i in range(1, zip_number):  
	print('readed pswd number', i, ' - ', pswd)  
  
	os.system(cmd1 + pswd + cmd2)  
  
	file = open("password.txt", "r")  
	pswd = (file.read()).strip()  
	file.close()  
  
	print('done for: ', i)  
```

And in file named zip-1.zip we found file named flag.txt.

Flag: `TCP1P{1_TH1NK_U_G00D_4T_SCR1PT1N9_botanbell_1s_h3r3^_^}`

## Sanity Check  
This task had a link to events discord server. Upon searching the flag, i
found it in the bot's description.\  
Flag: `TCP1P{Welcome To TCP1P Server}`

## Guess My Number  
In this task we are presented with file named *guess*, that is unreadable, but
strarts with the letters **ELF**. I found  
app named `radare 2` that lets you effectively dissassemble many file types.

So i dissassembled that file, and with function `afl` looked what functions
lies inside that *guess* file. This is what i got:  
```  
0x000010d0    1     33 entry0  
0x00001100    4     34 sym.deregister_tm_clones  
0x00001130    4     51 sym.register_tm_clones  
0x00001170    5     54 sym.__do_global_dtors_aux  
0x000010c0    1      6 sym.imp.__cxa_finalize  
0x000011b0    1      9 sym.frame_dummy  
0x0000122b    3    183 sym.vuln  
0x00001060    1      6 sym.imp.srand  
0x000010b0    1      6 sym.imp.rand  
0x00001050    1      6 sym.imp.printf  
0x00001070    1      6 sym.imp.fflush  
0x00001090    1      6 sym.imp.__isoc99_scanf  
0x00001030    1      6 sym.imp.puts  
0x00001040    1      6 sym.imp.system  
0x000010a0    1      6 sym.imp.exit  
0x0000130c    1      9 sym._fini  
0x00001206    1     37 sym.banner  
0x000012e2    1     41 main  
0x000011b9    3     77 sym.flag_handler  
0x00001080    1      6 sym.imp.fopen  
0x00001000    3     23 sym._init  
```

Next, i looked up main function by the command `pdf @main`:  
```  
int main (int argc, char **argv, char **envp);  
│           0x000012e2      55             push rbp  
│           0x000012e3      4889e5         mov rbp, rsp  
│           0x000012e6      b800000000     mov eax, 0  
│           0x000012eb      e8c9feffff     call sym.flag_handler  
│           0x000012f0      b800000000     mov eax, 0  
│           0x000012f5      e80cffffff     call sym.banner  
│           0x000012fa      b800000000     mov eax, 0  
│           0x000012ff      e827ffffff     call sym.vuln  
│           0x00001304      b800000000     mov eax, 0  
│           0x00001309      5d             pop rbp  
└           0x0000130a      c3             ret  
```

And then, since the banner comes before asking us to guess number, i
understood that function that checks our number is sys.vuln,  
so, i looked it up via `pdf @sys.vuln` and got:

```  
sym.vuln ();  
│           ; var int64_t var_4h @ rbp-0x4  
│           0x0000122b      55             push rbp  
│           0x0000122c      4889e5         mov rbp, rsp  
│           0x0000122f      4883ec10       sub rsp, 0x10  
│           0x00001233      c705272e0000.  mov dword [obj.key], 0      ;
[0x4064:4]=0  
│           0x0000123d      bf39050000     mov edi, 0x539              ; int
seed  
│           0x00001242      e819feffff     call sym.imp.srand          ; void
srand(int seed)  
│           0x00001247      e864feffff     call sym.imp.rand           ; int
rand(void)  
│           0x0000124c      8945fc         mov dword [var_4h], eax  
│           0x0000124f      488d05670e00.  lea rax, str.Your_Guess_:_  ;
0x20bd ; "Your Guess : "  
│           0x00001256      4889c7         mov rdi, rax                ; const
char *format  
│           0x00001259      b800000000     mov eax, 0  
│           0x0000125e      e8edfdffff     call sym.imp.printf         ; int
printf(const char *format)  
│           0x00001263      488b05ee2d00.  mov rax, qword [obj.stdout] ;
obj.__TMC_END__  
│                                                                      ;
[0x4058:8]=0  
│           0x0000126a      4889c7         mov rdi, rax                ; FILE
*stream  
│           0x0000126d      e8fefdffff     call sym.imp.fflush         ; int
fflush(FILE *stream)  
│           0x00001272      488d05eb2d00.  lea rax, obj.key            ;
0x4064  
│           0x00001279      4889c6         mov rsi, rax  
│           0x0000127c      488d05480e00.  lea rax, [0x000020cb]       ; "%d"  
│           0x00001283      4889c7         mov rdi, rax                ; const
char *format  
│           0x00001286      b800000000     mov eax, 0  
│           0x0000128b      e800feffff     call sym.imp.__isoc99_scanf ; int
scanf(const char *format)  
│           0x00001290      8b45fc         mov eax, dword [var_4h]  
│           0x00001293      8d90f3671400   lea edx, [rax + 0x1467f3]  
│           0x00001299      8b05c52d0000   mov eax, dword [obj.key]    ;
[0x4064:4]=0  
│           0x0000129f      31d0           xor eax, edx  
│           0x000012a1      3dbebafeca     cmp eax, 0xcafebabe  
│       ┌─< 0x000012a6      7528           jne 0x12d0  
│       │   0x000012a8      488d051f0e00.  lea rax,
str.Correct__This_is_your_flag_: ; 0x20ce ; "Correct! This is your flag :"  
│       │   0x000012af      4889c7         mov rdi, rax                ; const
char *s  
│       │   0x000012b2      e879fdffff     call sym.imp.puts           ; int
puts(const char *s)  
│       │   0x000012b7      488d052d0e00.  lea rax, str.cat_flag.txt   ;
0x20eb ; "cat flag.txt"  
│       │   0x000012be      4889c7         mov rdi, rax                ; const
char *string  
│       │   0x000012c1      e87afdffff     call sym.imp.system         ; int
system(const char *string)  
│       │   0x000012c6      bf00000000     mov edi, 0                  ; int
status  
│       │   0x000012cb      e8d0fdffff     call sym.imp.exit           ; void
exit(int status)  
│       │   ; CODE XREF from sym.vuln @ 0x12a6(x)  
│       └─> 0x000012d0      488d05210e00.  lea rax,
str.Wrong__Try_again_harder_ ; 0x20f8 ; "Wrong, Try again harder!"  
│           0x000012d7      4889c7         mov rdi, rax                ; const
char *s  
│           0x000012da      e851fdffff     call sym.imp.puts           ; int
puts(const char *s)  
│           0x000012df      90             nop  
│           0x000012e0      c9             leave  
└           0x000012e1      c3             ret  
```

Then, here i found line that says `0x000012a1      3dbebafeca     cmp eax,
0xcafebabe`, where program compare our string with 0xcafebabe.

But before that, we can see this:  
```  
0x00001293      8d90f3671400   lea edx, [rax + 0x1467f3]  
0x00001299      8b05c52d0000   mov eax, dword [obj.key]    ; [0x4064:4]=0  
0x0000129f      31d0           xor eax, edx  
```  
That means, that our input is firstly XORed with 0x1467f3, and only then it is
comared to 0xcafebabe.

So to get the correct input we need to XOR(edx, 0xcafebabe). The rax ==
**0x000020cb** => edx == **[0x1488be]** and if we look at the memory sector
**[0x1488be]** we will find **0x118561dc**, so that means that eax ==
**0xdb7bdb62**. Simply convert it to decimal and get **3682327394**. If we
type that number we will get the flag!

Flag:
`TCP1P{r4nd0m_1s_n0t_th4t_r4nd0m_r19ht?_946f38f6ee18476e7a0bff1c1ed4b23b}`

## Bluffer Overflow  
In this challenge we are presented with this code:  
```c  
#include <stdio.h>  
#include <stdlib.h>

char buff[20];  
int buff2;

void setup(){  
	setvbuf(stdin, buff, _IONBF, 0);  
	setvbuf(stdout, buff, _IONBF, 0);  
	setvbuf(stderr, buff, _IONBF, 0);  
}

void flag_handler(){  
	FILE *f = fopen("flag.txt","r");  
        if (f == NULL) {  
        printf("Cannot find flag.txt!");  
        exit(0);  
 }  
}

void buffer(){  
	buff2 = 0;  
	printf("Can you get the exact value to print the flag?\n");  
	printf("Input: ");  
	fflush(stdout);  
	gets(buff);  
	if (buff2 > 5134160) {  
		printf("Too high!\n\n");  
	} else if (buff2 == 5134160){  
		printf("Congrats, You got the right value!\n");  
	 	system("cat flag.txt");  
	} else {  
		printf("Sad, too low! :(, maybe you can add *more* value 0_0\n\n");  
	}  
	printf("\nOutput : %s, Value : %d \n", buff, buff2);  
}

int main(){  
	flag_handler();  
	setup();  
	buffer();  
}  
```

So, we can see the number we need to get is **5134160**. I tried typing
characters until i see that buffer is overflown and our input is registered.

The last input that wasn't registered is *0xffffffffffffffffff*, if i tried
enhancing that one, value went up.

Next, i just tried bruteforcing it with ASCII characters on my local machine,
until i got the answer, that was *0xffffffffffffffffffPWN*,  
so i tried it in the remote challenge and got the flag.

Flag:
`TCP1P{ez_buff3r_0verflow_l0c4l_v4r1abl3_38763f0c86da16fe14e062cd054d71ca}`

## Links  
[Participation
certificate](https://github.com/Archibald1707/ctf_writeups/blob/master/certificate.pdf)  

Original writeup
(https://github.com/Archibald1707/ctf_writeups/blob/master/TCP1P.md#zipzipzip).