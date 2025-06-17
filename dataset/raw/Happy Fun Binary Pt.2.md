My teammate (nobodyisnobody and macz) and I had a quick look on these
challenges, but we did not have time to flag anything but the first one during
the CTF.

After Happy Fun Binary Pt.1, we have a library called binary_of_ballas.so. The
binary dlopens the library and calls the symbol "foyer". We can simulate that
with this simple wrapper:  
```  
// gcc -m32 wrapper.c -o wrap -ldl  
#include <stdlib.h>  
#include <dlfcn.h>  
int main()  
{  
   void *h;  
   void *(*f)();  
   h = dlopen("./binary_of_ballas.so",2);  
   f = (void *(*)())dlsym(h,"foyer");  
   f();  
   dlclose(h);  
   return 0;  
}  
```

After some reversing work, the foyer function may look like this:  
```  
void foyer(void)  
{  
   int len;  
   int fd;  
   char buf1 [64];  
   char buf2 [192];  
   char command [256];

   puts("You emerge into a grand and extravegant foyer. While sparsely
furnished, intricately crafted code decorates every square inch of the walls
and ceiling. In the center of the room lies a grand structure, carved into
which are three slots. The three slots feed into a large chest in the middle
of the room. On the far side of the room lies 2 semi-circular doorways leading
into darkness.\n");  
   do {  
       fgets(buf1,0x40,stdin);  
       if (strcmp(buf1,"examine the doormat\n") == 0) {  
           printf("You look down, and are surprised to see a welcome mat beneath your feet. On it reads \"%s\". That was easy!\n","flag{yes_this_is_all_one_big_critical_role_reference}");  
       }  
       if (strcmp(buf1,"examine the treasure chest\n") == 0) {  
           puts("Inscribed on the chest is the message: \"Welcome to my halls, adventurer. I have left my worldly belongings in this chest, to be claimed by one worthy enough to inherit my mantle. In my halls you will find three flags. These flags, along with the contents of this chest, will prove to be more valuable than you can imagine. I wish you luck in your attempts to decipher my puzzles\"\n");  
       }  
       if (strcmp(buf1,"open the treasure chest\n") == 0) {

           puts("You go to open the chest, and see 3 slots engraved into the lock. You gather that you need to place your 3 flags in these slots to open it.\nfirst flag:\n");  
           fgets(buf1,0x40,stdin);  
           len = strlen(buf1);  
           buf1[len-1] = 0;  
           strcat(buf2,buf1);

           puts("second flag: ");  
           fgets(buf1,0x40,stdin);  
           len = strlen(buf1);  
           buf1[len-1] = 0;  
           strcat(buf2,buf1);

           puts("third flag: ");  
           fgets(buf1,0x40,stdin);  
           len = strlen(buf1);  
           buf1[len-1] = 0;  
           strcat(buf2,buf1);

           sprintf(command,"unzip -P %s chest",buf2);  
           fd = fopen("chest","w");  
           fwrite(chest,1,0xf6,fd);  
           fclose(fd);  
           system(command);  
       }  
       if (strcmp(buf1,"enter the first doorway\n") == 0) {  
           puts("You step through the doorway...\n");  
           chall_1();  
       }  
       if (strcmp(buf1,"enter the second doorway\n") == 0) {  
           puts("You step through the doorway...\n");  
           chall_2();  
       }  
   } while( true );  
}  
```

The first flag is in sight. To get the second flag, we need to reverse the the
function chall_1. This is not an easy task as it involves extended precision
float of 80 bits and some basic structures:  
```  
struct what {  
   char c,         // + 0x0  
   float80 f1,     // + 0x4  
   float80 f2      // + 0x10  
} //(size = 0x1c = 28)

struct hell {  
   char c,         // + 0x0  
   float80 f       // + 0x4  
} //(size = 0x10 = 16)  
```

The function initializes a table of five "what" from the values of an another
table of five "hell" stored in the library data. It defines five contiguous
intervals for the five letters: p, b, e, }, _

A python implementation may look like this:  
```  
import gmpy2  
from gmpy2 import mpfr as f  
gmpy2.get_context().precision=100

def float80(x):  
   if x & (1<<79):  
       s = f(-1.0)  
   else:  
       s = f(1.0)  
   e = (x & ((1<<79)-1)) >> 64  
   m = x & ((1<<64)-1)  
   if m & 0x8000000000000000:  
       i = f(1.0)  
   else:  
       i = f(0.0)  
   m &= 0x7FFFFFFFFFFFFFFF  
   res = gmpy2.div(f(m),f(1<<63))  
   res = gmpy2.add(res,i)  
   res = gmpy2.mul(res,f(2**(e - 16383)))  
   return gmpy2.mul(s,res)  
  
def frfc(c, wth, five):  
   for i in range(5):  
       if c == wth[i][0]:  
           return wth[i]  
   exit("ooops")

def encode(f1, f2, flag, five):  
   global wtf  
   tmp_float = f1;  
   for i in range(5):  
       wtf[i][1] = tmp_float  
       wtf[i][2] = tmp_float + (gmpy2.add(tmp_float, gmpy2.mul(gmpy2.sub(f2, f1), table[i][1]))f2- f1) * table[i][1]  
       tmp_float = wtf[i][2]  
   debugWTF()  
   wha = frfc(flag[0], wtf, five);  
   if len(flag) == 1 :  
       res = gmpy2.div(gmpy2.add(wha[1],wha[2]), A)  
   else:  
       res = encode(wha[1], wha[2], flag[1:], five)  
   return res

def debugWTF():  
   for w in wtf:  
       print( "%s | %.20f | %.20f | delta: %.20f" %(w[0], w[1],w[2],w[2]-w[1]) )  
   print()

# init table @ 0xf7fcc0a0  
table = []  
table.append(("p", float80(0x3ffd86bca50000000000)))  
table.append(("b", float80(0x3ffcd794210000000000)))  
table.append(("e", float80(0x3ffdbca1ad0000000000)))  
table.append(("}", float80(0x3ff9d794a70000000000)))  
table.append(("_", float80(0x3ffc86bca50000000000)))

# init float used in encode  
A = float80(0x40008000000000000000) # = 2.0

# init values of wtf  
wtf = [["",0.0,0.0] for i in range(5)]  
tmpf = f(0.0)  
for i in range(5):  
   wtf[i][0] = table[i][0]  
   wtf[i][1] = tmpf  
   tmpf = gmpy2.add(tmpf, table[i][1])  
   wtf[i][2] = tmpf

print(encode(f(0.0),f(1.0),"beeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeep}",5))  
```

We see that the encode function is called recursively for each letter of the
flag. Each time, the intervals are narrowed to match the previous chosen
interval. When entering the function chal_1, we are given a float ~ 0.406562.
Let's try to get a flag that gives this value, by selecting the letter
corresponding to the interval that matches this initial value:  
```  
import gmpy2  
from gmpy2 import mpfr as f  
gmpy2.get_context().precision=100

def float80(x):  
   if x & (1<<79):  
       s = f(-1.0)  
   else:  
       s = f(1.0)  
   e = (x & ((1<<79)-1)) >> 64  
   m = x & ((1<<64)-1)  
   if m & 0x8000000000000000:  
       i = f(1.0)  
   else:  
       i = f(0.0)  
   m &= 0x7FFFFFFFFFFFFFFF  
   res = gmpy2.div(f(m),f(1<<63))  
   res = gmpy2.add(res,i)  
   res = gmpy2.mul(res,f(2**(e - 16383)))  
   return gmpy2.mul(s,res)  
  
def frfc(c, wth, five):  
   for i in range(5):  
       if c == wth[i][0]:  
           return wth[i]  
   exit("ooops")

def narrowWTF(i):  
   global wtf  
   f1 = wtf[i][1]  
   f2 = wtf[i][2]  
   tmp_float = f1;  
   for i in range(5):  
       wtf[i][1] = tmp_float  
       wtf[i][2] = gmpy2.add(tmp_float, gmpy2.mul(gmpy2.sub(f2, f1), table[i][1]))  
       tmp_float = wtf[i][2]

def debugWTF():  
   for w in wtf:  
       print( "%s | %.20f | %.20f | delta: %.20f" %(w[0], w[1],w[2],w[2]-w[1]) )  
   print()  
  
# init table @ 0xf7fcc0a0  
table = []  
table.append(("p", float80(0x3ffd86bca50000000000)))  
table.append(("b", float80(0x3ffcd794210000000000)))  
table.append(("e", float80(0x3ffdbca1ad0000000000)))  
table.append(("}", float80(0x3ff9d794a70000000000)))  
table.append(("_", float80(0x3ffc86bca50000000000)))

# init float used in encode  
A = float80(0x40008000000000000000) # = 2.0

# init value of thefloat  
target = float80(0x3ffdd028f580b8df35b3)

# init values of wtf  
wtf = [["",0.0,0.0] for i in range(5)]  
tmpf = f(0.0)  
for i in range(5):  
   wtf[i][0] = table[i][0]  
   wtf[i][1] = tmpf  
   tmpf = gmpy2.add(tmpf, table[i][1])  
   wtf[i][2] = tmpf

# get the  flag  
flag = "flag{"  
while 1:  
   goodi = -1  
   for i,w in enumerate(wtf):  
       if w[1] <= target < w[2]:  
           flag += w[0]  
           print( flag )  
           goodi = i  
           break  
   if goodi < 0:  
       print( flag )  
       print( target )  
       debugWTF()  
       exit("oof")  
  
   elif flag[-1] == "}":  
       print( flag )  
       exit()  
  
   narrowWTF(goodi)  
```

This gives us the flag: flag{beep_beeep_bbbeeep_beeeeppppp}