# Super Secure Vault

Binary, 400 points

## Description

*Open the Vault to get the treasure.*

## Solution

We were given an ELF, [vault](vault). Let's try it out:

```console  
╭─face0xff@aniesu-chan ~/ctf/pragyan/vault  
╰─$ ./vault  
Enter the key: abc  
Wrong key.  
```

Let's disassemble it and generate some pseudocode using IDA:

```c  
int __cdecl main(int argc, const char **argv, const char **envp)  
{  
 unsigned int v3; // ST0C_4  
 unsigned int v4; // ST0C_4  
 unsigned int v5; // ST0C_4  
 unsigned int v6; // ST0C_4  
 __int64 v7; // rsi  
 int v9; // [rsp+14h] [rbp-BCh]  
 int v10; // [rsp+14h] [rbp-BCh]  
 int v11; // [rsp+14h] [rbp-BCh]  
 int v12; // [rsp+20h] [rbp-B0h]  
 int v13; // [rsp+24h] [rbp-ACh]  
 int v14; // [rsp+28h] [rbp-A8h]  
 int v15; // [rsp+2Ch] [rbp-A4h]  
 int v16; // [rsp+30h] [rbp-A0h]  
 int v17; // [rsp+34h] [rbp-9Ch]  
 int v18; // [rsp+38h] [rbp-98h]  
 int v19; // [rsp+3Ch] [rbp-94h]  
 int v20; // [rsp+40h] [rbp-90h]  
 int v21; // [rsp+44h] [rbp-8Ch]  
 char s; // [rsp+50h] [rbp-80h]  
 char v23; // [rsp+90h] [rbp-40h]  
 unsigned __int64 v24; // [rsp+C8h] [rbp-8h]  
  
 v24 = __readfsqword(0x28u);  
 v12 = 213;  
 v13 = 8;  
 v14 = 229;  
 v15 = 5;  
 v16 = 25;  
 v17 = 4;  
 v18 = 83;  
 v19 = 7;  
 v20 = 135;  
 v21 = 5;  
 printf("Enter the key: ", argv, envp);  
 __isoc99_scanf("%s", &s);  
 if ( strlen(&s) > 0x1E )  
   fail(0LL);  
 v3 = getNum((__int64)"27644437104591489104652716127", 0, v13);  
 if ( (unsigned int)mod(&s, v3) != v12 )  
   fail(0LL);  
 v9 = v13;  
 v4 = getNum((__int64)"27644437104591489104652716127", v13, v15);  
 if ( (unsigned int)mod(&s, v4) != v14 )  
   fail(0LL);  
 v10 = v15 + v9;  
 v5 = getNum((__int64)"27644437104591489104652716127", v10, v17);  
 if ( (unsigned int)mod(&s, v5) != v16 )  
   fail(0LL);  
 v11 = v17 + v10;  
 v6 = getNum((__int64)"27644437104591489104652716127", v11, v19);  
 if ( (unsigned int)mod(&s, v6) != v18 )  
   fail(0LL);  
 v7 = (unsigned int)getNum((__int64)"27644437104591489104652716127", v19 +
v11, v21);  
 if ( (unsigned int)mod(&s, v7) != v20 )  
   fail(0LL);  
 printf("Enter password: ", v7);  
 __isoc99_scanf("%s", &v23);  
 func2(&v23, &s, "27644437104591489104652716127");  
 return 0;  
}  
```

This is the main function. It basically asks for a key that should not exceed
30 bytes, and then runs several getNum calls on a certain string
"27644437104591489104652716127".

```c  
__int64 __fastcall getNum(__int64 a1, int a2, int a3)  
{  
 unsigned int v4; // [rsp+18h] [rbp-8h]  
 int i; // [rsp+1Ch] [rbp-4h]  
  
 v4 = 0;  
 for ( i = a2; i < a2 + a3; ++i )  
   v4 = 10 * v4 + *(char *)(i + a1) - 48;  
 return v4;  
}  
```

getNum(s, i, j) simply seems to take the argument string s and cut it starting
from the i-th byte and keeping j bytes. It then converts it into a integer.

Here is the function mod :

```c  
__int64 __fastcall mod(const char *a1, int a2)  
{  
 unsigned int v3; // [rsp+18h] [rbp-18h]  
 int i; // [rsp+1Ch] [rbp-14h]  
  
 v3 = 0;  
 for ( i = 0; i < strlen(a1); ++i )  
   v3 = (signed int)(10 * v3 + a1[i] - 48) % a2;  
 return v3;  
}  
```

It just seems to compute a1 mod a2.

Let's put everything together ; the big number is divided into 5 parts:
`27644437, 10459, 1489, 1046527, 16127`, and for each of these, the program
calculates our input, which has to be a number less than 30 digits, modulus
the part. It then tests if it is equal to a certain hardcoded value. Here are
the conditions that need to be reunited:

```  
s = 213 mod 27644437  
s = 229 mod 10459  
s = 25 mod 1489  
s = 83 mod 1046527  
s = 135 mod 16127  
```

So it happens that all these moduli are co-prime, so we can use the Chinese
Remainder Theorem to compute s. You can check the full script to see how it is
computed.

We find that the lowest solution for s is 3087629750608333480917556.

Once we entered the key, we are asked for a password, and there is a call to
func2(password, s, "27644437104591489104652716127").

Here are the contents of func2:

```c  
int __fastcall func2(__int64 a1, char *a2, const char *a3)  
{  
 unsigned __int64 v3; // rax  
 int v4; // ST30_4  
 int v5; // ST34_4  
 int v7; // [rsp+24h] [rbp-3Ch]  
 int v8; // [rsp+28h] [rbp-38h]  
 int v9; // [rsp+28h] [rbp-38h]  
 int v10; // [rsp+2Ch] [rbp-34h]  
 int v11; // [rsp+2Ch] [rbp-34h]  
 char *v12; // [rsp+40h] [rbp-20h]  
  
 v12 = strcat(a2, a3);  
 v3 = (unsigned __int64)&v12[strlen(v12)];  
 *(_WORD *)v3 = 12344;  
 *(_BYTE *)(v3 + 2) = 0;  
 v7 = 0;  
 v8 = 0;  
 v10 = strlen(v12) >> 1;  
 while ( v8 < strlen(v12) >> 1 )  
 {  
   if ( *(_BYTE *)(v7 + a1) != matrix[100 * (10 * (v12[v8] - 48) + v12[v8 + 1]
- 48)  
                                    - 48  
                                    + 10 * (v12[v10] - 48)  
                                    + v12[v10 + 1]] )  
     fail(1LL);  
   ++v7;  
   v8 += 2;  
   v10 += 2;  
 }  
 v9 = 0;  
 v11 = strlen(v12) >> 1;  
 while ( v9 < strlen(v12) >> 1 )  
 {  
   v4 = 10 * (v12[v9] - 48) + v12[v9 + 1] - 48;  
   v5 = 10 * (v12[v11] - 48) + v12[v11 + 1] - 48;  
   if ( *(_BYTE *)(v7 + a1) != matrix[100 * (v4 * v4 % 97) + v5 * v5 % 97] )  
     fail(1LL);  
   ++v7;  
   v9 += 2;  
   v11 += 2;  
 }  
 puts("Your Skills are really great. Flag is:");  
 return printf("pctf{%s}\n", a1);  
}  
```

So basically what this does is, we concat s with 27644437104591489104652716127
and then we append "80" (the 12344 decimal). We obtain a string v3 =
"30876297506083334809175562764443710459148910465271612780".

Then some loops will compare each character of our password to a certain value
in "matrix". Looking it up on IDA, matrix is a 10000-byte chunk of ascii
characters, from which I dumped the contents in [matrix.txt](matrix.txt).

The only thing that is left for us to do is to calculate all the indexes that
will be read in the matrix to figure out the password. Here's the final
keygen:

```python  
from functools import reduce  
import binascii

def chinese_remainder(n, a):  
   s = 0  
   prod = reduce(lambda a, b: a*b, n)  
   for n_i, a_i in zip(n, a):  
       p = prod // n_i  
       s += a_i * mul_inv(p, n_i) * p  
   return s % prod  
  
def mul_inv(a, b):  
   b0 = b  
   x0, x1 = 0, 1  
   if b == 1: return 1  
   while a > 1:  
       q = a // b  
       a, b = b, a % b  
       x0, x1 = x1 - q * x0, x0  
   if x1 < 0:  
       x1 += b0  
   return x1

a = [213, 229, 25, 83, 135]  
n = [27644437, 10459, 1489, 1046527, 16127]  
N = 27644437104591489104652716127

s = chinese_remainder(n, a)

matrix = open('matrix.txt', 'r').read()  
matrix = matrix.replace(' ', '').replace('\r', '').replace('\n', '')  
matrix = binascii.unhexlify(matrix)

v12 = str(s) + str(N) + "80"  
v12 = list(map(int, list(v12)))

v8 = 0  
v10 = len(v12) // 2

password = b""  
while v8 < len(v12) // 2:  
   q_ = 100*(10*v12[v8]+v12[v8+1])+10*v12[v10]+v12[v10+1]  
   password += bytes([matrix[q_]])  
   v8 += 2  
   v10 += 2

v9 = 0  
v11 = len(v12) // 2

while v9 < len(v12) // 2:  
   v4 = 10 * v12[v9] + v12[v9 + 1]  
   v5 = 10 * v12[v11] + v12[v11 + 1]  
   password += bytes([matrix[100*(v4**2%97)+v5**2%97]])  
   v9 += 2  
   v11 += 2

print(s, password)  
```

and its output:

```console  
╭─face0xff@aniesu-chan ~/ctf/pragyan/vault  
╰─$ python vault.py  
3087629750608333480917556 b'R3v3rS1Ng_#s_h311_L0t_Of_Fun'  
```

Let's try it out.

```console  
╭─face0xff@aniesu-chan ~/ctf/pragyan/vault  
╰─$ ./vault  
Enter the key: 3087629750608333480917556  
Enter password: R3v3rS1Ng_#s_h311_L0t_Of_Fun  
Your Skills are really great. Flag is:  
pctf{R3v3rS1Ng_#s_h311_L0t_Of_Fun}  
```

Enjoy!

Note: actually, there are more than 100000 correct (key, password) couples.
Indeed, the solutions to the modular system of equations are all congruent
modulo the product of the five integers. I lost a lot of time because I was
looking for a 30-digit key instead of simply choosing the lowest solution,
which yields a "readable" "flag-looking" password flag.

Some examples of other valid flags...

```  
10353650500772965893596379 b'XbGeQsfL#soYFTr$Byze@PIFPiRf'  
17619671250937598306275202 b'F$ihT}L(nF$IqTGpajfB{hNgi@wf'  
24885692001102230718954025 b'@XvtR)LWe&v(mTeWiT(j!Yhp{gzf'  
32151712751266863131632848 b'VPgdRtre{hQXVTyiy*)WQjoEz@Zf'  
39417733501431495544311671 b'jayNQrSOeiABITafV_zKQVEoH!hf'  
46683754251596127956990494 b'edUeTTxtvxa)MTE^QjfpQWTp{cvf'  
```  

Original writeup
(https://github.com/face0xff/ctf/tree/master/2019/Pragyan_CTF/Super_Secure_Vault).