**Description**

> the format of flag is flag{.+}  
>  
> attachment:  
>  
> https://drive.google.com/open?id=1JoAvVnUJOO-E-E2C2qGH1QDVAVu6-qiS

**Solution**

Opened the executable in IDA, and many SSE instructions were found :\(

For SSE instructions, it is even more clear to read assembly than to read the
F5 decompiler result. After changing some of the data structure of the
variable, F5 gives these results:

```c  
 s[7] = -1LL;  
 s[8] = -1LL;  
 input[0] = 'UUUUUUUU';  
 input[1] = 'UUUUUUUU';  
 input[2] = 'UUUUUUUU';  
 input[3] = 'UUUUUUUU';  
 input[4] = 'UUUUUUUU';  
 input[5] = 'UUUUUUUU';  
 input[6] = 'UUUUUUUU';  
 input[7] = 'UUUUUUUU';  
 input[8] = 'UUUUUUUU';  
 input[9] = 'UUUUUUUU';  
 input[10] = 'UUUUUUUU';  
 input[11] = 'UUUUUUUU';  
 input[12] = 'UUUUUUUU';  
 input[13] = 'UUUUUUUU';  
 input[14] = 'UUUUUUUU';  
 input[15] = 'UUUUUUUU';  
 s[0] = ' emocleW'; // Welcome  
 s[9] = -1LL;  
 s[1] = ' FTCR ot'; // to RCTF  
 s[10] = -1LL;  
 s[2] = 'eH !8102'; // 2018! He  
 s[11] = -1LL;  
 s[3] = ' a si er'; // re is a  
 s[12] = -1LL;  
 s[13] = -1LL;  
 s[14] = -1LL;  
 s[15] = -1LL;  
 s[4] = 'c ERybaB'; // BabyRE c  
 s[5] = 'egnellah'; // hallenge  
 s[6] = 'uoy rof '; //  for you  
 LOWORD(s[7]) = '.';  
 puts((const char *)s);  
 __printf_chk(1LL, "Give me your flag: ");  
 __isoc99_scanf("%127s", input);  
/*  
 unsigned __int64 input[16]; // [rsp+0h] [rbp-198h]  
 unsigned __int64 s[16]; // [rsp+80h] [rbp-118h]  
 q_xmm_word result[8]; // [rsp+100h] [rbp-98h]  
 //result is regarded as uint64_t when assigning the result  
 //and regarded as uint128_t when checking the correctness of the result  
  
00000000 q_xmm_word      union ; (sizeof=0x10, mappedto_16)  
00000000                                         ; XREF: main+1B8/w  
00000000                                         ; main+1E1/w ...  
00000000 qwords          two_qwords ?  
00000000 xmms            xmmword ?  
00000000 q_xmm_word      ends  
00000000  
00000000 ;
---------------------------------------------------------------------------  
00000000  
00000000 two_qwords      struc ; (sizeof=0x10, mappedto_14)  
00000000                                         ; XREF: q_xmm_word/r  
00000000 low             dq ?  
00000008 high            dq ?  
00000010 two_qwords      ends  
*/  
 result[0].qwords.low = sub_400BA0((q_xmm_word)(input[0] * (unsigned
__int128)s[0]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 result[0].qwords.high = sub_400BA0((q_xmm_word)(input[1] * (unsigned
__int128)s[1]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 result[1].qwords.low = sub_400BA0((q_xmm_word)(input[2] * (unsigned
__int128)s[2]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 result[1].qwords.high = sub_400BA0((q_xmm_word)(input[3] * (unsigned
__int128)s[3]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 result[2].qwords.low = sub_400BA0((q_xmm_word)(input[4] * (unsigned
__int128)s[4]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 result[2].qwords.high = sub_400BA0((q_xmm_word)(input[5] * (unsigned
__int128)s[5]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 result[3].qwords.low = sub_400BA0((q_xmm_word)(input[6] * (unsigned
__int128)s[6]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 result[3].qwords.high = sub_400BA0((q_xmm_word)(input[7] * (unsigned
__int128)s[7]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 result[4].qwords.low = sub_400BA0((q_xmm_word)(input[8] * (unsigned
__int128)s[8]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 result[4].qwords.high = sub_400BA0((q_xmm_word)(input[9] * (unsigned
__int128)s[9]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 result[5].qwords.low = sub_400BA0((q_xmm_word)(input[10] * (unsigned
__int128)s[10]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 result[5].qwords.high = sub_400BA0((q_xmm_word)(input[11] * (unsigned
__int128)s[11]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 result[6].qwords.low = sub_400BA0((q_xmm_word)(input[12] * (unsigned
__int128)s[12]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 result[6].qwords.high = sub_400BA0((q_xmm_word)(input[13] * (unsigned
__int128)s[13]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 result[7].qwords.low = sub_400BA0((q_xmm_word)(input[14] * (unsigned
__int128)s[14]), 0xFFFFFFFFFFFFFFC5LL, 0LL);  
 v3 = sub_400BA0((q_xmm_word)(input[15] * (unsigned __int128)s[15]),
0xFFFFFFFFFFFFFFC5LL, 0LL);  
 v4 = _mm_load_si128((const __m128i *)result);  
 result[7].qwords.high = v3;  
```

The logic is to regard 2 char arrays as arrays of `uint64_t`, multiply the
input by `s` (the welcome message) and `0xFFFFFFFF` after that, then store the
result in the result array.

Take a look at XMM instructions that follow:

```assembly  
movdqa  xmm1, xmmword ptr [rsp+198h+result] ; regard result as array of
uint128_t  
mov     qword ptr [rsp+198h+result+78h], rax  
movdqa  xmm0, xmmword ptr cs:unk_602070  
pxor    xmm1, xmmword ptr cs:keys ; xmm1 = result[0] ^ keys[0]  
movdqa  xmm4, xmmword ptr [rsp+198h+result+20h]  
pxor    xmm0, xmmword ptr [rsp+198h+result+10h] ; xmm0 = keys[1] ^ result[1]  
movdqa  xmm3, xmmword ptr [rsp+198h+result+30h]  
pxor    xmm4, xmmword ptr cs:unk_602080 ; xmm4 = xor 2  
movdqa  xmm2, xmmword ptr [rsp+198h+result+40h]  
pxor    xmm3, xmmword ptr cs:unk_602090 ; xmm5 = xor3  
por     xmm1, xmm0      ; xmm1 = [0] | [1]  
pxor    xmm2, xmmword ptr cs:unk_6020A0 ; xmm2 = xor 4  
movdqa  xmm0, xmmword ptr [rsp+198h+result+60h]  
por     xmm4, xmm1      ; xmm4 = [0] | [1] | [2]  
movdqa  xmm1, xmmword ptr [rsp+198h+result+50h]  
pxor    xmm0, xmmword ptr cs:unk_6020C0 ; xmm0 = xor 6  
por     xmm3, xmm4      ; xmm3 = [0] | [1] | [2] | [3]  
pxor    xmm1, xmmword ptr cs:unk_6020B0 ; xmm1 = xor [5]  
por     xmm2, xmm3      ; xmm2 = [0] | [1] | [2] | [3] | [4]  
movdqa  xmm3, xmm2  
movdqa  xmm2, xmm1  
movdqa  xmm1, xmm0  
movdqa  xmm0, xmmword ptr cs:unk_6020D0  
por     xmm2, xmm3      ; xmm2 = [0] | [1] | [2] | [3] | [4] | [5]  
pxor    xmm0, xmmword ptr [rsp+198h+result+70h] ; xmm0 = xor7  
por     xmm1, xmm2  
por     xmm0, xmm1  
movdqa  xmm1, xmm0  
psrldq  xmm1, 8  
por     xmm0, xmm1  
movq    rax, xmm0  
test    rax, rax  
jz      short loc_400A86 ; jmp if correct  
mov     edi, offset s   ; "Incorrect."  
call    _puts  
```

The logic is, "xor" the result with the key, and "or" all of them together; if
the final value obtained is 0, the answer is correct. This means that, all of
the "xor" result must be 0, which means that result array from `sub_400BA0`
must be same as key.

Interestingly, we can see the optimisation of the compiler, which generates
the code that will be faster on out\-of\-order CPUs.

So take a look at `sub_400BA0`:

```c  
unsigned __int64 __fastcall sub_400BA0(q_xmm_word res, unsigned __int64 fc5,
unsigned __int64 zero)  
{  
 unsigned __int64 fc5_; // r10  
 unsigned __int64 result; // rax  
 unsigned __int64 v5; // rdx  
 __int64 v6; // rbp  
 int v7; // ebp  
 unsigned __int64 v8; // rbx  
 unsigned __int64 v9; // r10  
 unsigned __int64 v10; // r8  
 q_xmm_word v11; // tt  
 unsigned __int64 v12; // rsi  
 q_xmm_word v13; // ax  
 unsigned __int64 v14; // rcx  
 __int64 v15; // rdi  
 q_xmm_word v16; // ax  
 q_xmm_word tmp; // tt

 fc5_ = fc5;  
 result = res.qwords.low;  
 if ( zero )  
 { // can't reach here, zero is always 0, possibly obsfucation  
   if ( zero > res.qwords.high )  
   {  
     result = res.qwords.low;  
   }  
   else  
   {  
     _BitScanReverse64((unsigned __int64 *)&v6, zero);  
     v7 = v6 ^ 0x3F;  
     if ( v7 )  
     {  
       v8 = fc5 << v7;  
       v9 = (zero << v7) | (fc5 >> (64 - (unsigned __int8)v7));  
       v10 = res.qwords.low << v7;  
       v11.qwords.low = ((unsigned __int64)res.qwords.low >> (64 - (unsigned __int8)v7)) | (res.qwords.high << v7);  
       v11.qwords.high = res.qwords.high >> (64 - (unsigned __int8)v7);  
       v12 = v11.xmms % v9;  
       v13.xmms = (fc5 << v7) * (unsigned __int128)(unsigned __int64)(v11.xmms / v9);  
       v14 = v8 * (unsigned __int128)(unsigned __int64)(v11.xmms / v9) >> 64;  
       v15 = v8 * (v11.xmms / v9);  
       if ( v12 < v13.qwords.high || v12 == v13.qwords.high && v10 < v13.qwords.low )  
       {  
         v16.xmms = v13.xmms - __PAIR__(v9, v8);  
         v14 = v16.qwords.high;  
         v15 = v16.qwords.low;  
       }  
       result = ((v10 - v15) >> v7) | ((__PAIR__(v12, v10) - __PAIR__(v14, v15)) >> 64 << (64 - (unsigned __int8)v7));  
     }  
     else if ( zero < res.qwords.high || fc5 <= res.qwords.low )  
     {  
       result = res.qwords.low - fc5;  
     }  
   }  
 }  
 else  
 {  
   if ( fc5 <= res.qwords.high )  
   {  
     if ( !fc5 )  
       fc5_ = 1 / 0uLL;                        // never, fc5 is always a constant  
     tmp.qwords.low = res.qwords.low; // never, since for ret.high > fc5, the input is no longer readable  
     tmp.qwords.high = res.qwords.high % fc5_;  
     v5 = tmp.xmms % fc5_;  
   }  
   else  
   {//only useful part  
     v5 = res.xmms % fc5;  
   }  
   result = v5;  
 }  
 return result;  
}  
```

This function contains a lot useless code again: firstly, `zero` is always
zero, so all the code in the first branch are useless; secondly, `fc5` is
always non-zero, so the divivision by 0 exception can't occur; thirdly, `fc5
<= res.qwords.high` is always false, since for the result of multiplication to
be larger than or equal to `0xFFFFFFFFFFFFFFC50000000000000000`, the input
characters are not readable anymore, even if we took `0xFFFFFFFFFFFFFFFF` as
the factor:

```python  
>>> hex(0xFFFFFFFFFFFFFFC50000000000000000 / 0xFFFFFFFFFFFFFFFF)  
'0xffffffffffffffc5L'  
```

Also, the bytes after the flag are `U` instead of `0xFF` as shown above; a
number larger than `0xFFFFFFFFFFFFFFC5L` won't occur in the input array. So
this means we need to solve the following equations:

```c  
(input[0] * 0x20656d6f636c6557) % 0xFFFFFFFFFFFFFFC5 == 0x2b7192452905e8fb  
(input[1] * 0x2046544352206f74) % 0xFFFFFFFFFFFFFFC5 == 0x7ba58f82bd898035  
(input[2] * 0x6548202138313032) % 0xFFFFFFFFFFFFFFC5 == 0xa3112746582e1434  
(input[3] * 0x2061207369206572) % 0xFFFFFFFFFFFFFFC5 == 0x163f756fcc221ab0  
(input[4] * 0x6320455279626142) % 0xFFFFFFFFFFFFFFC5 == 0xecc78e6fb9cba1fe  
(input[5] * 0x65676e656c6c6168) % 0xFFFFFFFFFFFFFFC5 == 0xdcdd8b49ea5d7e14  
(input[6] * 0x756f7920726f6620) % 0xFFFFFFFFFFFFFFC5 == 0xa2845fe0b3096f8e  
(input[7] * 0xffffffffffff002e) % 0xFFFFFFFFFFFFFFC5 == 0xaaaaaaaaaa975d1c  
(input[8] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3  
(input[9] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3  
(input[10] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3  
(input[11] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3  
(input[12] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3  
(input[13] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3  
(input[14] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3  
(input[15] * 0xffffffffffffffff) % 0xFFFFFFFFFFFFFFC5 == 0x55555555555559a3  
```

These would take too long to brute-force (2^64-ish possibilities for each
entry of the `input` array). But, multiply-modulo-compare is clearly just a
[linear congruence](https://en.wikipedia.org/wiki/Chinese_remainder_theorem).
A very fast algorithm to solve these is Euclid's extended algorithm.

([solver
script](https://github.com/Aurel300/empirectf/blob/master/writeups/2018-05-19-RCTF/scripts/babyre2.py))

   666c61677b737461  
   795f7072696d655f  
   737461795f696e76  
   65727469626c655f  
   617761795f66726f  
   6d5f627275746566  
   6f7263657d005555  
   5555555555555555  
   5555555555555555  
   5555555555555555  
   5555555555555555  
   5555555555555555  
   5555555555555555  
   5555555555555555  
   5555555555555555  
   5555555555555555

And after decoding:

`flag{stay_prime_stay_invertible_away_from_bruteforce}`  

Original writeup
(https://github.com/Aurel300/empirectf/blob/master/writeups/2018-05-19-RCTF/README.md#444-reverse
--babyre2).