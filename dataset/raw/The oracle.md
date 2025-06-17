**Description**

> The Oracle gave me this note. She mentioned it uses a substitution cipher.
> She also reminded me that there is no flag.

**Files given**

- `oracle.tar.gz` - archive containing [`emsg.txt`](https://github.com/Aurel300/empirectf/blob/master/writeups/2018-05-31-SecurityFest/scripts/oracle/emsg.txt) looking like binary data

**Solution**

The file we have been given indeed is just some text encrypted using a
substitution cipher. See [above](#485-crypto--the-note) for how to approach
this. The difference for this one is that there are more distinct values,
since we are not limited to a polybius square. As such, the most common
character is most likely `0x20`, a space. Replacing the most common occurring
character `0x68` with `0x20` and everything else with question marks, we get:

> ???? ????????????? ???? ??? ?? ???? ???? ??? ???????? ???? ??? ???? ?? ?????
> ????? ????? ??? ????????? ???? ???????? ?????????? ?????? ??????? ?? ?????
> ???????????? ??? ???? ????? ??????? ???????
> ????????????????????????????????????????????????????????????????????
> ?????????? ???????

Which seems fairly good, all of these could easily be English words. The only
one that stands out is the 68 character one - the flag. We should exclude that
for our frequency analysis.

I did try using `the` as a crib for this one, but this failed. As you'll soon
see, the text doesn't actually include this word. So instead, we just use
letter frequencies and deduction.

([interactive decoder script
here](https://github.com/Aurel300/empirectf/blob/master/writeups/2018-05-31-SecurityFest/scripts/oracle/Solve.hx))

   --- Interactive decode mode ---  
   Frequency chart:  
      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  
   0  0  0  0  0  0  0  0  2  0  1  1  0  1  0  0  0  
   1  0  4  0  0  0  0  0 12  0  0  0  0  3  1  0  1  
   2 12 14  0  0 18  3 14 14  0  9  2  2  9 18  4  5  
   3  0  5  0  1  0  1  0  0  1  0 11 12 11 11  3  6  
   4  0  0 10  0  0  0  0  0  0  0  0  0  0  0  0  0  
   5  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  
   6  0  0  0  0  3  0  4  0 33  0  0  0  0  0  0  0  
   7  0  0  0  0  0  0  0  1  3  8  0  0  4  1  0  4  
   8  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  
   9  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  
   A  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  
   B  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  
   C  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  
   D  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  
   E  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  
   F  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  
   Current plain text:  
       0 1 2 3 4 5 6 7 8 9 |  0  1  2  3  4  5  6  7  8  9  
     0 ? ? ? ?   ? ? ? ? ? | 0C 2D 29 3A 68 1C 3A 21 26 21  
    10 ? ? ? ? ? ? ? ?   ? | 3C 31 64 42 42 11 27 3D 68 3F  
    20 ? ? ?   ? ? ?   ? ? | 21 24 24 68 2F 2D 3C 68 21 26  
    30   ? ? ? ?   ? ? ? ? | 68 24 27 3E 2D 68 3F 21 3C 20  
    40   ? ? ?   ? ? ? ? ? | 68 1C 20 2D 68 07 26 2D 66 42  
    50 ? ? ?   ? ? ? ?   ? | 11 27 3D 68 3F 21 24 24 68 3B  
    60 ? ?   ? ? ? ?   ? ? | 2D 2D 68 3F 20 29 3C 68 26 27  
    70   ? ? ? ? ?   ? ? ? | 68 27 3C 20 2D 3A 68 20 3D 25  
    80 ? ?   ? ? ? ? ?   ? | 29 26 68 29 24 21 3E 2D 68 20  
    90 ? ?   ? ? ? ? ? ? ? | 29 3B 68 3B 2D 2D 26 66 42 11  
   100 ? ?   ? ? ? ?   ? ? | 27 3D 68 3F 21 24 24 68 3C 3A  
   110 ? ? ? ? ? ?   ? ? ? | 2D 3B 38 29 3B 3B 68 2A 27 3D  
   120 ? ? ? ? ? ? ?   ? ? | 26 2C 29 3A 21 2D 3B 68 26 27  
   130 ? ? ? ?   ? ? ? ? ? | 2A 27 2C 31 68 2C 3A 2D 29 25  
   140 ? ?   ? ?   ? ? ? ? | 2D 2C 68 27 2E 68 2F 27 21 26  
   150 ?   ? ? ? ? ? ? ? ? | 2F 68 3C 20 3A 27 3D 2F 20 66  
   160 ? ? ? ?   ? ? ?   ? | 42 09 26 2C 68 31 27 3D 68 3F  
   170 ? ? ?   ? ? ? ? ?   | 21 24 24 68 3E 21 3B 21 3C 68  
   180 ? ? ? ? ? ? ?   ? ? | 78 79 66 42 0A 3D 3C 68 3A 2D  
   190 ? ? ? ? ?   ? ? ? ? | 25 21 26 2C 64 68 3B 2B 3C 2E  
   200 ? ? ? ? ? ? ? ? ? ? | 33 1F 79 24 24 17 1D 17 7D 7F  
   210 ? ? ? ? ? ? ? ? ? ? | 79 24 24 17 2C 3D 17 7C 24 24  
   220 ? ? ? ? ? ? ? ? ? ? | 17 78 2E 17 7F 20 79 3B 17 79  
   230 ? ? ? ? ? ? ? ? ? ? | 2E 17 79 17 20 7C 2C 17 26 78  
   240 ? ? ? ? ? ? ? ? ? ? | 7F 17 3B 7C 79 2C 17 7C 26 31  
   250 ? ? ? ? ? ? ? ? ? ? | 7F 20 79 26 2F 77 35 42 42 11  
   260 ? ? ? ?   ? ? ? ? ? | 27 3D 3A 3B 68 3C 3A 3D 24 31  
   270 ? ? ? ? ?   ? ? ? ? | 64 42 1C 20 2D 68 07 3A 29 2B  
   280 ? ? ?               | 24 2D 42                       
   Replace pos / char: char  
   Replace (charcode): 0x2D  
   With (charcode):    0x65  
   (E is the most frequent letter)  
   Current plain text:  
       0 1 2 3 4 5 6 7 8 9 |  0  1  2  3  4  5  6  7  8  9  
     0 ? e ? ?   ? ? ? ? ? | 0C 2D 29 3A 68 1C 3A 21 26 21  
    10 ? ? ? ? ? ? ? ?   ? | 3C 31 64 42 42 11 27 3D 68 3F  
    20 ? ? ?   ? e ?   ? ? | 21 24 24 68 2F 2D 3C 68 21 26  
    30   ? ? ? e   ? ? ? ? | 68 24 27 3E 2D 68 3F 21 3C 20  
    40   ? ? e   ? ? e ? ? | 68 1C 20 2D 68 07 26 2D 66 42  
    50 ? ? ?   ? ? ? ?   ? | 11 27 3D 68 3F 21 24 24 68 3B  
    60 e e   ? ? ? ?   ? ? | 2D 2D 68 3F 20 29 3C 68 26 27  
    70   ? ? ? e ?   ? ? ? | 68 27 3C 20 2D 3A 68 20 3D 25  
    80 ? ?   ? ? ? ? e   ? | 29 26 68 29 24 21 3E 2D 68 20  
    90 ? ?   ? e e ? ? ? ? | 29 3B 68 3B 2D 2D 26 66 42 11  
   100 ? ?   ? ? ? ?   ? ? | 27 3D 68 3F 21 24 24 68 3C 3A  
   110 e ? ? ? ? ?   ? ? ? | 2D 3B 38 29 3B 3B 68 2A 27 3D  
   120 ? ? ? ? ? e ?   ? ? | 26 2C 29 3A 21 2D 3B 68 26 27  
   130 ? ? ? ?   ? ? e ? ? | 2A 27 2C 31 68 2C 3A 2D 29 25  
   140 e ?   ? ?   ? ? ? ? | 2D 2C 68 27 2E 68 2F 27 21 26  
   150 ?   ? ? ? ? ? ? ? ? | 2F 68 3C 20 3A 27 3D 2F 20 66  
   160 ? ? ? ?   ? ? ?   ? | 42 09 26 2C 68 31 27 3D 68 3F  
   170 ? ? ?   ? ? ? ? ?   | 21 24 24 68 3E 21 3B 21 3C 68  
   180 ? ? ? ? ? ? ?   ? e | 78 79 66 42 0A 3D 3C 68 3A 2D  
   190 ? ? ? ? ?   ? ? ? ? | 25 21 26 2C 64 68 3B 2B 3C 2E  
   200 ? ? ? ? ? ? ? ? ? ? | 33 1F 79 24 24 17 1D 17 7D 7F  
   210 ? ? ? ? ? ? ? ? ? ? | 79 24 24 17 2C 3D 17 7C 24 24  
   220 ? ? ? ? ? ? ? ? ? ? | 17 78 2E 17 7F 20 79 3B 17 79  
   230 ? ? ? ? ? ? ? ? ? ? | 2E 17 79 17 20 7C 2C 17 26 78  
   240 ? ? ? ? ? ? ? ? ? ? | 7F 17 3B 7C 79 2C 17 7C 26 31  
   250 ? ? ? ? ? ? ? ? ? ? | 7F 20 79 26 2F 77 35 42 42 11  
   260 ? ? ? ?   ? ? ? ? ? | 27 3D 3A 3B 68 3C 3A 3D 24 31  
   270 ? ? ? ? e   ? ? ? ? | 64 42 1C 20 2D 68 07 3A 29 2B  
   280 ? e ?               | 24 2D 42                       
   Replace pos / char: pos  
   Replace (pos):   196  
   With (charcode): 0x73  
   Replace pos / char: pos  
   Replace (pos):   197  
   With (charcode): 0x63  
   Replace pos / char: pos  
   Replace (pos):   198  
   With (charcode): 0x74  
   Replace pos / char: pos  
   Replace (pos):   199  
   With (charcode): 0x66  
   ("sctf" at the beginning of the flag)  
   ...  
   ...  
   ...  
   Current plain text:  
       0 1 2 3 4 5 6 7 8 9 |  0  1  2  3  4  5  6  7  8  9  
     0 ? e ? r   ? r ? ? ? | 0C 2D 29 3A 68 1C 3A 21 26 21  
    10 t ? ? ? ? ? o ?   w | 3C 31 64 42 42 11 27 3D 68 3F  
    20 ? ? ?   ? e t   ? ? | 21 24 24 68 2F 2D 3C 68 21 26  
    30   ? o ? e   w ? t h | 68 24 27 3E 2D 68 3F 21 3C 20  
    40   ? h e   ? ? e ? ? | 68 1C 20 2D 68 07 26 2D 66 42  
    50 ? o ?   w ? ? ?   s | 11 27 3D 68 3F 21 24 24 68 3B  
    60 e e   w h ? t   ? o | 2D 2D 68 3F 20 29 3C 68 26 27  
    70   o t h e r   h ? ? | 68 27 3C 20 2D 3A 68 20 3D 25  
    80 ? ?   ? ? ? ? e   h | 29 26 68 29 24 21 3E 2D 68 20  
    90 ? s   s e e ? ? ? ? | 29 3B 68 3B 2D 2D 26 66 42 11  
   100 o ?   w ? ? ?   t r | 27 3D 68 3F 21 24 24 68 3C 3A  
   110 e s ? ? s s   ? o ? | 2D 3B 38 29 3B 3B 68 2A 27 3D  
   120 ? ? ? r ? e s   ? o | 26 2C 29 3A 21 2D 3B 68 26 27  
   130 ? o ? ?   ? r e ? ? | 2A 27 2C 31 68 2C 3A 2D 29 25  
   140 e ?   o f   ? o ? ? | 2D 2C 68 27 2E 68 2F 27 21 26  
   150 ?   t h r o ? ? h ? | 2F 68 3C 20 3A 27 3D 2F 20 66  
   160 ? ? ? ?   ? o ?   w | 42 09 26 2C 68 31 27 3D 68 3F  
   170 ? ? ?   ? ? s ? t   | 21 24 24 68 3E 21 3B 21 3C 68  
   180 ? ? ? ? ? ? t   r e | 78 79 66 42 0A 3D 3C 68 3A 2D  
   190 ? ? ? ? ?   s c t f | 25 21 26 2C 64 68 3B 2B 3C 2E  
   200 ? ? ? ? ? ? ? ? ? ? | 33 1F 79 24 24 17 1D 17 7D 7F  
   210 ? ? ? ? ? ? ? ? ? ? | 79 24 24 17 2C 3D 17 7C 24 24  
   220 ? ? f ? ? h ? s ? ? | 17 78 2E 17 7F 20 79 3B 17 79  
   230 f ? ? ? h ? ? ? ? ? | 2E 17 79 17 20 7C 2C 17 26 78  
   240 ? ? s ? ? ? ? ? ? ? | 7F 17 3B 7C 79 2C 17 7C 26 31  
   250 ? h ? ? ? ? ? ? ? ? | 7F 20 79 26 2F 77 35 42 42 11  
   260 o ? r s   t r ? ? ? | 27 3D 3A 3B 68 3C 3A 3D 24 31  
   270 ? ? ? h e   ? r ? c | 64 42 1C 20 2D 68 07 3A 29 2B  
   280 ? e ?               | 24 2D 42                       
   ...  
   ...  
   ...  
   Current plain text:  
       0 1 2 3 4 5 6 7 8 9 |  0  1  2  3  4  5  6  7  8  9  
     0 D e a r   T r i n i | 0C 2D 29 3A 68 1C 3A 21 26 21  
    10 t y , % % Y o u   w | 3C 31 64 42 42 11 27 3D 68 3F  
    20 i l l   g e t   i n | 21 24 24 68 2F 2D 3C 68 21 26  
    30   l o v e   w i t h | 68 24 27 3E 2D 68 3F 21 3C 20  
    40   T h e   O n e % % | 68 1C 20 2D 68 07 26 2D 66 42  
    50 Y o u   w i l l   s | 11 27 3D 68 3F 21 24 24 68 3B  
    60 e e   w h a t   n o | 2D 2D 68 3F 20 29 3C 68 26 27  
    70   o t h e r   h u m | 68 27 3C 20 2D 3A 68 20 3D 25  
    80 a n   a l i v e   h | 29 26 68 29 24 21 3E 2D 68 20  
    90 a s   s e e n % % Y | 29 3B 68 3B 2D 2D 26 66 42 11  
   100 o u   w i l l   t r | 27 3D 68 3F 21 24 24 68 3C 3A  
   110 e s p a s s   b o u | 2D 3B 38 29 3B 3B 68 2A 27 3D  
   120 n d a r i e s   n o | 26 2C 29 3A 21 2D 3B 68 26 27  
   130 b o d y   d r e a m | 2A 27 2C 31 68 2C 3A 2D 29 25  
   140 e d   o f   g o i n | 2D 2C 68 27 2E 68 2F 27 21 26  
   150 g   t h r o u g h % | 2F 68 3C 20 3A 27 3D 2F 20 66  
   160 % A n d   y o u   w | 42 09 26 2C 68 31 27 3D 68 3F  
   170 i l l   v i s i t   | 21 24 24 68 3E 21 3B 21 3C 68  
   180 ? ? % % B u t   r e | 78 79 66 42 0A 3D 3C 68 3A 2D  
   190 m i n d ,   s c t f | 25 21 26 2C 64 68 3B 2B 3C 2E  
   200 ? ? ? l l ? ? ? ? ? | 33 1F 79 24 24 17 1D 17 7D 7F  
   210 ? l l ? d u ? ? l l | 79 24 24 17 2C 3D 17 7C 24 24  
   220 ? ? f ? ? h ? s ? ? | 17 78 2E 17 7F 20 79 3B 17 79  
   230 f ? ? ? h ? d ? n ? | 2E 17 79 17 20 7C 2C 17 26 78  
   240 ? ? s ? ? d ? ? n y | 7F 17 3B 7C 79 2C 17 7C 26 31  
   250 ? h ? n g ? ? % % Y | 7F 20 79 26 2F 77 35 42 42 11  
   260 o u r s   t r u l y | 27 3D 3A 3B 68 3C 3A 3D 24 31  
   270 , % T h e   O r a c | 64 42 1C 20 2D 68 07 3A 29 2B  
   280 l e %               | 24 2D 42

At this point we have everything pretty much everything from the readable
text, but we need to figure out the flag. `?ny?h?ng` looks like `anything`,
but we already used those letters. We also used the capital A and T, so we
probably need to substitute with numbers. So, eventually:

   Current plain text:  
       0 1 2 3 4 5 6 7 8 9 |  0  1  2  3  4  5  6  7  8  9  
     0 D e a r   T r i n i | 0C 2D 29 3A 68 1C 3A 21 26 21  
    10 t y , % % Y o u   w | 3C 31 64 42 42 11 27 3D 68 3F  
    20 i l l   g e t   i n | 21 24 24 68 2F 2D 3C 68 21 26  
    30   l o v e   w i t h | 68 24 27 3E 2D 68 3F 21 3C 20  
    40   T h e   O n e % % | 68 1C 20 2D 68 07 26 2D 66 42  
    50 Y o u   w i l l   s | 11 27 3D 68 3F 21 24 24 68 3B  
    60 e e   w h a t   n o | 2D 2D 68 3F 20 29 3C 68 26 27  
    70   o t h e r   h u m | 68 27 3C 20 2D 3A 68 20 3D 25  
    80 a n   a l i v e   h | 29 26 68 29 24 21 3E 2D 68 20  
    90 a s   s e e n % % Y | 29 3B 68 3B 2D 2D 26 66 42 11  
   100 o u   w i l l   t r | 27 3D 68 3F 21 24 24 68 3C 3A  
   110 e s p a s s   b o u | 2D 3B 38 29 3B 3B 68 2A 27 3D  
   120 n d a r i e s   n o | 26 2C 29 3A 21 2D 3B 68 26 27  
   130 b o d y   d r e a m | 2A 27 2C 31 68 2C 3A 2D 29 25  
   140 e d   o f   g o i n | 2D 2C 68 27 2E 68 2F 27 21 26  
   150 g   t h r o u g h % | 2F 68 3C 20 3A 27 3D 2F 20 66  
   160 % A n d   y o u   w | 42 09 26 2C 68 31 27 3D 68 3F  
   170 i l l   v i s i t   | 21 24 24 68 3E 21 3B 21 3C 68  
   180 0 1 % % B u t   r e | 78 79 66 42 0A 3D 3C 68 3A 2D  
   190 m i n d ,   s c t f | 25 21 26 2C 64 68 3B 2B 3C 2E  
   200 { W 1 l l _ U _ 5 7 | 33 1F 79 24 24 17 1D 17 7D 7F  
   210 1 l l _ d u _ 4 l l | 79 24 24 17 2C 3D 17 7C 24 24  
   220 _ 0 f _ 7 h 1 s _ 1 | 17 78 2E 17 7F 20 79 3B 17 79  
   230 f _ 1 _ h 4 d _ n 0 | 2E 17 79 17 20 7C 2C 17 26 78  
   240 7 _ s 4 1 d _ 4 n y | 7F 17 3B 7C 79 2C 17 7C 26 31  
   250 7 h 1 n g ? } % % Y | 7F 20 79 26 2F 77 35 42 42 11  
   260 o u r s   t r u l y | 27 3D 3A 3B 68 3C 3A 3D 24 31  
   270 , % T h e   O r a c | 64 42 1C 20 2D 68 07 3A 29 2B  
   280 l e %               | 24 2D 42

Reformatted:

> Dear Trinity,  
>  
> You will get in love with The One  
>  
> You will see what no other human alive has seen  
>  
> You will trespass boundaries nobody dreamed of going through  
>  
> And you will visit 01  
>  
> But remind, sctf{W1ll_U_571ll_du_4ll_0f_7h1s_1f_1_h4d_n07_s41d_4ny7h1ng?}  
>  
> Yours truly,  
>  
> The Oracle

`sctf{W1ll_U_571ll_du_4ll_0f_7h1s_1f_1_h4d_n07_s41d_4ny7h1ng?}`

Original writeup
(https://github.com/Aurel300/empirectf/blob/master/writeups/2018-05-31-SecurityFest/README.md#51-crypto
--the-oracle).