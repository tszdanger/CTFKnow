# Dive in to Numbers

Dive into Numbers and enjoy!

Attachments:  
* [numbers](./numbers)  
* [wtflag_enc](./wtflag_enc)

## Solution  
Decompiling the binary in IDA and renaming/retyping variables we get...

```cpp  
 std::ifstream::basic_ifstream(instream, "wtflag.txt", 8LL);  
 std::ofstream::basic_ofstream(outstream, "wtflag_enc", 4LL);  
 std::getline<char,std::char_traits<char>,std::allocator<char>>(instream,
inp);  
 to_hexstring(inp_data, inp);  
 if (
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(inp_data)
<= 0xFF )  
 {  
   i = 0;  
   v40 =
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(inp_data);  
   while ( i < 256 - v40 )  
   {  
     std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=(inp_data, "0");  
     ++i;  
   }  
 }  
```  
It reads data of `wtflag.txt` converts into a hex string, then it pads the hex
string to 256 bytes (128 bytes of original string)

```cpp  
 mpz_set_str(mpz_hex_str, inp_data, 0x10u);  
 mpz_get_str(integer_str, mpz_hex_str, 10u);  
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator=(inp_data,
integer_str);  
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(integer_str);  
```  
Then it uses GMP library to convert the hex string to integer string and store
it again in `inp_data`.  
```cpp  
 r = rand_int_0(1u, 0x80u);  
 mpz_get_str(integer_str, mpz_hex_str, 10u);  
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator=(inp_data,
integer_str);  
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(integer_str);  
 str_len =
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(inp_data);  
 if ( str_len != r )  
 {  
   v4 = std::operator<<<std::char_traits<char>>(&std::cout, "Your number is
very small!");  
   std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);  
   exit(0);  
 }  
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::substr(sub_1,
inp_data, 0LL, r);  
 mpz_set_str(x, sub_1, 10u);  
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(sub_1);  
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::substr(sub_2,
inp_data, r, -1LL);  
 mpz_set_str(y, sub_2, 10u);  
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(sub_2);  
```  
Then it splits the integer string into two parts using a random number as
offset and converts them to mpz integer string, there is a logical error here
but we can guess what's the program is trying to do.

**POC**

```cpp  
if ( str_len != r ) // to bypass this r = str_len  
//then  
sub_2 = inp_data.substr(r,-1) // == inp_data.substr(str_len,-1) --> which will
return null to sub_2  
mpz_set_str(y, sub_2, 10LL); // bcz sub_2 is null this causes error  
```

```cpp  
 r1 = rand_int_2(1LL, 0x1FFFFFFFFFFFLL);  
 r2 = rand_int_2(1LL, 0x1FFFFFFFFFFFLL);  
 mpz_init_set(y1, y);  
 mpz_init_set(x1, x);  
 Some_enc(enc_out_1, x1, y1, r1, 2u);  
 mpz_get_str(out_str_1, enc_out_1, 0x10u);  
 mpz_clear(enc_out_1);  
 mpz_clear(x1);  
 mpz_clear(y1);  
 set[0] = sub_4D79(2, x);  
 set[1] = v5;  
 sub_4DB2(y2, set);                            // y2 = x * 2  
 mpz_init_set(x2, y);  
 Some_enc(enc_out_2, x2, y2, r2, 2u);  
 mpz_get_str(out_str_2, enc_out_2, 0x10u);  
 mpz_clear(enc_out_2);  
 mpz_clear(x2);  
 mpz_clear(y2);  
```  
Then it does some encryption on `x,y,r1,2` and `y,x*2,r2,2` and stores the mpz
result to hex strings `out_str_1` and `out_str_2`

### enc  
```cpp  
 mpz_set_str__(output, "AAAA", 0x10u);  
 sub_4081(tmp_range, len);  
 mpz_set_str(range, tmp_range, 10u);  
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(tmp_range);  
 mpz_set_str__(i, "0", 10u);  
 while ( mpz_cmp(i, range) )  
 {  
   sub_48EB(x, y);  
   set_1[0] = v5;                              // x  
   set_1[1] = v6;                              // y  
   sub_491C(set_1, num);  
   set_2[0] = v7;                              // -> set_1  
   set_2[1] = v8;                              // num  
   sub_4956(output, set_2);                    // output = x + y // 2  
   mpz_set(x, y);                              // x = y  
   mpz_set(y, output);                         // y = output  
   inc(tmp, i);                                // i++  
   mpz_clear(tmp);  
 }  
 mpz_clear(i);  
 mpz_clear(range);  
```  
It does the following loop n times where n is the random number.

```cpp  
 if (
(std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(out_str_1)
& 1) == 1 )  
   v6 = "0";  
 else  
   v6 = &byte_6072;  
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=(out_str_1,
v6);  
 if (
(std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(out_str_2)
& 1) == 1 )  
   v7 = "0";  
 else  
   v7 = &byte_6072;  
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=(out_str_2,
v7);  
 ...  
```  
Then it pads the hex strings to a even length and store the two hex strings as
bytes into the output file with `SSSS` as a seprater.

**Understanding the enc**

The series created by the enc loop converges towards `(a + 2b) / 3` , after a
high value of n the series will result in a fixed value (converging point).
Since this is a CTF task, we can say that the series converged.

So we can write:  
```  
(x +   2y) / 3 = a1  
(y + 2*2x) / 3 = a2  
```  
Now we can solve these equations to get x and y.  
```  
x = 3*(2*out_2-out_1) //7  
y = 3*(4*out_1-out_2) //7  
```  
There is a loss in precision in the encryption, but we can bruteforce a byte
value high and low to get the flag.

Solve script [here](./solve.py)

## Flag  
> `S4CTF{_S0L1X_5EqU3nCe_iZ_S1mPl3!!}`

Original writeup
(https://github.com/1GN1tE/CTF_Writeups/tree/main/Writeups/S4CTF_2021/Dive%20in%20to%20Numbers).