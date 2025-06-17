# Rev 0 (re, 728p, 23 solved)

In the task we get a simple code:

```python  
#!/usr/bin/env python3

import flagchecker

print("Enter Flag: ")  
inp = input()  
if flagchecker.CheckFlag(inp):  
   print("Way to Go!")  
else:  
   print("Bad Boy!")  
```

And a [native
library](https://raw.githubusercontent.com/TFNS/writeups/master/2020-04-25-IJCTF/rev0/flagchecker.so)
to reverse.

## Reversing the library

Flag checking logic is at `0x00100a41`.  
The logic is pretty clear:

1. User input is collected  
2. Input is encoded into form of some arrays  
3. Input is collapsed into a single number  
4. This number is compared with some constant

### Input encoding stage 1

First step creates some arrays:

```c  
encoded_input_list = PyList_New((long)input_length);  
i = 0;  
while (i < input_length) {  
 long_value1 = PyLong_FromUnsignedLong(1);  
 long_value2 = PyLong_FromUnsignedLong(1);  
 list2 = PyList_New(2);  
 PyList_SetItem(list2,0,long_value1);  
 PyList_SetItem(list2,1,long_value2);  
 PyList_SetItem(encoded_input_list,(long)i,list2);  
 i = i + 1;  
}  
```

Which is pretty much just creating lots of arrays `[1,1]`.

Then:

```c  
j = 0;  
while (j < input_length) {  
 k = 0;  
 while (k < 8) {  
   input_char = *(char *)(j + user_input);  
   list2_ = PyList_GetItem(encoded_input_list,(long)j,(long)j);  
   long_value3 = PyList_GetItem(list2_,1);  
   long_value4 = PyList_GetItem(list2_,0);  
   added_longs = PyNumber_Add(long_value4,long_value3);  
   PyList_SetItem(list2_,(input_char >> (k & 0x1f) & 1U ^1),added_longs);  
   k = k + 1;  
 }  
 j = j + 1;  
}  
```

This is basically:

```python  
list2 = [1, 1]  
for i in range(8):  
   added_longs = list2[0] + list2[1]  
   list2[(ord(input_char) >> (i & 0x1f) & 1 ^ 1)] = added_longs  
```

performed for each character of the input.

Notice that since this is done character by character, we don't really need to
figure out how to `invert` this logic.  
We can simply create a lookup table of all possible values:

```python  
def encode_array(input_char):  
   list2 = [1, 1]  
   for i in range(8):  
       two = list2[0] + list2[1]  
       list2[(ord(input_char) >> (i & 0x1f) & 1 ^ 1)] = two  
   return list2

reference = {tuple(encode_array(char)): char for char in string.printable}  
```

This way we can immediately recover the character from such array.

### Input encoding stage 2

Next step is:

```c  
long_value5 = PyLong_FromUnsignedLong(0);  
i_ = 0;  
while (i_ < input_length) {  
 local_a68 = PyList_GetItem(encoded_input_list,(long)i_,(long)i_);  
 long_value3 = PyLong_FromUnsignedLong(0x551);  
 long_value5 = PyNumber_Multiply(long_value5,long_value3,long_value3);  
 long_value3 = PyList_GetItem(local_a68,0);  
 long_value5 = PyNumber_Add(long_value5,long_value3,long_value3);  
 long_value3 = PyLong_FromUnsignedLong(0x551);  
 long_value5 = PyNumber_Multiply(long_value5,long_value3,long_value3);  
 long_value3 = PyList_GetItem(local_a68,1);  
 long_value5 = PyNumber_Add(long_value5,long_value3,long_value3);  
 i_ = i_ + 1;  
}  
```

This performs simple:

```python  
x = 0  
for i in range(len(data)):  
   list2 = encoded_input_list[i]  
   x = x * 0x551 + list2[0]  
   x = x * 0x551 + list2[1]  
return x  
```

Where `encoded_input_list` is the array we got in previous step.  
If we look at the last step, the final value will be `0x551*x + y`.  
It's clear that we can therefore just get mod 0x551 to get back `y`.  
But this property propagates from the start, so we can do mod 0x551 until we
recover all numbers:

```python  
def decode_single_pair(number):  
   y = number % 0x551  
   number = (number - x) / 0x551  
   x = number % 0x551  
   number = (number - y) / 0x551  
   return y, x, number

def decode(number):  
   rest = number  
   results = []  
   while rest != 0:  
       a, b, rest = decode_single_pair(rest)  
       results.append([a, b])  
   return results[::-1]  
```

## Recovering comparison constants

Now the last step is just comparison with some constant:

```c  
constant_long = PyLong_FromString(&local_228,0,0x10);  
result = PyObject_RichCompare(constant_long,long_value5,2,long_value5);  
```

Ghidra made this a bit messy, so it was faster to grab the constant from the
debugger.  
We just run python in gdb, break on `PyLong_FromString` and inspect the
pointer at RAX `x/100s 0x7ffffffed7800` to get:
`0xc8ec454b3ac5971259b9ec147b62f0543f37a526f4247aed6d318ff4ae3461d79ea5fda8f8632ddc3162f0b4cdb879d3ded85857a900785bbe250be80102e7ae2afd33cf074a9bf5058329e6fda96911e2694463378374a90d4e4e250327c4a0614ba51d4cf396f8a6b9f48f4a8a54e24fce4734b5833fe155ef66155475f6f86a5accd890c9143ba1c12f10515c9e682da44b41a83f49a1494df131f0bd4017cb5fb790d3c2eb183`

# Flag

Now we just run our decoder and get:
`IJCTF{r4t10n4l$_4r3_c0unt4bl3_calk1n_w1lf_tr33_n0t_st3rn_br0c0t!}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-04-25-IJCTF/rev0/README.md).