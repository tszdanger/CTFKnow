## Challenge Description

The CIA has been tracking a group of hackers who communicate using PNG files
embedded with a custom steganography algorithm.  
An insider spy was able to obtain the encoder, but it is not the original
code.  
You have been tasked with reversing the encoder file and creating a decoder as
soon as possible in order to read the most recent PNG file they have sent.

## Solution

We are given a PNG file and a CPython transpilation/compilation of the
original Python script used to embed a secret in the PNG file. We can see it
sometimes contains comments leaking parts of the original Python script. We
can extract those using a script to recreate the original script.

```py  
#!/usr/bin/env python3

f = open("encoder.c")

prog = ["" for _ in range(100)]  
num = 0  
for line in f.readlines():  
   if line.strip().startswith("/* \"encoder"):  
       num = int(line.split(":")[1])  
#        print(num)  
       continue  
   if line.startswith(" * "):  
       good_line = line.split("*")[1].strip()  
       prog[num] = good_line  
       num += 1  
   continue

for line in prog:  
   print(line)  
```

We get the original file:  
```py  
from PIL import Image  # <<<<<<<<<<<<<<  
from random import randint  
import binascii

def hexstr_to_binstr(hexstr):  # <<<<<<<<<<<<<<  
   n = int(hexstr, 16)  
   bstr = ''  
   while n > 0:  
       bstr = str(n % 2) + bstr  
       n = n >> 1  
   if len(bstr) % 8 != 0:  
       bstr = '0' + bstr  
   return bstr  # <<<<<<<<<<<<<<

def pixel_bit(b):  # <<<<<<<<<<<<<<  
   return tuple((0, 1, b))

def embed(t1, t2):  # <<<<<<<<<<<<<<  
   return tuple((t1[0] + t2[0], t1[1] + t2[1], t1[2] + t2[2]))

def full_pixel(pixel):  # <<<<<<<<<<<<<<  
   return pixel[1] == 255 or pixel[2] == 255

print("Embedding file...")

bin_data = open("./flag.txt", 'rb').read()  
data_to_hide = binascii.hexlify(bin_data).decode('utf-8')

base_image = Image.open("./original.png")

x_len, y_len = base_image.size  
nx_len = x_len

new_image = Image.new("RGB", (nx_len, y_len))

base_matrix = base_image.load()  
new_matrix = new_image.load()

binary_string = hexstr_to_binstr(data_to_hide)  
remaining_bits = len(binary_string)

nx_len = nx_len - 1  
next_position = 0

for i in range(0, y_len):  # <<<<<<<<<<<<<<  
   for j in range(0, x_len):  
       pixel = new_matrix[j, i] = base_matrix[j, i]

       if remaining_bits > 0 and next_position <= 0 and not full_pixel(pixel):  # <<<<<<<<<<<<<<  
           new_matrix[nx_len - j, i] = embed(pixel_bit(int(binary_string[0])), pixel)  
           next_position = randint(1, 17)  
           binary_string = binary_string[1:]  
           remaining_bits -= 1  
       else:  
           new_matrix[nx_len - j, i] = pixel  
           next_position -= 1  # <<<<<<<<<<<<<<

new_image.save("./symatrix.png")  
new_image.close()  
base_image.close()

print("Work done!")  
exit(1)  # <<<<<<<<<<<<<<  
```

We notice that each bit of the secret is embedded into the blue channel of
each pixel, starting from top right, going to the left. It also skips a random
amount of pixels. Because the first few lines in our image are all black
pixels, we can deduce which pixels were used by looking on the green channel.
Each used pixel should have the value 1 on the green channel, because all the
pixels were initially (0,0,0) and a used pixel has the info (0,1,b) (where b
is the secret bit). We recreate the secret by modifying the embedding script a
bit:

```py  
from PIL import Image

use_custom_hexstr = True

def binstr_to_hexstr(binstr):  
   if use_custom_hexstr:  
       hexstr = ''  
       for i in range(0, len(binstr), 8):  
           start = i  
           end = i + 8  
           slice = int(binstr[start:end], 2)  
           slice_str = hex(slice)[2:]  
           if len(slice_str) % 2 == 1:  
               slice_str = '0' + slice_str  
           hexstr += slice_str  
       return hexstr  
   else:  
       return hex(int(binstr, 2))

def pixel_bit(b):  
   return tuple((0, 1, b))

def embed(data_pixel, original_pixel):  
   return tuple((data_pixel[0] + original_pixel[0], data_pixel[1] +
original_pixel[1], data_pixel[2] + original_pixel[2]))

def full_pixel(pixel):  
   return pixel[1] == 255 or pixel[2] == 255

base_image = Image.open("./symatrix.png")

x_len, y_len = base_image.size  
nx_len = x_len

base_matrix = base_image.load()

binary_result_string = ''

nx_len = nx_len - 1

limit = 1546 * 19

for i in range(0, y_len):  
   for j in range(0, x_len):  
       limit -= 1  
       if limit == 0:  
           print(binstr_to_hexstr(binary_result_string))  
           # assert len(binary_result_string) % 8 == 0  
           hex_result = binstr_to_hexstr(binary_result_string)[2:]  
           if len(hex_result) % 2 == 1:  
               hex_result = '0' + hex_result

           print(bytes.fromhex(hex_result))  
           exit(69)

       pixel = base_matrix[nx_len - j, i]  
       if full_pixel(pixel):  
           continue

       if pixel[1] >= 1:  
           assert pixel[2] == 1 or pixel[2] == 0  
           binary_result_string += str(pixel[2])

print("Work done!")  
exit(1)  
```  

Original writeup (https://dothidden.xyz/google_ctf_2023/symatrix/).