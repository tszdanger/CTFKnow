# TRICKY BIT  
> Points: 475

## Description  
> I always hated to be that last one, At least i should be in the second least
> place.

> [File](TRICKY_BIT.zip)

## Solution  
After opening the `Encrypt.py` file we can see,

```python  
__author__ = 'cyb3rz0n3'

HEADER_SIZE = 54  
DELIMITER = "$"

ImageFile = "lsb.bmp"  
StegImageFile = "lsb1.bmp"

class LSBEncrypter(object):

   def __init__(self):  
       self.image_byte_counter = 0  
       self.new_image_data = ''  
       self.original_image = ''  
       self.text_to_hide = ''

   def open_image(self):                     # opens our image file  
       with open(ImageFile, "rb") as f:  
           self.original_image = f.read()

   def read_header(self):                    # stores the first 54 Bytes of
image data (Image Header)  
       for x in range(0, HEADER_SIZE):  
           self.new_image_data += self.original_image[x]  
           self.image_byte_counter += 1

   def hide_text_size(self):  
       sz = len(self.text_to_hide)  
       s_sz = str(sz)                # hidden text size converted to string  
       s_sz += DELIMITER             # adds the DELIMITER ( hmm...interesting! )  
       self.do_steg(s_sz)            # does some magic on the text size!        

   def do_steg(self, steg_text):            # where the magic happens xD...

       for ch in range(0, len(steg_text)):

           current_char = steg_text[ch]                                # stores the current character of the string to be hidden  
           current_char_binary = '{0:08b}'.format(ord(current_char))     # converts the current character to 8 bit binary string

           for bit in range(0, len(current_char_binary)):    # traverse the 8 bit binary string  
               new_byte_binary = ''

               current_image_binary = '{0:08b}'.format(ord(self.original_image[self.image_byte_counter]))  # converts the current image byte to 8 bit binary string

               new_byte_binary = current_image_binary[:7]        # stores the 1st 7 bits from the 8 bit binary string of the image byte 

               new_byte_binary += current_char_binary[bit]       # add the last bit (LSB) from the current character's 8 bit binary string

               new_byte = chr(int(new_byte_binary, 2))   # convert the new 8 bit binary string back to character

               self.new_image_data += new_byte     # add new byte to image data  
               self.image_byte_counter += 1

   def copy_rest(self):  
       self.new_image_data += self.original_image[self.image_byte_counter:]

   def close_file(self):  
       with open(StegImageFile, "wb") as out:  
           out.write(self.new_image_data)

   def run(self, stega_text):  
       self.text_to_hide = stega_text  
       self.open_image()  
       self.read_header()  
       self.hide_text_size()  
       self.do_steg(self.text_to_hide)  
       self.copy_rest()  
       self.close_file()

def main():  
   global TextToHide  
   stega_instance = LSBEncrypter()  
   stega_instance.run(TextToHide)  
   print "Successfully finished hiding text"

if __name__ == '__main__':  
	main()  
```

**Now that we have understood the encryption scheme, all we have to do is**,  
* Read the bytes from `lsb1.bmp` excluding the Header Bytes  
* Convert each byte to binary  
* Extract the LSBs   
* Convert the LSBs back to `hidded text`

### [Solution Script](decrypt.py)

```python  
with open("lsb1.bmp", "rb") as f:  
	image = f.read()  
	headless = image[54:]     # remove the Header Bytes  
  
	bin_str = ''  
	for i in headless:  
		current_char_binary = '{0:08b}'.format(i)	# convert current image byte to binary  
		bin_str += str(current_char_binary)[-1:]	# extract the LSB from the current char binary

	hidden_text = ''  
	hidden_text_size = 0  
	DELIMITER = "$" 	  
	for i in range(0, len(bin_str), 8):		  
		eight_bits = bin_str[i:i+8]			# extract 8 bits from our binary string  
		char = chr(int(eight_bits, 2))		# convert the binary back to char  
  
		if(char == DELIMITER):					# DELIMITER helps us to get the length of hidden text  
			hidden_text_size = int(hidden_text)		# get the length of the hidden text  
			hidden_text = ''  
		else:  
			hidden_text += char  
			# print(hidden_text)        # remove comment and run to see magic... 

		if(len(hidden_text) == hidden_text_size):  
			print(hidden_text)  
			break  
```

## Flag  
> DarkCTF{7H!5_0n3_was_4_l!ttl3_TRICKY}  

Original writeup (https://github.com/t3rmin0x/CTF-
Writeups/tree/master/DarkCTF/Forensics/TRICKY%20BIT#tricky-bit).