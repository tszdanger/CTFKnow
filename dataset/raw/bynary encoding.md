# Bynary Encoding

Writeup by: [j4asper](https://github.com/j4asper)

---

## Challenge Description

Starfleet has received a transmission from Bynaus. However, the message apears
to be blank. Is there some kind of hidden message here?

[transmission.txt](./files/transmission.txt)

## Challenge Solution

I first looked at the transmission.txt file, and noticed that is was filled
randomly with whitespace. I also noticed that there was 2 different "spaces"
one was long that another when going through the file with the arrow keys. To
confirm that if was binary, I expected the flag to be there. So in
[CyberChef](https://gchq.github.io/CyberChef/) i made an end curly bracket `}`
and converted it using the "To Binary" operation. Now when looking at the last
line and going through it, we notice that small spaces are zeros and the long
ones are ones. As you can see below, i have replaced the long spaces with
underscores and the small ones with a hyphen to make it easier to see.

`- _ _ _ _ _ - _` <- transmission.txt content on last line  
`0 1 1 1 1 1 0 1` <- End curly bracket in binary (to match the ending of a
flag)  

To translate the whole file, i made a quick python script to print out all the
lines as binary.

Python script:

```py  
with open("transmission.txt", "r") as f:  
   lines = f.readlines()

for line in lines:  
   bin_char = []  
   line = line.replace("\n", "")  
   for char in line:  
       if char == " ":  
           bin_char.append("0")  
       elif char == "\t":  
           bin_char.append("1")  
   print("".join(bin_char))

```

When copying the output of the file, you can paste it into
[CyberChef](https://gchq.github.io/CyberChef/) and use the "from binary"
operation, and then you will se the flag.  

Original writeup
(https://github.com/Z3R0D4Y-Team/Writeups/tree/main/2023/Space%20Heroes%20CTF/Bynary%20Encoding).