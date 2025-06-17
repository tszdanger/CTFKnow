My teammate (nobodyisnobody and macz) and I had a quick look on these
challenges, but we did not have time to flag anything but the first one during
the CTF.

The chall_2 function reversing will give us the third flag.

This function asks us for a flag and checks each letter c of the flag against
the result of rand()%3 :  
* If result == 0, it calls the function checker_1(c)  
* If result == 1, it calls the function checker_2(c)  
* If result == 2, it calls the function checker_3(c)

The problem is that the seed for the srand is changed when the library is
initialized. Then it checks the TracerPid in /proc/self/status, and if the
value is not zero, it modifies that value.

So the real seed is 0x7a69 not 0x538 :')

From here, we can bruteforce the value of the flag by checking the return
value of the three functions checker (return 1 when ok, else 0). Or... we can
reverse these three functions and calculate the flag! More interesting. In
checker's functions, a far jump is changing the execution mode from 32 bits to
64 bits. We can easily notice that by using strace. In such case, gdb is
completly out of it... I used captstone to get real instructions for those
parts.

### checker_1 function:  
The function opens the binary "./happy_fun_binary" and mmaps 0x2000 bytes of
it at address 0x180000. The letter of the flag is compared against a byte of
happy_fun_binary.  
After each execution, a counter c1_ind is incremented. This counter gives the
index for a table of 16 entries. Each entry is an offset in the mapped memory.

### checker_2 function:  
After each execution, a counter c2_ind is incremented. This counter gives the
index for a table of 19 entries. Each letter of the flag is compared against
the xor of the second byte of happy_fun_binary ("E") and the sum of the
tables's entry and the index of the letter in the flag.

### checker_3 function:  
After each execution, a counter c3_ind is incremented. This counter gives the
index for a table of 21 entries. The index of the letter in flag is used
modulo 4 to get an extra index in the ordinal values of "Y,E,E,T". So let's
make an ugly script that will resolve all that sh*t:

```  
t1 =
[0x42f,0x3a8,0x4d3,0x1be,0x1c2,0x1c2,0x1c3,0x1bf,0x3c4,0x3c4,0x3c4,0x3db,0x1be,0x3c4,0x4bd,0x2c8]  
f = open("../happy_fun_binary","rb")  
data = f.read()  
f.close()

t2=[0x28,0x22,0x1f,0x3a,0x1d,0x2b,0x15,0x16,0x0e,0x5c,0xff,0x1b,0x59,0x55,0xff,0x0d,0x0b,0xff,0xf3]

t3=[0xc3,0x98,0xcd,0x36,0xef,0x19,0x55,0xed,0xc7,0x5a,0x9e,0x6f,0x19,0x4d,0x62,0x9f,0x2c,0x81,0x42,0xf6,0xd9]

def d1(i):  
   global i1  
   c = data[t1[i1]]  
   i1 += 1  
   return chr(c)

def d2(i):  
   global i2  
   c = ((t2[i2] + i)&0xff) ^ ord("E")  
   i2 += 1  
   return chr(c)

def d3(i):  
   global i3  
   c = (t3[i3] - (i ^ [ord(x) for x in "YEET"][i&3])**2) & 0xff  
   i3 += 1  
   return chr(c)

# values of rand() for seed 0x7a69  
R =
"0111100112002112220200220111112221101202200212222210012000002022111201021022022011002000010010021102212121101101211212001102210121022011002120220"

flag = ""  
i1,i2,i3 = 0,0,0  
for i,r in enumerate(R):  
   try:  
       if r == "0":  
           flag += d1(i)  
       elif r == "1":  
           flag += d2(i)  
       elif r == "2":  
           flag += d3(i)  
   except:  
       print(flag)  
       exit()

```

This gives us flag{h3av3ns_gate_should_b3_r3nam3d_to_planar_sh1ft_1m0}