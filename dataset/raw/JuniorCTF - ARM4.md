# Junuior ARM4 - mid

**Category:** rev  
**Points:** 290  
**Solves:** 11  
**Description:**

Can you reverse engineer this code and get the flag?

This code is ARM Thumb 2 code which runs on an STM32F103CBT6. You should not
need such a controller to solve this challenge.

There are 5 stages in total which share all the same code base, so you are
able to compare code from the first stage with all the other stages to see
what code is actually relevant.

If you should need a datasheet, [you can get it
here](http://www.st.com/content/ccc/resource/technical/document/reference_manual/59/b9/ba/7f/11/af/43/d5/CD00171190.pdf/files/CD00171190.pdf/jcr:content/translations/en.CD00171190.pdf).

In case you need to refresh your ARM assembly, [check out Azeria's cool
articles](https://azeria-labs.com/writing-arm-assembly-part-1/).

[Challenge binary](arm_stage4.bin)

## Write-up

Load file in IDA, set "Processor type" to "ARM little-endian", then set "ROM
start address" and "Loading address" to 0x8000000.

sub_8000108 - is first function(entry point), and only call function
sub_8001180, sub_8001180 call sub_8000290, sub_8000290 is main.

We add segment 0x20000000-0x20005000 and in main we have code like this  
```C  
void main(void) {  
 sub_8001100();  
 sub_8000FE8();  
 print_text("Enter flag: ");  
 for ( unsigned int i = 0; i <= 13; ++i )  
 {  
   flag[i] = sub_80010DC();  
   read_char(flag[i]);                         // read 14 bytes  
 }  
 print_text("\r\n");  
 if ( 34 * flag[13] + -4 * (flag[1] - 5 * flag[0] - 16 * flag[2] + 3 *
flag[3]) - 73 * flag[4] - 65 * flag[5] + 77 * flag[6] + 20 * flag[7] - 66 *
flag[8] + 4 * flag[9] - 58 * flag[10] - 6 * flag[11] + 94 * flag[12] != 8701  
   || -48 * flag[13] + -66 * flag[0] + 56 * flag[1] - 37 * flag[2] - 8 *
flag[3] - 26 * flag[4] - 79 * flag[5] - 28 * flag[6] - 99 * flag[7] - 87 *
flag[8] - 86 * flag[9] + 71 * flag[10] - 69 * flag[11] - 43 * flag[12] !=
-40417  
   || 38 * flag[13] + 93 * flag[0] + 77 * flag[1] - 43 * flag[2] - 19 *
flag[3] + 99 * flag[4] + 61 * flag[5] + 5 * flag[6] - 67 * flag[7] - 60 *
flag[8] + 88 * flag[9] + 41 * flag[10] + 19 * flag[11] + 70 * flag[12] !=
34075  
   || (flag[13] << 6) + -44 * flag[0] - 32 * flag[1] - 30 * flag[2] + 5 *
flag[3] + 56 * flag[4] - 28 * flag[5] + 61 * flag[6] + 9 * flag[7] + 80 *
flag[8] + 40 * flag[9] - 66 * flag[10] - 42 * flag[11] + 62 * flag[12] !=
17090  
   || -40 * flag[13] + -61 * flag[0] + 46 * flag[1] + 35 * flag[2] - 33 *
flag[3] + 91 * flag[4] - 13 * flag[5] - 39 * flag[6] + 7 * flag[7] + 51 *
flag[8] + 93 * flag[9] + 55 * flag[10] + 49 * flag[11] + 94 * flag[12] !=
31516  
   || 33 * flag[13] + 17 * flag[0] - 61 * flag[1] + 51 * flag[2] + 26 *
flag[3] + 75 * flag[4] + 14 * flag[5] - 32 * flag[6] - 46 * flag[7] - 10 *
flag[8] - 36 * flag[9] + 81 * flag[10] + 69 * flag[11] - 32 * flag[12] !=
10846  
   || 29 * flag[13] + 69 * flag[0] - 92 * flag[1] + 24 * flag[2] - 33 *
flag[3] + 16 * flag[4] + 57 * flag[5] - 31 * flag[6] + 91 * flag[7] + 85 *
flag[8] + 72 * flag[9] + 23 * flag[10] + 21 * flag[11] + 45 * flag[12] !=
31883  
   || -66 * flag[13] + -22 * flag[0] + 21 * flag[1] + 52 * flag[2] + 71 *
flag[3] + 76 * flag[4] - 80 * flag[5] - 97 * flag[6] + 4 * flag[7] + 99 *
flag[8] - 7 * flag[9] - 43 * flag[10] - 13 * flag[11] + 37 * flag[12] != -2288  
   || -63 * flag[13] + -59 * flag[0] + 74 * flag[1] + 65 * flag[2] + 61 *
flag[3] - 21 * flag[4] - 9 * flag[5] + 44 * flag[6] + 13 * flag[7] + 30 *
flag[8] + 13 * flag[9] - 69 * flag[10] - 2 * flag[11] + 9 * flag[12] != 891  
   || 74 * flag[13] + 51 * flag[0] + 58 * flag[1] + 16 * flag[2] + 58 *
flag[3] + 83 * flag[4] + 30 * flag[5] - 57 * flag[6] - 27 * flag[7] - 28 *
flag[8] + 94 * flag[9] + 55 * flag[10] + 72 * flag[11] - 96 * flag[12] !=
24772  
   || 56 * flag[13] + 68 * flag[0] - 5 * flag[1] + 19 * flag[2] - 85 * flag[3]
+ 38 * flag[4] + 84 * flag[5] + 17 * flag[6] + 77 * flag[7] - 98 * flag[8] -
37 * flag[9] - 38 * flag[10] + 32 * flag[11] - 45 * flag[12] != 7094  
   || 59 * flag[13] + 13 * flag[0] + 99 * flag[1] - 21 * flag[2] + 58 *
flag[3] + 26 * flag[4] + 18 * flag[5] - 87 * flag[6] + 26 * flag[7] - 77 *
flag[8] - 47 * flag[9] + 33 * flag[10] - 45 * flag[11] - 78 * flag[12] !=
-4767  
   || 31 * flag[13] + -95 * flag[0] + 63 * flag[1] + 18 * flag[2] - 12 *
flag[3] + 56 * flag[4] - 77 * flag[5] + 68 * flag[6] + 70 * flag[7] + 54 *
flag[8] + 41 * flag[9] + 25 * flag[10] - 78 * flag[11] + 43 * flag[12] !=
27400  
   || -78 * flag[13] + 22 * flag[0] - 33 * flag[1] - 31 * flag[2] - 46 *
flag[3] + 20 * flag[4] + 80 * flag[5] - 54 * flag[6] + 55 * flag[7] + 77 *
flag[8] + 94 * flag[9] - 89 * flag[10] + 51 * flag[11] - 27 * flag[12] !=
-4494 )  
 {  
   print_text("Wrong!\r\n");  
 }  
 else  
 {  
   print_text("Correct!\r\n");  
 }  
 while ( 1 )  
   ;  
}  
```

Readed flag started from 0x20000444, and we have

Solver  
```python  
from z3_staff import * # https://github.com/KosBeg/z3_staff

var_num = 14  
create_vars(var_num, size=8)  
solver()  
init_vars(globals())  
set_ranges(var_num)

set_known_bytes('34C3_', var_num, type='start') # set flagFormat

add_eq(34*x13+-4*(x1+-5*x0+-16*x2+3*x3)+-73*x4+-65*x5+77*x6+20*x7+-66*x8+4*x9+-58*x10+-6*x11+94*x12==8701)  
add_eq(-48*x13+-66*x0+56*x1+-37*x2+-8*x3+-26*x4+-79*x5+-28*x6+-99*x7+-87*x8+-86*x9+71*x10+-69*x11+-43*x12==-40417)  
add_eq(38*x13+93*x0+77*x1+-43*x2+-19*x3+99*x4+61*x5+5*x6+-67*x7+-60*x8+88*x9+41*x10+19*x11+70*x12==34075)  
add_eq((x13<<6)+-44*x0+-32*x1+-30*x2+5*x3+56*x4+-28*x5+61*x6+9*x7+80*x8+40*x9+-66*x10+-42*x11+62*x12==17090)  
add_eq(-40*x13+-61*x0+46*x1+35*x2+-33*x3+91*x4+-13*x5+-39*x6+7*x7+51*x8+93*x9+55*x10+49*x11+94*x12==31516)  
add_eq(33*x13+17*x0+-61*x1+51*x2+26*x3+75*x4+14*x5+-32*x6+-46*x7+-10*x8+-36*x9+81*x10+69*x11+-32*x12==10846)  
add_eq(29*x13+69*x0+-92*x1+24*x2+-33*x3+16*x4+57*x5+-31*x6+91*x7+85*x8+72*x9+23*x10+21*x11+45*x12==31883)  
add_eq(-66*x13+-22*x0+21*x1+52*x2+71*x3+76*x4+-80*x5+-97*x6+4*x7+99*x8+-7*x9+-43*x10+-13*x11+37*x12==-2288)  
add_eq(-63*x13+-59*x0+74*x1+65*x2+61*x3+-21*x4+-9*x5+44*x6+13*x7+30*x8+13*x9+-69*x10+-2*x11+9*x12==891)  
add_eq(74*x13+51*x0+58*x1+16*x2+58*x3+83*x4+30*x5+-57*x6+-27*x7+-28*x8+94*x9+55*x10+72*x11+-96*x12==24772)  
add_eq(56*x13+68*x0+-5*x1+19*x2+-85*x3+38*x4+84*x5+17*x6+77*x7+-98*x8+-37*x9+-38*x10+32*x11+-45*x12==7094)  
add_eq(59*x13+13*x0+99*x1+-21*x2+58*x3+26*x4+18*x5+-87*x6+26*x7+-77*x8+-47*x9+33*x10+-45*x11+-78*x12==-4767)  
add_eq(31*x13+-95*x0+63*x1+18*x2+-12*x3+56*x4+-77*x5+68*x6+70*x7+54*x8+41*x9+25*x10+-78*x11+43*x12==27400)  
add_eq(-78*x13+22*x0+-33*x1+-31*x2+-46*x3+20*x4+80*x5+-54*x6+55*x7+77*x8+94*x9+-89*x10+51*x11+-27*x12==-4494)

i = 0  
start_time = time.time()  
while s.check() == sat:  
 prepare_founded_values(var_num)  
 print prepare_key(var_num)  
 iterate_all(var_num)  
 i += 1  
print('--- %.2f seconds && %d answer(s) ---' % ((time.time() - start_time), i)
)  
```  
```  
34C3_1_d0_m4th  
--- 0.18 seconds && 1 answer(s) ---  
```

Flag is: **34C3_1_d0_m4th**  

Original writeup (https://github.com/KosBeg/ctf-
writeups/tree/master/34C3_CTF/arm_stage4).