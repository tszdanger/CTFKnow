## 0CTF 2020 - W (Reversing 523)  
##### 29/06 - 01/07/2020 (48hr)  
___

### Description

-

___

### Solution

This is [WebAssembly](https://webassembly.org/) challenge:  
```  
ispo@ispo-glaptop2:~/ctf/0ctf_2020/W$ file ww  
ww: WebAssembly (wasm) binary module version 0x1 (MVP)

ispo@ispo-glaptop2:~/ctf/0ctf_2020/W$ ./wasm3 ww  
Secret: ?  
ispo  
hmmm...

ispo@ispo-glaptop2:~/ctf/0ctf_2020/W$ rewasm/target/release/rewasm ww >
decomp.wasm  
```

The good news about [WebAssembly](https://webassembly.org/) binaries is that
they can be decompiled.  
A quick search shows several available decompilers.  
We will use [ReWasm](https://github.com/benediktwerner/rewasm) and  
[JEB Pro](https://www.pnfsoftware.com/). Let's load `ww` binary on JEB Pro.
Program starts from  
function `__f13` (we can easily find that by checking the XREFs to the
`Secret: ?` string). We  
clean it up a little and we rename the functions:  
```c  
int main__f13(int param0, int param1) {  
   int v0 = __g0 - 112;

   __g0 -= 112;  
   *(int*)(v0 + 108) = 0;  
   *(int*)(v0 + 104) = param0;  
   *(int*)(v0 + 100) = param1;  
   setvbuf__f264(0, 2, 0, gvar_5B40_);  
   setvbuf__f264(0, 2, 0, gvar_5B44);  
   *(int*)v0 = 0;  
   int fp = open__f246(v0, 0, "/dev/urandom");  
   *(int*)(v0 + 96) = fp;  
   *(long long*)(v0 + &gvar_20_secret) = 0L;  
   *(long long*)(v0 + 88) = 0L;  
   *(long long*)(v0 + 80) = 0L;  
   *(long long*)(v0 + 72) = 0L;  
   *(long long*)((int*)((int)&gvar_20_secret + v0) + &gvar_8) = 0L;  
   *(long long*)((int*)((int)&gvar_18 + v0) + &gvar_8) = 0L;  
   *(unsigned long long*)((int*)((int)&gvar_10 + v0) + &gvar_8) = 0L;  
   *(long long*)((int*)((int)&gvar_8 + v0) + &gvar_8) = 0L;  
   print__f258(0x5615);  // Secret:  
   int v2 = fgets__f263(gvar_5B40_, 64, v0 + &gvar_20_secret);  // secret is
up to 64 bytes  
   if(v2 == 0) {  
       *(int*)(v0 + 108) = -1;  
   }  
   else {  
       int secret_len = strlen__f292(v0 + &gvar_20_secret);  
       *(char*)(v0 + secret_len + &gvar_20_secret) = 0;  
       int buf = calloc__f238(1, (int)(gvar_5604_buflen + 1));  // 0x5201  
       *(int*)((int)&gvar_1C_buf + v0) = buf;  
       if(*(unsigned int*)((int)&gvar_1C_buf + v0) == 0) {  
           *(int*)(v0 + 108) = -1;  
       }  
       else {  
           memcpy__f291(gvar_5604_buflen, &ENC_BUF_START, *(int*)((int)&gvar_1C_buf + v0));  
           unpack__f42(v0 + &gvar_20_secret, gvar_5604_buflen, *(int*)((int)&gvar_1C_buf + v0));  
           int v5 = *(int*)((int)&gvar_1C_buf + v0);  
           int buf = gvar_5604_buflen;  
           int len = strlen__f292("Welcome to 0CTF/TCTF 2020! Have a g00d time");  // *0x5604 is 0x5200  
           int start = memmem__f293(len, "Welcome to 0CTF/TCTF 2020! Have a g00d time", buf, v5);  
           if(!start) {  
               print__f258("hmmm...");  
               *(int*)(v0 + 108) = 0;  
           }  
           else {  
               print__f258("Loading...");  // unpacking successful  
               int v9 = load_wasm__f33(gvar_5604_buflen, *(int*)((int)&gvar_1C_buf + v0));  
               *(int*)((int)&gvar_18 + v0) = v9;  
               int v10 = init_interpreter__f43(*(int*)((int)&gvar_18 + v0));  
               *((int*)((int)&gvar_10 + v0) + 1) = v10;  
               load_data_section__f46(*((int*)((int)&gvar_10 + v0) + 1));  
               load_globals__f47(*((int*)((int)&gvar_10 + v0) + 1));  
               print__f258("Go Go Go!!");  
               int res = run__f52(22, *((int*)((int)&gvar_10 + v0) + 1)); // start execution from function 22  
               *(int*)((int)&gvar_10 + v0) = res;  
               free_interpreter__f45(*((int*)((int)&gvar_10 + v0) + 1));  
               free_wasm_obj__f41(*(int*)((int)&gvar_18 + v0));  
               free__f236(*(int*)((int)&gvar_1C_buf + v0));  
               if(*(int*)(v0 + 96) != -1) {  // fp from urandom  
                   close__f242(*(int*)(v0 + 96));  
               }  
               *(int*)(v0 + 108) = *(int*)((int)&gvar_10 + v0);  
           }  
       }  
   }

   int result = *(int*)(v0 + 108);  
   __g0 = v0 + 112;  
   return result;  
}  
```

Unfortunately, JEB does not recognize standard functions (for instance
`memcpy` is shown as `__f291`  
in JEB). However, ReWasm can determine function names as you can see:  
```c  
   puts(22058);  
   var_32 = load<i32>(var_2 + 28);  
   var_33 = load<i32>(0 + 22020);  
   var_34 = load_wasm(var_32, var_33);  
   store<i32>(var_2 + 24, var_34)  
   var_35 = load<i32>(var_2 + 24);  
   var_36 = init_interpreter(var_35);  
   store<i32>(var_2 + 20, var_36)  
   var_37 = load<i32>(var_2 + 20);  
   load_data_section(var_37);  
   var_38 = load<i32>(var_2 + 20);  
   load_globals(var_38);  
   puts(22069);  
   var_39 = load<i32>(var_2 + 20);  
   var_40 = run(var_39, 22);  
   store<i32>(var_2 + 16, var_40)  
   var_41 = load<i32>(var_2 + 20);  
   free_interpreter(var_41);  
   var_42 = load<i32>(var_2 + 24);  
   free_wasm_obj(var_42);  
   var_43 = load<i32>(var_2 + 28);  
   free(var_43);  
   var_44 = load<i32>(var_2 + 96);  
   var_45 = var_44 != -1 & 1;  
   if var_45 != 0 {  
       var_46 = load<i32>(var_2 + 96);  
       close(var_46);  
   }  
   var_47 = load<i32>(var_2 + 16);  
   store<i32>(var_2 + 108, var_47)  
```

Therefore, we simply rename JEB functions based on ReWasm output. Let's now
see how program works.  
First it computes the length of the secret input and then allocates a buffer
of size `5201h` bytes:  
```c  
int secret_len = strlen__f292(v0 + &gvar_20_secret);  
*(char*)(v0 + secret_len + &gvar_20_secret) = 0;

int buf = calloc__f238(1, (int)(gvar_5604_buflen + 1));  // 0x5201  
*(int*)((int)&gvar_1C_buf + v0) = buf;  
```

```  
.data:00005604    gvar_5604_buflen dd 5200h                                  ;
xref: main__f13+2A2h (data-adv) / main__f13+280h (data-adv) / main__f13+1D5h
(data-adv) / main__f13+255h (data-adv) / main__f13+31Ch (data-adv)  
```

Then program copies `5200h` bytes from address `400h` (`ENC_BUF_START`) into
buffer:  
```c  
memcpy__f291(gvar_5604_buflen, &ENC_BUF_START, *(int*)((int)&gvar_1C_buf +
v0));  
```

Let's see teh contents at address `400h`:  
```  
.data:00000400 ENC_BUF_START    db 9Ah  
.data:00000401        db B6h, A9h, E9h, 95h, CFh, BEh, DCh, B7h, EDh, CBh,
F3h, 9Bh, "z6h"  
.data:00000410        db '!', 1Eh, 0, 'f', 81h, 'g', 19h, FFh, AFh, 97h, 'y',
0, F9h, A6h, AEh, 11h  
.data:00000420        db 0Bh, C5h, ACh, 1Eh, 3, 'T', A6h, 'E', A0h, C8h, 97h,
D4h, ':', DBh, 14h, ABh  
.....  
.data:00005200        db 9Ah, BFh, F1h, C7h, FBh, " 'e", 0Eh, ',', 13h, 'K',
2, "`mN"  
.data:00005210        db "N~", 0, "@ g", 19h, '8', 8, "1|", 2, "\`", 11h, '/'  
.data:00005220        db "K$K?", C7h, F7h, A6h, CBh, EBh, 83h, BCh, C4h, AEh,
8Dh, 'C', 0Bh  
.....  
```

Then program invokes a special `unpack` function that takes as input i) the
secret (`param0`),  
ii) the size of the buffer which is `0x5200` (`param1`) and iii) the address
of the newly  
allocated buffer (`param2`):  
```c  
unpack__f42(v0 + &gvar_20_secret, gvar_5604_buflen, *(int*)((int)&gvar_1C_buf
+ v0));  
```

Finally, program verifies if unpacking is successfully or not, by searching in
the "unpacked" buffer  
for the presence of the `Welcome to 0CTF/TCTF 2020! Have a g00d time` string.
If this string is not  
found the `hmmm...` message is printed and the program terminates. Otherwise,
it moves on with the  
execution of the second stage payload:  
```c  
int v5 = *(int*)((int)&gvar_1C_buf + v0);  
int buf = gvar_5604_bufaddr;  
int len = strlen__f292("Welcome to 0CTF/TCTF 2020! Have a g00d time");  //
*0x5604 is 0x5200  
int start = memmem__f293(len, "Welcome to 0CTF/TCTF 2020! Have a g00d time",
buf, v5);  
if(!start) {  
   puts__f258("hmmm...");  
   *(int*)(v0 + 108) = 0;  
}  
else {  
   print__f258("Loading...");  // unpacking successful  
   /* .... */  
}  
```  

### Reversing the Unpacking Routine

Unfortunately, JEB fails to decompile `unpack`, so we switch to ReWasm:  
```c  
void unpack__f42(int par0, int par1, int par2) {  
   // Decompilation error  
}

```

```c  
// Function 42  
fn unpack(i32 arg_0, i32 arg_1, i32 arg_2) {  
   var_3 = 0;  
   /* ... */  
   var_42 = 0;  
   var_43 = global_0 - 48;  
   store<i32>(var_43 + 44, arg_0)                      // buf  
   gl0_b = global_0 - 48;  
   store<i32>(gl0_b + 40, arg_1)                       // buflen = 0x5200  
   gl0_c = global_0 - 48;  
   store<i32>(gl0_c + 36, arg_2)                       // flag  
   gl0_d = global_0 - 48;  
   var_47 = load<i32>(gl0_d + 40);                     // g40 = buflen  
   if (var_47 & 511) == 0 {                            // 0x5200 & 0x1FF == 0
? yes!  
       gl0_e = global_0 - 48;  
       var_49 = load<i32>(gl0_e + 40);                 // g40 = buflen  
       gl0_e = global_0 - 48;  
       var_51 = var_49 >>u 9;                          // buflen >> 9  
       store<i32>(gl0_e + 32, var_51)                  // g32 = buflen >> 9  
       gl0_g = global_0 - 48;  
       var_53 = load<i32>(gl0_g + 44);  
       gl0_h = global_0 - 48;  
       store<i32>(gl0_h + 28, var_53)                  // g28 = buf  
       gl0_i = global_0 - 48;  
       store<i32>(gl0_i + 24, 0)                       // g24 = i = 0  
       while true {  
           gl0_j = global_0 - 48;  
           var_57 = load<i32>(gl0_j + 24);             // i  
           gl0_k = global_0 - 48;  
           var_59 = load<i32>(gl0_k + 32);             // buflen >> 9  
           var_60 = var_57 _> 9) ?  
           if var_60 == 0 {  
               break;                                  // if not break  
           }  
           gl0_l = global_0 - 48;  
           store_8<i32>(gl0_l + 23, 255)               // g23 = 255 = a  
           gl0_m = global_0 - 48;  
           store<i32>(gl0_m + 16, 0)                   // g16 = j = 0  
           while true {  
               gl0_n = global_0 - 48;  
               var_64 = load<i32>(gl0_n + 16);         // g16 = j  
               var_65 = var_64 _(gl0_o + 16);         // j  
               var_3 = var_67;  
               var_4 = 31;  
               var_5 = var_67 & 31;  
               gl0_p = global_0 - 48;  
               var_69 = var_67 & 31;  
               store_8<i32>(gl0_p + 15, var_69)        // g15 = j & 0x1F  
               gl0_q = global_0 - 48;  
               var_71 = load<i32>(gl0_q + 36);         // g36 = flag  
               var_6 = var_71;  
               gl0_r = global_0 - 48;  
               var_73 = load_8u<i32>(gl0_r + 15);      // g15 = j & 0x1F  
               var_7 = var_73;  
               var_8 = 255;  
               var_9 = var_73 & 255;  
               var_10 = var_71 + (var_73 & 255);       // & flag + (j & 0x1F)  
               var_74 = load_8u<i32>(var_10);          // f = flag[j & 0x1F]  => Flag is 31 characters!  
               var_11 = var_74;  
               var_12 = 255;  
               var_13 = var_74 & 255;  
               gl0_s = global_0 - 48;  
               var_76 = load_8u<i32>(gl0_s + 23);      // g23 = a  
               var_14 = var_76;  
               var_15 = 24;  
               var_16 = var_76 << 24;  
               var_17 = var_76 << 24 >>s 24;           // (a << 24) >> 24 ? ~> a  
               var_18 = var_74 & 255 ^ var_17;         // flag[j & 0x1F] ^ a  
               gl0_t = global_0 - 48;  
               var_78 = load<i32>(gl0_t + 28);         // g28 = buf  
               var_19 = var_78;  
               gl0_u = global_0 - 48;  
               var_80 = load<i32>(gl0_u + 16);         // g16 = j  
               var_20 = var_80;  
               var_21 = var_78 + var_80;  
               var_81 = load_8u<i32>(var_78 + var_80); // buf[j]  
               var_22 = var_81;  
               var_23 = 255;  
               var_24 = var_81 & 255;  
               var_25 = var_18 ^ var_81 & 255;         // flag[j & 0x1F] ^ a ^ buf[j]  
               gl0_v = global_0 - 48;  
               store_8<i32>(gl0_v + 14, var_25)        // g14 = flag[j & 0x1F] ^ a ^ buf[j]  
               gl0_w = global_0 - 48;  
               var_84 = load<i32>(gl0_w + 28);         // g28 = buf  
               var_26 = var_84;  
               gl0_x = global_0 - 48;  
               var_86 = load<i32>(gl0_x + 16);         // g16 = i  
               var_27 = var_86;  
               var_28 = var_84 + var_86;  
               var_87 = load_8u<i32>(var_84 + var_86); // buf[j]  
               var_29 = var_87;  
               gl0_y = global_0 - 48;  
               store_8<i32>(gl0_y + 23, var_87)        // g23 = a = buf[j]  
               gl0_z = global_0 - 48;  
               var_90 = load_8u<i32>(gl0_z + 14);      // g14 = flag[j & 0x1F] ^ a ^ buf[j]  
               var_30 = var_90;  
               var_31 = 255;  
               var_32 = var_90 & 255;  
               gl0_aa = global_0 - 48;  
               var_92 = load_8u<i32>(gl0_aa + 15);     // g15 = j & 0x1F  
               var_33 = var_92;  
               var_34 = 255;  
               var_35 = var_92 & 255;  
               var_93 = var_92 & 255;  
               var_36 = (var_90 & 255) - var_93;       // flag[j & 0x1F] ^ a ^ buf[j] - (j & 0x1F)  
               gl0_ab = global_0 - 48;  
               var_95 = load<i32>(gl0_ab + 28);        // g28 = buf  
               var_37 = var_95;  
               gl0_ac = global_0 - 48;  
               var_97 = load<i32>(gl0_ac + 16);        // g16 = j  
               var_38 = var_97;  
               var_39 = var_95 + var_97;  
               store_8<i32>(var_95 + var_97, var_36)   // buf[j] = flag[j & 0x1F] ^ a ^ buf[j] - (j & 0x1F)  
               gl0_ad = global_0 - 48;  
               var_99 = load<i32>(gl0_ad + 16);        // g16 = j  
               var_40 = var_99;  
               var_41 = 1;  
               var_42 = var_99 + 1;                    // j + 1  
               gl0_ae = global_0 - 48;  
               var_101 = var_99 + 1;  
               store<i32>(gl0_ae + 16, var_101)        // g16 = j = j + 1 (++j)  
           }  
           var_102 = global_0 - 48;  
           var_103 = load<i32>(var_102 + 28);          // g28 = buf  
           var_104 = global_0 - 48;  
           var_105 = var_103 + 512;  
           store<i32>(var_104 + 28, var_105)           // g28 = buf = buf + 512 (move on the next chunk)  
           var_106 = global_0 - 48;  
           var_107 = load<i32>(var_106 + 24);          // g24 = i = outer iterator  
           var_108 = global_0 - 48;  
           var_109 = var_107 + 1;                      // ++i  
           store<i32>(var_108 + 24, var_109)           // g24 = i + 1  
       }  
   }  
   return;  
}  
```__

Let's decompile this function into Python:  
```python  
def unpack(buf, buflen, secret):  
   """Unpacks the WebAssebmly stage 2 payload."""  
   for i in range(0, buflen >> 9):  
       a = 255  
       for j in range(512):  
           b = ord(secret[j & 0x1F]) ^ a ^ buf[i*512 + j]  
           a = buf[i*512 + j]

           buf[i*512 + j] = (b - (j & 0x1F)) & 0xFF

   return buf  
```

That's quite simple isn't it? **Each byte of the buffer is XORed with the next
character from the  
secret and the previous plaintext byte of the buffer**. We also know (from `j
& 0x1F` part) that  
the **secret is 32 characters long**.

### Cracking the Unpacking Routine

The question now, is how to find the secret? We know that somewhere in the
decrypted buffer, there  
is the string `Welcome to 0CTF/TCTF 2020! Have a g00d time`, so we can
leverage that to do a  
*Known Plaintext Attack*. If we know the position of the plaintext string in the buffer, we can  
apply the reverse algorithm and recover the secret. Since the buffer is small
only (`5200h` bytes),  
we can brute force the starting position and check which decryption yields to
a meaningful secret  
(i.e., is ASCII printable). Here's how we do that:  
```python  
# Brute force plaintext location inside buf.  
for i in range(len(buf) - len(plain)):  
   secret = [0]*32

   for k in range(0, len(plain)):  
       j = (i + k) & 0x1F

       b = (plain[k] + (j & 0x1F)) & 0xFF  
       a = buf[i + k - 1] if i + k - 1 > 0 else 255  
       secret[j] = b ^ a ^ buf[i + k]  
  
   if all(x >= 0x20 and x <= 0x7e for x in secret):  
       secret = ''.join(chr(s) for s in secret)  
       print(f'[+] Secret FOUND at offset {i} : {secret}')  
       break  
```

The above code finds a unique solution at offset `20346`:
`eNj0y_weba5SemB1Y.lstrip("web")!`

We try the secret to see if it works:  
```  
ispo@ispo-glaptop2:~/ctf/0ctf_2020/W$ ./wasm3 ww  
Secret: ?  
eNj0y_weba5SemB1Y.lstrip("web")!  
Loading...  
Go Go Go!!  
aoshine~ What's up?  
1. add pair  
2. dump pair  
3. check pair  
4. exit

```

For more details please refer to the [w_crack.py](./w_crack.py) script.

### Reversing Second Stage Payload

If we go back to main (`__f13`) we can see what program does with the
decrypted buffer:  
```c  
   print__f258("Loading...");  // unpacking successful  
   int v9 = load_wasm__f33(gvar_5604_buflen, *(int*)((int)&gvar_1C_buf + v0));  
   *(int*)((int)&gvar_18 + v0) = v9;  
   int v10 = init_interpreter__f43(*(int*)((int)&gvar_18 + v0));  
   *((int*)((int)&gvar_10 + v0) + 1) = v10;  
   load_data_section__f46(*((int*)((int)&gvar_10 + v0) + 1));  
   load_globals__f47(*((int*)((int)&gvar_10 + v0) + 1));  
   print__f258("Go Go Go!!");  
   int res = run__f52(22, *((int*)((int)&gvar_10 + v0) + 1)); // start
execution from function 22  
   *(int*)((int)&gvar_10 + v0) = res;  
   free_interpreter__f45(*((int*)((int)&gvar_10 + v0) + 1));  
   free_wasm_obj__f41(*(int*)((int)&gvar_18 + v0));  
   free__f236(*(int*)((int)&gvar_1C_buf + v0));  
```

That is, we expect the decrypted buffer to also be a WebAssembly binary:  
```  
ispo@ispo-glaptop2:~/ctf/0ctf_2020/W$ file ww.stage2  
ww.stage2: WebAssembly (wasm) binary module version 0x1 (MVP)  
```

Let's load it again in JEB and start from function `22` (this is where
`run__f52` starts from):  
```c  
int main__f22() {  
   int* glo = __g0 - 0x118;

   __g0 -= 0x118;  
   *(glo + 0x117) = 0;  
   int num_a = __f23((int)(gvar_400 * 12));  // 0x80  
   *(glo + 0x116) = num_a;  
   if(*(glo + 0x116) == 0) {  
       *(glo + 0x117) = -1;  
   }  
   else {  
       int num_b = __f23((int)(gvar_400 * 4));  // 0x200  
       *(glo + 0x115) = num_b;  
       if(*(glo + 0x115) == 0) {  
           *(glo + 0x117) = -1;  
       }  
       else {  
           int fp = open(0, 0, "/dev/urandom");  
           *(glo + 0x114) = fp;  
           __f31(&gvar_400, 0, (int)(glo + 20));  
           *(glo + 19) = (int)(glo + 20);  
           *(glo + 18) = &gvar_400;  
           *(glo + 17) = 3;  
           *(long long*)(glo + 8) = 0L;  
           *(long long*)(glo + 14) = 0L;  
           *(long long*)(glo + 12) = 0L;  
           *(long long*)(glo + 10) = 0L;  
           *(glo + 7) = -1;  
           p_and_q__f7(*(glo + 0x116));  
           __f17((int)(gvar_400 * 4), -1, *(glo + 0x115));  
           puts__f20("aoshine~ What\'s up?\n");  
           *(glo + 6) = 0;  
           while(1) {  
               show_menu__f21();  
               read_str__f12(2, (int)(glo + 8), 0);  
               int choice = read_inp__f18((int)(glo + 8));  
               *(glo + 7) = choice;  
               if(*(glo + 7) == 1 && *(glo + 17) < gvar_400 && *(glo + 6) < &gvar_400) {  
                   goto NEW_PAIR;  
               }  
               else if(*(glo + 7) == 2) {  
                   DUMP_PAIR__f10(*(glo + 17), *(glo + 0x115), *(glo + 0x116));  
                   continue;  
               }  
               if(*(glo + 7) == 3) {  
                   int chk_res = CHECK_PAIR__f3(*(*(unsigned int*)(glo + 0x116) + 7), *(*(unsigned int*)(glo + 0x116) + 4));  
                   *(glo + 3) = chk_res;  
                   if(!*(glo + 3)) {  // this must return non zero  
                       puts__f20(*(*(unsigned int*)(glo + 0x116) + 1));  
                       puts__f20("hmmm, try again\n");  
                   }  
                   else {  
                       itoa__f19((int)(glo + 8), *(glo + 3));  // secret number is 32-bits  
                       puts__f20("flag is: flag{secret+");  
                       puts__f20((int)(glo + 8));  
                       puts__f20("}\n");  
                       continue;  
                   NEW_PAIR:  
                       puts__f20("input new pair:\n");  
                       int len_maybe = read_str__f12(*(glo + 18) - *(glo + 6), *(glo + 19), 0);  
                       *(glo + 5) = len_maybe;  
                       if(*(glo + 5) <= 0) {  
                           *(glo + 0x117) = -1;  
                           break;  
                       }  
                       else if(*(glo + 5) + *(glo + 6) + 1 > &gvar_400) {  
                           continue;  
                       }  
                       else {  
                           *(glo + 6) = *(glo + 5) + *(glo + 6) + 1;  
                           *(char*)(*(glo + 5) + *(glo + 19)) = 0;  
                           int v6 = ADD_PAIR__f9(*(glo + 17), *(glo + 0x115), *(glo + 0x116), *(glo + 5), *(glo + 19));  
                           *(glo + 4) = v6;  
                           if(*(glo + 4)) {  
                               goto loc_50002855;  
                           }  
                           else {  
                               puts__f20(*(*(unsigned int*)(glo + 0x116) + 1));  
                               puts__f20(", bye~\n");  
                           }  
                       }  
                   }  
               }  
               if(*(glo + 0x116) != 0) {  
                   __f25(*(glo + 0x116));  
               }  
               if(*(glo + 0x115) != 0) {  
                   __f25(*(glo + 0x115));  
               }  
               *(glo + 0x117) = 0;  
               break;  
           loc_50002855:  
               *(glo + 17) = *(glo + 4) + *(glo + 17);  
               *(glo + 19) = *(glo + 5) + *(glo + 19) + 1;  
           }  
       }  
   }

   int result = *(glo + 0x117);  
   __g0 = glo + 0x118;  
   return result;  
}  
```

```c  
void show_menu__f21() {  
   puts__f20("1. add pair\n");  
   puts__f20("2. dump pair\n");  
   puts__f20("3. check pair\n");  
   puts__f20("4. exit\n");  
}  
```

Unfortunately, neither JEB not ReWasm provide function names (e.g., `itoa` or
`puts`), but we can  
easily recognize them by looking their input/output. Program shows a small
menu where it can *add*,  
*dump* and *check* a pair (whatever that means) in a loop. Let's see how we can get the flag:  
```c  
int chk_res = CHECK_PAIR__f3(*(*(unsigned int*)(glo + 0x116) + 7),
*(*(unsigned int*)(glo + 0x116) + 4));  
*(glo + 3) = chk_res;

if(!*(glo + 3)) {  // this must return non zero  
   puts__f20(*(*(unsigned int*)(glo + 0x116) + 1));  
   puts__f20("hmmm, try again\n");  
} else {  
   itoa__f19((int)(glo + 8), *(glo + 3));  // secret number is 32-bits  
   puts__f20("flag is: flag{secret+");  
   puts__f20((int)(glo + 8));  
   puts__f20("}\n");  
}  
```

Function `__f3` is responsible for implementing the `check pair`
functionality. The input is a pair  
of numbers and the output must be non-zero:  
```c  
// Function 3  
fn func_3(i32 arg_0, i32 arg_1) -> i32 {  
   /* ... */  
   var_2 = global_0 - 32;  
   var_3 = global_0 - 32;  
   global_0 = var_3;  
   store<i32>(var_2 + 24, arg_0)                       // g24 = arg0  
   store<i32>(var_2 + 20, arg_1)                       // g20 = arg1  
   var_4 = load<i32>(var_2 + 24);                      // arg0  
   var_5 = var_4 != 0 & 1;  
   var_6 = var_5 == 0;  
   if !var_6 {                                         // arg0 must be non-
zero  
       var_7 = load<i32>(var_2 + 20);                  // arg1  
       var_8 = var_7 != 0 & 1;  
       var_9 = var_8;  
       if var_9 {                                      // arg1 must be non zero as well  
           var_10 = load<i32>(var_2 + 24);  
           var_11 = func_18(var_10);  
           store<i32>(var_2 + 16, var_11)              // g16 = func_18(arg0)  
           var_12 = load<i32>(var_2 + 20);  
           var_13 = func_18(var_12);  
           store<i32>(var_2 + 12, var_13)              // g12 = func_18(arg1)  
           var_14 = load<i32>(var_2 + 16);  
           var_15 = func_4(var_14);                    // func_4(func_18(arg0))  
           var_16 = var_15 == 0;  
           if !var_16 {                                // must be nonzero  
               var_17 = load<i32>(var_2 + 12);  
               var_18 = func_4(var_17);                // func_4(func_18(arg1))  
               var_19 = var_18;  
               if var_19 {                             // must be nonzero too  
                   var_20 = load<i32>(var_2 + 16);  
                   var_21 = load<i32>(var_2 + 12);  
                   var_22 = var_21 * 87;  
                   var_23 = var_20 * 20 + var_22;  
                   store<i32>(var_2 + 8, var_23)       // g8 = func_18(arg0)*20 + func_18(arg1)*87  
                   var_24 = load<i32>(var_2 + 16);  
                   var_25 = load<i32>(var_2 + 12);  
                   var_26 = var_24 + var_25;  
                   store<i32>(var_2 + 4, var_26)       // g4 = func_18(arg0) + func_18(arg1)  
                   var_27 = load<i32>(var_2 + 8);  
                   var_28 = var_27 == 20200627 & 1;    // func_18(arg0)*20 + func_18(arg1)*87 == 20200627  
                   var_29 = var_28 == 0;  
                   if !var_29 {                        // must be true  
                       var_30 = load<i32>(var_2 + 4);  
                       var_31 = var_30 == 249310 & 1;  // func_18(arg0) + func_18(arg1) == 249310  
                   }  
                   if var_29 || !var_29 && var_31 == 0 {  
                       store<i32>(var_2 + 28, 0)       // g28 = 0  
                   }  
                   else {  
                       var_32 = load<i32>(var_2 + 16);  
                       var_33 = load<i32>(var_2 + 12);  
                       var_34 = var_33 * 20;           // func_18(arg1)*20  
                       var_35 = var_32 * 20 + var_34;  // func_18(arg0)*20 + func_18(arg1)*20  
                       var_36 = var_35 + 628;  
                       store<i32>(var_2 + 28, var_36)  // g28 = 20*(func_18(arg0) + func_18(arg1)) + 628  
                   }  
               }  
           }  
           if var_16 || !var_16 && !var_19 {  
               store<i32>(var_2 + 28, 0)               // g28 = 0  
           }  
       }  
   }  
   if var_6 || !var_6 && !var_9 {  
       store<i32>(var_2 + 28, 0)                       // g28 = 0  
   }  
   var_37 = load<i32>(var_2 + 28);  
   global_0 = var_2 + 32;  
   return var_37;                                      // return g28  
}  
```

Let's decompile this function into Python:  
```python  
def check_pair(arg0, arg1):  
   """Checks if a pair of numbers is 'good'."""  
   if not func_4(func_18(arg0)) or not func_4(func_18(arg1)):  
       return 0

   if func_18(arg0)*20 + func_18(arg1)*87 != 20200627:  
       return 0

   if func_18(arg0) + func_18(arg1) != 249310:  
       return 0

   return 20*(func_18(arg0) + func_18(arg1)) + 628  
```

Function `func_4` is really long, but we do not really need to know what it
does as it is only  
used for a check. Apart from that, function takes as input **2** numbers, `x`
and `y` and checks  
if they satisfy the following equations:  
```  
20*x + 87*y = 20200627  
  x +    y = 249310  
```

If `x` and `y` satisfy the above equations, function returns `20*(x + y) +
628` which is our flag.

This is a linear system of **2** equations, so it's very easy to find `x =
22229` and `y = 227081`.  
Then the expected return value of `check_pair` will be `4986828`.

  
So the flag is: `flag{eNj0y_weba5SemB1Y.lstrip("web")!+4986828}`

### Bonus: Verifying Flag in the Binary  

At this point, the challenge was over (I already had the correct flag), but it
was still unclear to  
me how to pass the right input to the program:  
```  
ispo@ispo-glaptop2:~/ctf/0ctf_2020/W$ ./wasm3 ww  
Secret: ?  
eNj0y_weba5SemB1Y.lstrip("web")!  
Loading...  
Go Go Go!!  
aoshine~ What's up?  
1. add pair  
2. dump pair  
3. check pair  
4. exit  
1  
input new pair:  
22229 227081  
1. add pair  
2. dump pair  
3. check pair  
4. exit  
3  
Welcome to 0CTF/TCTF 2020! Have a g00d timehmmm, try again  
```

Just for my curiosity I continued trying to understand the program. The first
interesting part was  
at function `__f7`:  
```c  
int p_and_q__f7(int param0) {  
   int* ptr0 = __g0 - 4;

   __g0 -= 4;  
   *(ptr0 + 3) = param0;  
   __f17(0x600, 0, *(ptr0 + 3));  
   **(unsigned int*)(ptr0 + 3) = "0ops";  
   *(*(unsigned int*)(ptr0 + 3) + 1) = "Welcome to 0CTF/TCTF 2020! Have a g00d time";  
   *(*(unsigned int*)(ptr0 + 3) + 2) = 25;  
   *(*(unsigned int*)(ptr0 + 3) + 3) = "p";  
   *(*(unsigned int*)(ptr0 + 3) + 4) = 0;  // p value  
   *(*(unsigned int*)(ptr0 + 3) + 5) = 0;  
   *(*(unsigned int*)(ptr0 + 3) + 6) = "q";  
   *(*(unsigned int*)(ptr0 + 3) + 7) = 0;  // q value  
   *(*(unsigned int*)(ptr0 + 3) + 8) = 0;  
   int result = *(ptr0 + 3);  
   __g0 = ptr0 + 4;  
   return result;  
}  
```

This function initializes an object of pointers. The important part is the
strings `p` and `q`. Now  
let's look at how a new pair is added to the list (program can store multiple
pairs):  
```c  
int ADD_PAIR__f9(int param0, int param1, int param2, int param3, int param4) {  
   int* ptr0 = __g0 - &gvar_10;

   __g0 -= &gvar_10;  
   *(ptr0 + 14) = param0;  
   *(ptr0 + 13) = param1;  
   *(ptr0 + 12) = param2;  
   *(ptr0 + 11) = param3;  
   *(ptr0 + 10) = param4;  // len maybe  
   if(*(ptr0 + 14) == 0 || *(ptr0 + 12) == 0 || !(unsigned int)(*(ptr0 + 11)
!= 0)) {  
       *(ptr0 + 15) = 0;  
   }  
   else {  
       *(ptr0 + 9) = *(ptr0 + 13) + *(ptr0 + 14);  
       if(*(ptr0 + 9) < *(ptr0 + 14)) {  
           *(ptr0 + 15) = 0;  
       }  
       else {  
           *(ptr0 + 8) = *(ptr0 + 14);  
           *(ptr0 + 7) = *(ptr0 + 14);  
           *(ptr0 + 6) = 0;  
           *(ptr0 + 5) = 128 - *(ptr0 + 10);  
           *(ptr0 + 4) = 0;  
           *(ptr0 + 3) = 0;  
           while(((*(ptr0 + 8) - *(ptr0 + 7) < *(ptr0 + 13) ? (unsigned int)(*(ptr0 + 4) < *(ptr0 + 5)): 0) & 0x1) != 0) {  
               int v0 = strcat__f16(*(ptr0 + 9) - *(ptr0 + 8), 10, *(ptr0 + 8));  
               *(ptr0 + 6) = v0;  
               if(*(ptr0 + 6) == 0 || (unsigned int)(*(ptr0 + 6) >= *(ptr0 + 9)) || *(ptr0 + 6) < *(ptr0 + 8)) {  
                   break;  
               }  
               else {  
                   **(unsigned int*)(ptr0 + 6) = 0;  
                   if(*(ptr0 + 6) - *(ptr0 + 8) > 1) {  
                       if((int)*(char*)((char*)*(unsigned int*)(ptr0 + 8) + 1) != '=') {  
                       loc_50001098:  
                           *(ptr0 + 3) = *(ptr0 + 10);  
                       }  
                       else if((int)**(unsigned int*)(*(unsigned int*)(ptr0 + 12) + 3) == (int)**(unsigned int*)(ptr0 + 8)) {  
                           *(ptr0 + 3) = 1;  // +3 = p  
                       }  
                       else if((int)**(unsigned int*)(*(unsigned int*)(ptr0 + 12) + 6) != (int)**(unsigned int*)(ptr0 + 8)) {  
                           goto loc_50001098;  
                       }  
                       else {  
                           *(ptr0 + 3) = 2;  // +6 = q  
                       }  
                       *(ptr0 + 2) = *(ptr0 + 3) * 12 + *(ptr0 + 12);  // (6 - 3)*4 = 12 ~> pointer to write number  
                       __f8(*(ptr0 + 6) - *(ptr0 + 8), *(ptr0 + 8), *(ptr0 + 2));  
                       *(int*)((*(ptr0 + 4) + *(ptr0 + 10)) * 4 + (int)*(unsigned int*)(ptr0 + 11)) = *(ptr0 + 3);  
                       *(ptr0 + 4) = *(ptr0 + 4) + 1;  
                   }  
                   *(ptr0 + 8) = *(ptr0 + 6) + 1;  
               }  
           }  
           if(*(ptr0 + 8) - *(ptr0 + 7) < *(ptr0 + 13) && *(ptr0 + 4) < *(ptr0 + 5)) {  
               if((int)*(char*)((char*)*(unsigned int*)(ptr0 + 8) + 1) != '=') {  
               loc_500013BF:  
                   *(ptr0 + 3) = *(ptr0 + 10);  
               }  
               else if((int)**(unsigned int*)(*(unsigned int*)(ptr0 + 12) + 3) == (int)**(unsigned int*)(ptr0 + 8)) {  
                   *(ptr0 + 3) = 1;  
               }  
               else if((int)**(unsigned int*)(*(unsigned int*)(ptr0 + 12) + 6) != (int)**(unsigned int*)(ptr0 + 8)) {  
                   goto loc_500013BF;  
               }  
               else {  
                   *(ptr0 + 3) = 2;  
               }  
               *(ptr0 + 1) = *(ptr0 + 3) * 12 + *(ptr0 + 12);  
               __f8(*(ptr0 + 7) + *(ptr0 + 13) - *(ptr0 + 8), *(ptr0 + 8), *(ptr0 + 1));  
               *(int*)((*(ptr0 + 4) + *(ptr0 + 10)) * 4 + (int)*(unsigned int*)(ptr0 + 11)) = *(ptr0 + 3);  
               *(ptr0 + 4) = *(ptr0 + 4) + 1;  
           }  
           *(ptr0 + 15) = *(ptr0 + 4);  
       }  
   }

   int result = *(ptr0 + 15);  
   __g0 = ptr0 + &gvar_10;  
   return result;  
}  
```

This function looks complicated at the first glance, but let's focus on the
most impoortant parts.  
At the beginning we have an important assignment: `*(ptr0 + 12) = param2`.
`param2` is a pointer to  
the object that `p_and_q__f7` returns. Let's move on:  
```c  
if((int)*(char*)((char*)*(unsigned int*)(ptr0 + 8) + 1) != '=') {  
loc_50001098:  
   *(ptr0 + 3) = *(ptr0 + 10);  
}  
else if((int)**(unsigned int*)(*(unsigned int*)(ptr0 + 12) + 3) ==
(int)**(unsigned int*)(ptr0 + 8)) {  
   *(ptr0 + 3) = 1;  // +3 = p  
}  
else if((int)**(unsigned int*)(*(unsigned int*)(ptr0 + 12) + 6) !=
(int)**(unsigned int*)(ptr0 + 8)) {  
   goto loc_50001098;  
}  
else {  
   *(ptr0 + 3) = 2;  // +6 = q  
}  
*(ptr0 + 2) = *(ptr0 + 3) * 12 + *(ptr0 + 12);  // (6 - 3)*4 = 12 ~> pointer to write number  
__f8(*(ptr0 + 6) - *(ptr0 + 8), *(ptr0 + 8), *(ptr0 + 2));  
```

`ptr0 + 8` points to the input string. The first `if` checks if `inpt[1] !=
'='`. If this is true,  
`ptr0 + 3` gets assigned the string `*(ptr0 + 10)`, which is `*(ptr0 + 8 +
2)`, which is `inp[2:]`.  
The second `else if` checks the value of `(ptr0 + 12) + 3)` is equal to `(ptr0
+ 8)` which is  
`inp[0]`. `ptr0 + 12` points to the output of `p_and_q__f7` which is
initialized to  
`*(*(unsigned int*)(ptr0 + 3) + 3) = "p";` That is, this if checks if `inp[0]
== 'p'`. If so, it  
assigns `*(ptr0 + 3) = 1`. Then program makes another check but this time with
`(ptr0 + 12) + 6)`  
which is the assignment `*(*(unsigned int*)(ptr0 + 3) + 6) = "q";` in
`p_and_q__f7`. That is, it  
checks if `inp[0] == 'q'` and if so, it assigns `*(ptr0 + 3) = 2;`. Finally it
makes an important  
assignment: `*(ptr0 + 2) = *(ptr0 + 3) * 12 + *(ptr0 + 12);`, which can have
**1** of the **2**  
possible values:  
```  
if inp[0] == 'p':  
   *(ptr0 + 3)*12 + *(ptr0 + 8 + 4) = 1*12 + p_and_q_obj = p_and_q_obj->p_val (+3 * 4 + 4 = +16)

if inp[0] == 'q'  
   *(ptr0 + 3)*12 + *(ptr0 + 8 + 4) = 2*12 + p_and_q_obj = p_and_q_obj->q_val (+6 * 4 + 4 = +28)  
```

Now let's go main (`__f22`) see the paramters of `check_pair`  
```c  
p_and_q__f7(*(glo + 0x116));  
/* ... */

int chk_res = CHECK_PAIR__f3(*(*(unsigned int*)(glo + 0x116) + 7),  
                            *(*(unsigned int*)(glo + 0x116) + 4));  
```

For some reason, in ReWasm, parameters appear in the reverse order:  
```c  
var_124 = load<i32>(var_92 + 1112);  
var_125 = load<i32>(var_124 + 16);

var_126 = load<i32>(var_92 + 1112);  
var_127 = load<i32>(var_126 + 28);

var_128 = func_3(var_125, var_127);  
````

The first parameter is `p_and_q_obj->p_val` (offset **+4** or **16**) and the
second parameter is  
`p_and_q_obj->q_val` (offset **+7** or **28**). That is, we need to pass **2**
distinct pairs to  
the program: `p=22229` and `q=227081`. Let's try it out:  
```  
ispo@ispo-glaptop2:~/ctf/0ctf_2020/W$ ./wasm3 ww  
Secret: ?  
eNj0y_weba5SemB1Y.lstrip("web")!  
Loading...  
Go Go Go!!  
aoshine~ What's up?  
1. add pair  
2. dump pair  
3. check pair  
4. exit  
1  
input new pair:  
p=22229  
1. add pair  
2. dump pair  
3. check pair  
4. exit  
1  
input new pair:  
q=227081  
1. add pair  
2. dump pair  
3. check pair  
4. exit  
2  
p=22229  
q=227081

1. add pair  
2. dump pair  
3. check pair  
4. exit  
3  
flag is: flag{secret+4986828}  
1. add pair  
2. dump pair  
3. check pair  
4. exit  
4  
```

Anw, the flag was: `flag{eNj0y_weba5SemB1Y.lstrip("web")!+4986828}`  
___  

Original writeup (https://github.com/ispoleet/ctf-
writeups/tree/master/0ctf_quals_2020/W).