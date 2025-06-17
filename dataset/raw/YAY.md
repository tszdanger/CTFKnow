# YAY! (988 pts)  
This challenge is another PE (32-bit this time, so no hex-rays in my IDA
Home). The task's description was:

> unpackme if you can !

which was a bit misleading as we'll see later. The binary had some "weird"
anti-debugging tricks which were for the most by ScyllaHide on x64dbg for me.
The first anti-debugger trick I encoutered was:  
```  
push    0  
push    0  
push    ThreadHideFromDebugger  
push    0FFFFFFFEh  
call    esi ; NtSetInformationThread  
push    4  
push    4  
push    ThreadHideFromDebugger  
push    0FFFFFFFEh  
call    esi ; NtSetInformationThread  
```  
which basically shuts down all debugging features of the process who calls
this function (if not hooked by ScyllaHide :þ). Then there was a quite huge
function in 0x4057B0 that seemed to scrap syscalls numbers from NTDLL, but I
didn't spend time to identify what syscalls.

Then another anti-debug function that did "WinVerifyTrust" calls to check some
DLL integrity, calling scrapped syscall from previous function and putting
vectored exception handler after that. For some reason, the function failed,
but I just forced EIP to bypass the check after, so I could trigger the useful
part of the binary.

Once the antidebugs bypassed, the binary connects to a server to fetch a
string, which is actually:  
```  
0,1,7,13,9,0,8,4,1,0,10,1,0,11,25,12,2,1,14,2,1,1,1,5,10,16,18,17,0,4,1,0,10,1,0,11,53,19,2,20,3,10,2,3,11,48,21,6,1,1,1,5,32,22,6  
```  
This string is then splitted by "," character and each int is stored in array.
This array is just bytecode for a custom VM, which contains 24 handlers. After
some reversing, I was able to decode this bytecode and got this:  
```  
0,1      // weird init  
7        // print welcome  
13       // input flag  
9,0      // mov r0, flag_size  
8        // print flag, srand(0x10c9) and creates an array of (rand() % 7) + 1  
4,1,0    // mov r1, 0  
10,1,0   // cmp r1, r0  
11,25    //    jz @26  
 12,2,1 //    mov r2, flag[r1]  
 14,2   //    push r2  
 1,1,1  //    add r1, 1  
 5,10   //    jmp @10  
16       // crypt_input_buf  
18       // put_serial_vec  
17,0     // mov r0, serial_len  
4,1,0    // mov r1, 0  
10,1,0   // cmp r1, r0  
 11,53  //   jz @53  
 19,2   //   mov r2, enc_input  
 20,3   //   mov r3, input  
 10,2,3 //   cmp r2, r3  
 11,48  //   jz 48  
 21,6   // print badboy  
 1,1,1  // add r1, 1  
5,32     // jmp @32  
22,6     // print goodboy  
```  
The interesting handler is "crypt_input_buf" handler, which looks like this:  
```  
.text:004022BD                 cmp     [esi+VMContext.flagbuffer.sz1], 0 ;
jumptable 00402151 case 16  
.text:004022C1                 mov     [ebp+i], 0  
.text:004022CB                 jbe     def_402151      ; jumptable 00402151
default case  
.text:004022D1                 mov     edi, [esi+VMContext.input_vec.end]  
.text:004022D4                 mov     edx, [esi+VMContext.randvec.end]  
.text:004022D7                 nop     word ptr [eax+eax+00000000h]  
.text:004022E0  
.text:004022E0 loc_4022E0:                             ; CODE XREF:
DecodeInstruction+30E↓j  
.text:004022E0                 mov     edi, [edi-4]  
.text:004022E3                 mov     ecx, 8  
.text:004022E8                 mov     edx, [edx-4]  
.text:004022EB                 mov     eax, edi  
.text:004022ED                 sub     ecx, edx  
.text:004022EF                 sar     eax, cl  
.text:004022F1                 mov     ecx, edx  
.text:004022F3                 shl     edi, cl  
.text:004022F5                 or      eax, edi  
.text:004022F7                 movzx   ecx, al  
.text:004022FA                 mov     eax, [esi+VMContext.enc_input.end]  
.text:004022FD                 mov     [ebp+var_C4], ecx  
.text:00402303                 cmp     eax,
[esi+VMContext.enc_input.alloc_end]  
.text:00402306                 jz      short loc_402310  
.text:00402308                 mov     [eax], ecx  
.text:0040230A                 add     [esi+VMContext.enc_input.end], 4  
.text:0040230E                 jmp     short loc_402320  
.text:00402310 ;
---------------------------------------------------------------------------  
.text:00402310  
.text:00402310 loc_402310:                             ; CODE XREF:
DecodeInstruction+2D6↑j  
.text:00402310                 lea     ecx, [ebp+var_C4]  
.text:00402316                 push    ecx             ; int  
.text:00402317                 push    eax             ; Src  
.text:00402318                 lea     ecx, [esi+VMContext.enc_input]  
.text:0040231B                 call    vector_append  
```

It's basically a ROL unoptimized by the compiler, with the random array built
by the "8" opcode. Then, the "encrypted" username is compared to some buffer
defined at the beginning of the function:  
```  
mov     dword ptr [ebp+var_44], 2F16F25Fh  
mov     dword ptr [ebp+var_44+4], 37CAE6AFh  
mov     dword ptr [ebp+var_44+8], 0D8D8B037h  
mov     dword ptr [ebp+var_44+0Ch], 0B1C10EFAh  
mov     dword ptr [ebp+var_44+10h], 0D56C1AF5h  
mov     dword ptr [ebp+var_44+14h], 46AFBEADh  
mov     dword ptr [ebp+var_44+18h], 0E67DC2B9h  
mov     dword ptr [ebp+var_44+1Ch], 0C63ABDE4h  
mov     dword ptr [ebp+var_44+20h], 59EB67CAh  
mov     dword ptr [ebp+var_44+24h], 0DE1DB047h  
mov     dword ptr [ebp+var_44+28h], 3BDAFAC9h  
mov     dword ptr [ebp+var_44+2Ch], 0C62C76F6h  
mov     word ptr [ebp+var_44+30h], 0CCh ; 'Ì'  
```

Given this, we can write a decode script to get the flag:  
```python  
import ctypes

crt = ctypes.cdll.msvcrt

crt.srand(0x10c9)  
encodedflag = bytes.fromhex("5F F2 16 2F AF E6 CA 37 37 B0 D8 D8 FA 0E C1 B1
F5 1A 6C D5 AD BE AF 46 B9 C2 7D E6 E4 BD 3A C6 CA 67 EB 59 47 B0 1D DE C9 FA
DA 3B F6 76 2C C6 CC".replace(" ", ""))  
arr = [(crt.rand() % 7) + 1 for i in range(len(encodedflag))]  
decarr = arr[::-1]  
lol = []  
for i in range(len(arr)):  
   ret = ((encodedflag[i] << (8 - decarr[i])) | (encodedflag[i] >> decarr[i])) & 0xff  
   lol.append(ret)  
print(bytes(lol[::-1]))  
```  
Which gives `flag{vm_rotate_vectors_and__much_cpp_classes_yay}`.

Original writeup
(https://github.com/ret2school/ctf/blob/master/2021/securinets/rev/README.md).