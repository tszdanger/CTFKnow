Decompiled:

```C  
#include "out.h"

int _init(EVP_PKEY_CTX *ctx)

{  
 int iVar1;  
  
 iVar1 = __gmon_start__();  
 return iVar1;  
}

void FUN_00101020(void)

{  
                   // WARNING: Treating indirect jump as call  
 (*(code *)(undefined *)0x0)();  
 return;  
}

void FUN_00101050(void)

{  
 __cxa_finalize();  
 return;  
}

void __stack_chk_fail(void)

{  
                   // WARNING: Subroutine does not return  
 __stack_chk_fail();  
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

int putc(int __c,FILE *__stream)

{  
 int iVar1;  
  
 iVar1 = putc(__c,__stream);  
 return iVar1;  
}

void processEntry _start(undefined8 param_1,undefined8 param_2)

{  
 undefined auStack_8 [8];  
  
 __libc_start_main(main,param_2,&stack0x00000008,0,0,param_1,auStack_8);  
 do {  
                   // WARNING: Do nothing block with infinite loop  
 } while( true );  
}

// WARNING: Removing unreachable block (ram,0x001010c3)  
// WARNING: Removing unreachable block (ram,0x001010cf)

void deregister_tm_clones(void)

{  
 return;  
}

// WARNING: Removing unreachable block (ram,0x00101104)  
// WARNING: Removing unreachable block (ram,0x00101110)

void register_tm_clones(void)

{  
 return;  
}

void __do_global_dtors_aux(void)

{  
 if (completed_0 != '\0') {  
   return;  
 }  
 FUN_00101050(__dso_handle);  
 deregister_tm_clones();  
 completed_0 = 1;  
 return;  
}

void frame_dummy(void)

{  
 register_tm_clones();  
 return;  
}

long super_optimized_calculation(int param_1)

{  
 long lVar1;  
 long lVar2;  
  
 if (param_1 == 0) {  
   lVar1 = 0;  
 }  
 else if (param_1 == 1) {  
   lVar1 = 1;  
 }  
 else {  
   lVar2 = super_optimized_calculation(param_1 + -1);  
   lVar1 = super_optimized_calculation(param_1 + -2);  
   lVar1 = lVar1 + lVar2;  
 }  
 return lVar1;  
}

undefined8 main(void)

{  
 ulong uVar1;  
 long in_FS_OFFSET;  
 uint local_84;  
 uint local_78 [26];  
 long local_10;  
  
 local_10 = *(long *)(in_FS_OFFSET + 0x28);  
 local_78[0] = 0x8bf7;  
 local_78[1] = 0x8f;  
 local_78[2] = 0x425;  
 local_78[3] = 0x36d;  
 local_78[4] = 0x1c1928b;  
 local_78[5] = 0xe5;  
 local_78[6] = 0x70;  
 local_78[7] = 0x151;  
 local_78[8] = 0x425;  
 local_78[9] = 0x2f;  
 local_78[10] = 0x739f;  
 local_78[11] = 0x91;  
 local_78[12] = 0x7f;  
 local_78[13] = 0x42517;  
 local_78[14] = 0x7f;  
 local_78[15] = 0x161;  
 local_78[16] = 0xc1;  
 local_78[17] = 0xbf;  
 local_78[18] = 0x151;  
 local_78[19] = 0x425;  
 local_78[20] = 0xc1;  
 local_78[21] = 0x161;  
 local_78[22] = 0x10d;  
 local_78[23] = 0x1e7;  
 local_78[24] = 0xf5;  
 uVar1 = super_optimized_calculation(0x5a);  
 for (local_84 = 0; local_84 < 0x19; local_84 = local_84 + 1) {  
   putc((int)(uVar1 % (ulong)local_78[(int)local_84]),stdout);  
 }  
 putc(10,stdout);  
 if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
                   // WARNING: Subroutine does not return  
   __stack_chk_fail();  
 }  
 return 0;  
}

void _fini(void)

{  
 return;  
}

```

The saved bytes in local_78 form the bytestring:  
  
```  
0x8bf70x8f0x4250x36d0x1c1928b0xe50x700x1510x4250x2f0x739f0x910x7f0x425170x7f0x1610xc10xbf0x1510x4250xc10x1610x10d0x1e70xf5  
```

The core of the problem is  
```  
uVar1 = super_optimized_calculation(0x5a);  
 for (local_84 = 0; local_84 < 0x19; local_84 = local_84 + 1) {  
   putc((int)(uVar1 % (ulong)local_78[(int)local_84]),stdout);  
 }  
```  
The hex value '0x5a' (90: int)

The super optimized calculation:  
```  
long super_optimized_calculation(int param_1)

{  
 long lVar1;  
 long lVar2;  
  
 if (param_1 == 0) {  
   lVar1 = 0;  
 }  
 else if (param_1 == 1) {  
   lVar1 = 1;  
 }  
 else {  
   lVar2 = super_optimized_calculation(param_1 + -1);  
   lVar1 = super_optimized_calculation(param_1 + -2);  
   lVar1 = lVar1 + lVar2;  
 }  
 return lVar1;  
}  
```  
We can write the same inefficient thing in python  
```  
def soc(a):  
   if a == 0:  
       return 0  
   elif a == 1:  
       return 1  
   else:  
       x = soc(a-1)  
       y = soc(a-2)  
       return x+y  
```  
Since this will take ages to compute we can optimize this with a cache:  
```  
cache = [0, 1, soc(2), soc(3), soc(4)]  
def soc_opt(a):  
   if a < len(cache):  
       return cache[a]  
   else:  
       x = soc_opt(a-1)  
       y = soc_opt(a-2)  
       cache.append(x+y)  
       return cache[a]  
```  
We can check that it works by comparing the results of a manageable initial
value:  
```  
>>>print(soc(12))  
144  
>>>print(soc_opt(12))  
144  
```  
The desired initial value is 90,  which computes to:  
```  
>>>print(soc_opt(90))  
2880067194370816120  
```

When combining the bytestring with the optimized computation result  
```  
n = soc_opt(90)

b =
'0x8bf70x8f0x4250x36d0x1c1928b0xe50x700x1510x4250x2f0x739f0x910x7f0x425170x7f0x1610xc10xbf0x1510x4250xc10x1610x10d0x1e70xf5'  
flag = ''  
for x in b.split('0x'):  
   if x:  
       m = n % int(x, 16)  
       flag = f"{flag}{chr(m)}"  
print(flag)  
```  
We get the flag:  
```  
bctf{what's_memoization?}  
```