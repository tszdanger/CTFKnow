# Karte (6 solves)

Author: @moratorium08, @smallkirby\_  
Estimated difficulty: Easy

## Abstraction  
The goal of this chal is to ovewrite `authorized` in BSS.  
You can alloc, extend, change the part of chunks(`id`), free, and read the
information(`id`,`size`) of allocated chunks. The main information is
remembered by following structure.  
```c  
typedef struct {  
   unsigned long long size;  
   unsigned long long id;  
   unsigned long long data[];  
}__attribute__((__packed__)) Vec;  
```  
  
Note that `id` is a second member. This feature would be usefull when you have
to overwrite only `bk` of a chunk.  
And you have to know that this binary uses glibc-2.31. Since glibc-2.28, you
can't simply double free tcache and duplicate it to make them point to
arbitrary address.

## Bug  
This program has UAF(write) of `id` member. Therefore, if a chunk is freed and
connected to smallbin, you can overwrite `bk` of this chunk using this UAF.  

## Rough Overview of Exploit  
The first part is heap address leak and libc address leak.  
You can read the buffer after free if you know the id (\*(ptr + 8)).  
The buffer at fastbin can be read, since id will not be overwritten  
after free.  
After you get the heap address, you can also get libc address.

The second part is to overwrite `authorized` in BSS.  
We used `tcache_stashing` for this.  
  
The main concept of this technique is  
- overwrite `bk` of smallbin into arbitrary address using UAF of id member.    
- when malloc a chunk, the rest of smallbins are stashed into tcache.    
```c  
#if USE_TCACHE  
	  /* While we're here, if we see other chunks of the same size,  
	     stash them in the tcache.  */  
	  size_t tc_idx = csize2tidx (nb);  
	  if (tcache && tc_idx < mp_.tcache_bins)  
	    {  
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */  
	      while (tcache->counts[tc_idx] < mp_.tcache_count  
		     && (tc_victim = last (bin)) != bin)  
		{  
		  if (tc_victim != 0)  
		    {  
		      bck = tc_victim->bk;  
		      set_inuse_bit_at_offset (tc_victim, nb);  
		      if (av != &main_arena)  
			set_non_main_arena (tc_victim);  
		      bin->bk = bck;  
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);  
	            }  
		}  
	    }  
#endif  
```  

`bck->fd = bin` is the target of this attack, which would overwrite
`authorized`.  
  

So let me summarize the step to pwn.  
- forge fake fd on `name`, which is needed to avoid error of smallbin linked list.    
- leak heapbase    
- leak libcbase, which is needed when stashing because the last chunk in smallbin must point to the valid address in main_arena.    
- overwrite `bk` of smallbin into `name`.    
- stashe two smallbins into tcaches.    
- in this stashing, `fd` of the smallbin adjacent to `authorized` is overwritten to the address in main_arena.   
- now `authorized` is not zero, so you can choose `5` of `menu` and get a shell.  

[poc.py](https://github.com/tsg-
ut/tsgctf2020/blob/master/pwn/karte/solver/solve.py)

Original writeup (https://github.com/tsg-
ut/tsgctf2020/blob/master/pwn/karte/writeup.md).