# kmemo

## Goal

This is the second challenge out of three in the fullchain challenge series.
In  
the
[umemo](https://github.com/mephi42/ctf/tree/master/2023.09.16-SECCON_CTF_2023_Quals/umemo)
challenge we obtained a shell, now it's time to get root.

The author has provided the source code for the vulnerable kernel module.

## Debugging

* The kernel source code can be conveniently browsed in [Elixir](  
https://elixir.bootlin.com/linux/v6.2.8/source/).  
* `vmlinux` can be extracted from `bzImage` with `binwalk -e`.  
* kallsyms can be extracted and imported into a decompiler with [ida-kallsyms](  
https://github.com/mephi42/ida-kallsyms).  
* Struct layouts and non-exported symbols unfortunately need to be reversed.  
 One can find the functions that use the interesting structs or symbols, and  
 correlate the decompiled code with the source code.  
* A debug version of vmlinux can be created with [dwarfexport](  
https://github.com/ALSchwalm/dwarfexport).  
* `s/kaslr/nokaslr/` in `ukqmemo/release/run.sh` in order to simplify the  
 debugging experience.  
* GDB can be attached to the VM using [gdbstub](  
https://wiki.qemu.org/Features/gdbstub).  
* Module can be located in memory by using an observation that it's the only  
 one and therefore `mod_tree.addr_min` [points to
it](https://github.com/mephi42/ctf/blob/master/2023.09.16-SECCON_CTF_2023_Quals/kmemo/gdbscript).  
* With that, one can set breakpoints in the kernel and in the module, and see  
 the respective symbols in backtraces.

## Vulnerability

In my local setup I had dmesg enabled and observed the following quite a lot
of  
times after the umemo app crashes:

```  
BUG: Bad page state in process memo  pfn:019b6  
page:(____ptrval____) refcount:-1 mapcount:0 mapping:0000000000000000
index:0x0 pfn:0x19b6  
```

So from the start I knew that the problem was somewhere in the `struct page`  
reference counting. The only place that deals with `struct page` is:

```  
static vm_fault_t mmap_fault(struct vm_fault *vmf){  
       struct memo *memo = vmf->vma->vm_private_data;  
       if(!memo)  
               return VM_FAULT_OOM;

       char *data = get_memo_rw(memo, vmf->pgoff << PAGE_SHIFT);  
       if(!data)  
               return VM_FAULT_OOM;

       vmf->page = virt_to_page(data);

       return 0;  
}  
```

so I was immediately suspicious if a refcount increment was missing here.
After  
all, we give our `struct page` to the common code. So I set a breakpoint on  
`mmap_fault` and then a watchpoint on `vmf->page's` refcount.

Not only it dropped to 0 shortly after returning from `mmap_fault()` in  
[`do_cow_fault()`](  
https://elixir.bootlin.com/linux/v6.2.8/source/mm/memory.c#L4528), but it was  
also almost immediately reused by the vulnerable module:

```  
Old value = 0  
New value = 1  
0xffffffff811a8207 in get_page_from_freelist ()  
(gdb) bt  
#0  0xffffffff811a8207 in get_page_from_freelist ()  
#1  0xffffffff811a9a45 in __alloc_pages ()  
#2  0xffffffff811aa258 in get_zeroed_page ()  
#3  0xffffffffc0201093 in __pgoff_to_memopage (memo=0x0,
memo@entry=0xffff8880019b6240, pgoff=18446612682103736320,
modable=modable@entry=true,  
   new_page=new_page@entry=0x0) at
/data/yutaro/CTF/misc/Playground/kernel/modules/memo/memo.c:55  
```

So we have a use-after-free.

## kmemo page tables

As we already know from the umemo challenge, the module keeps the data in  
pages. How are they organized? Turns out they are indexed by a two-level page  
table structure:

```  
#define MEMOPAGE_TABLE_SHIFT (9)

struct memo_page_table {  
       void* entry[PAGE_SIZE/sizeof(void*)];  
};

struct memo {  
       struct memo_page_table *top;  
       uint32_t count;  
       struct mutex lock;  
};  
```

* The lowest 12 bits of an offset are ignored.  
* The next 9 bits are used for the second hierarchy level.  
* The next 9 bits are used for the first hierarchy level,  
* The other bits are ignored - this was the vulnerability for the umemo  
 challenge.

## Exploitation

The plan is to leverage the use-after-free for overlapping a data (second  
level) page with a page table (first level) page. This would give us the  
arbitrary read-write capability.

For the overlap, we need to keep three pages in mind:

* Attacker page. Use offset 0, because why not. After it's `mmap()`ped and  
 accessed, its reference counter will drop to 0 because of the bug.  
* Victim page. This will be allocated as a page table page when referencing an  
 offset with non-zero first level bits, e.g., `(1 << (PAGE_SHIFT +  
 MEMOPAGE_TABLE_SHIFT))`. It will overlap with the attacker page.  
* Data page. It will be initially allocated alongside the victim page and  
 referred to by it.

Having set that up, we can now read and write to the victim page using the  
`mmap()`ped attacker page. By reading the first 8 bytes we get the virtual  
address of the data page.

This address is generated in `__pgoff_to_memopage()` using  
[`get_zeroed_page()`](  
https://elixir.bootlin.com/linux/v6.2.8/source/mm/page_alloc.c#L5606), which  
in turn calls [`__get_free_pages()`](  
https://elixir.bootlin.com/linux/v6.2.8/source/mm/page_alloc.c#L5595) →  
[`page_address()`](  
https://elixir.bootlin.com/linux/v6.2.8/source/mm/highmem.c#L740) →  
[`lowmem_page_address()`](  
https://elixir.bootlin.com/linux/v6.2.8/source/include/linux/mm.h#L1864) →  
[`page_to_virt()`](  
https://elixir.bootlin.com/linux/v6.2.8/source/include/linux/mm.h#L115) →  
[`__va()`](  
https://elixir.bootlin.com/linux/v6.2.8/source/arch/x86/include/asm/page.h#L59  
). Phew, that was a lot. At the end `__va()` will add [`PAGE_OFFSET`](  
https://elixir.bootlin.com/linux/v6.2.8/source/arch/x86/include/asm/page_types.h#L30  
), which is an alias for [`page_offset_base`](  
https://elixir.bootlin.com/linux/v6.2.8/source/arch/x86/include/asm/page_64.h#L17  
), to the page's physical address. The latter is set by  
[`kernel_randomize_memory()`](  
https://elixir.bootlin.com/linux/v6.2.8/source/arch/x86/mm/kaslr.c#L43) with a  
huge granularity of a PUD (1G).

What are the practical consequences of this? By and-ing the leaked data page  
virtual address with `~(PUD_SIZE - 1)`, we get the value of
`page_offset_base`:  
a virtual address, at which all physical memory is mapped.

By writing the addresses of the form of `page_offset_base + X` to the first 8  
bytes of the attacker page, we can access physical address `X` by reading or  
writing to the device at offset we used when allocating the attacker page.

The next step is to locate vmlinux by scanning the physical memory. The
process  
can be sped up a bit by noticing that it's loaded at a physical address of at  
least [`CONFIG_PHYSICAL_START`](  
https://elixir.bootlin.com/linux/v6.2.8/source/arch/x86/Kconfig#L2129) on a  
[`CONFIG_PHYSICAL_ALIGN`](  
https://elixir.bootlin.com/linux/v6.2.8/source/arch/x86/Kconfig#L2227)  
boundary.

This will give us the virtual address of vmlinux in the directly mapped  
physical memory, but vmlinux is executed from a different mapping. Just for  
convenience, i.e., ease of cross-checking the addresses with backtraces in the  
debugger, find the address of this mapping by loading, e.g., `init_task.cred`  
from the directly mapped vmlinux and subtracting `init_cred` offset from it.

Finally, use the good old `current->cred = current->real_cred = &init_cred`  
(`current` can be found using `pcpu_base_addr`) to get root.

## Flag

`SECCON{d0n7_f0rg37_70_1ncr3m3n7_r3fc0un7}`  

Original writeup
(https://github.com/mephi42/ctf/tree/master/2023.09.16-SECCON_CTF_2023_Quals/kmemo).