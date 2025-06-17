# Treecache: Alyx  
> We remastered this old classic. There is now less cheese and more trees.  
>  
> Connect at `nc pwn.hsctf.com 5008`.

> > Hint: It would be a downright shame if I accidentally ran free(NULL). Good
> thing root can't ever become NULL!

## Solution  
### Outline  
1. Completely clearing a non-empty tree sets `root` equal to `temp_null`. Freeing `temp_null` as well creates a use-after-free vulnerability.  
2. The `free()` method places a pointer to tcache where the `description` pointer for a donation would go, letting us write directly into tcache with the use-after-free.  
3. We leaked the libc address by freeing a chunk onto the smallbin freelist and then using `malloc` first-fit to put the address of the leak in the `amount` parameter of a donation.  
4. Writing directly into tcache allows us arbitrary write, which lets us write `system` to `__free_hook` to gain a shell.

### Vulnerability  
We present a long, probably unintended, but truly *epic* solution to this
challenge. It will again be roughly orthogonal to the previous two Treecache
challenges. As always, we begin with a `checksec`.  
```  
$ checksec trees_alyx  
[*] '/trees_alyx'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```  
This is even sadder than the previous Treecache challenges because we're now
using full RELRO. Anyways, stack exploits are unlikely given all of the
various protections, so it's time to heap.

One of the confusing things about the hint is that it's not referring to `0x0`
but rather to the `temp_null` variable used in the deletion method of the
program.  
```c  
		Node* child;  
		if (node->left != NULL) {  
			child = node->left;  
		} else if (node->right != NULL) {  
			child = node->right;  
		} else {  
			temp_null->parent = node;  
			node->left = temp_null;  
			child = temp_null;  
		}  
```  
The first vulnerability is that when the tree is cleared, `root` is not set to
`0x0`. Rather, when deleting the `root` node, the program goes through the
entire deletion algorithm, setting a child equal to `temp_null` and promoting
it. This means that `temp_null` will be equal to `root`.

While sketchy, this does not look immediately exploitable. However, the hint
mentions *freeing* `temp_null`, which after some pushing to bypass some checks
we can do. Note the `id` of `temp_null` is read as `0`, so we can just revoke
donation `0`. There is a small hiccup in that we have to pass the following
check.  
```c  
void repair_dblack(Node* node) {  
	if (node->color == BLACK) {  
		Node* p = node->parent;  
		if (p == NULL) {  
			return;  
		}  
		if (p->left == node) {  
			assert(p->right != NULL); // all pointers in temp_null are null now  
		...  
```  
This can be bypassed by just allocating `temp_null` a right child and then
freeing `temp_null` followed by freeing the right child to clear the tree
again.

This presents a second more serious "use-after-free" vulnerability. In
particular, we just managed to free `temp_null`, but `root` is set to
`temp_null` in an empty tree, so we have access to it, potentially even the
ability to read and write. With some more pushing, this vulnerability turns
out to be enough.

### Leaking Libc  
This is done in the same way as [Treecache 2](/Treecache_2/Treecache2.md).
Once again, because we want a libc pointer, we go ahead and fill tcache with
seven chunks of some size and then free another onto the smallbin freelist,
which will place libc pointers inside the chunk. Then we use `malloc` first-
fit to eventually receive back this eigth chunk and read the stored libc
pointer.

In particular, we have to leak from the `print_donation` function here.  
```c  
	printf("%lu trees\n", a->amount);  
	printf("Donator: %s\n", a->name);  
	printf("Description: %s\n", a->description);  
```  
It is easiest to read directly from the `amount` and `name` parameters.
Reading from `description` is hard because our strings get null-terminated by
the program, which will block our leak. So the outline is to make eight huge
`description` blocks (say, `0x100`) and then revoke all of those donations,
putting the eigth large chunk on the smallbin freelist. Then if we
continuously make new donations in the heap, eventually `malloc` will split
the large smallbin chunk, putting libc pointers in random places of our
donations. With luck the pointers will show up in `amount` or `name`, so we'll
be able to leak.

### Exploiting the Vulnerability  
The key to the exploit is comparing what freed chunks look like in tcache to
what the donation structure looks like. When freeing a chunk onto tcache in
libc 2.29, it looks roughly like the following.  
```  
0x0000000000000000      0x0000000000000111 <-- size header; prev_in_use set  
0x[next on tcache]      0x[tcache pointer] <-- tcache's metadata  
0xdeadbeefdeadbeef      0xdeadbeefdeadbeef <-- old data  
...  
```  
What is interesting here is that tcache will write a pointer to itself (at the
top of the heap) inside of a freed chunk. Additionally, the donation struct
looks like the following.  
```  
0x0000000000000000      0x0000000000000041 <-- size header  
0x[donated amount]      0x[ desc. pointer] <-- description!  
0x[ name pointer ]      0x[a tree pointer]  
0x[a tree pointer]      0x[a tree pointer]  
0x[  id  ][ color]      ...  
```  
Now we bring in the fact that we have a use-after-free vulnerability. Notice
that at our current state after setting `root` to `temp_null`, freeing
`temp_null`, and then setting `root` back to `temp_null`, we have convinced
the program that the freed `temp_null` chunk is currently on the tree.

However, comparing the structure of a freed chunk to the donation chunk, we
notice that tcache wrote `0x[next on tcache]` into `0x[donated amount]`
(helper for leaks but otherwise irrelevant) and `0x[tcache pointer]` into `0x[
desc. pointer]`. So right now, `temp_null->description` points to the top of
the tcache chunk. As a brief review, the tcache chunk looks like the following
in libc 2.29.  
```  
0x0000000000000000      0x0000000000000251 <-- tcache has size 0x250  
0x0101010101010101      0x0101010101010101 <-- length of each freelist  
0x0101010101010101      0x0101010101010101     here all freelists are 1 long  
0x0101010102010101      0x0101010101010101  
0x0101010101010101      0x0101010101010101  
0x[top 0x20 chunk]      0x[top 0x30 chunk]  
0x[top 0x40 chunk]      0x[top 0x50 chunk]  
...  
```  
If we edit `temp_null`, it will free the current `temp_null->description` and
then `malloc` in another one; here is that part of the `edit_donation`
function.  
```c  
	free(a->description);  
	desc = malloc(len_desc);  
	puts("Enter new description.");  
	read_str(desc, len_desc);  
	a->description = desc;  
```  
In this case, this will free the tcache chunk, and put *tcache* onto the
tcache freelist. Then if we ask for a chunk of size `0x250` for the length of
our description, then `malloc` will generously give us tcache back to write in
our description. So editing `temp_null`'s description will let us write
directly into tcache metadata.

With our newfound awesome power of writing directly into tcache, we can fool
`malloc` into doing pretty much whatever we want. Placing `0x01` for all of
the freelist lengths ensures that `malloc` thinks that there's a chunk waiting
for it in each freelist. Then if we write in `0x7f00deadbeef` into tops of all
the tcache freelists, then `malloc` will happily give us `0x7f00deadbeef`
whenever we ask for a chunk. For clarity, tcache now looks like the following.  
```  
0x0000000000000000      0x0000000000000251 <-- tcache has size 0x250  
0x0101010101010101      0x0101010101010101 <-- length of each freelist  
0x0101010101010101      0x0101010101010101     here all freelists are 1 long  
0x0101010102010101      0x0101010101010101  
0x0101010101010101      0x0101010101010101  
0x00007f00deadbeef      0x00007f00deadbeef <-- top of freelists is
0x7f00deadbeef  
0x00007f00deadbeef      0x00007f00deadbeef  
...  
```  
This gives us the most arbitrary of writes.

### Finishing Up  
From here the exploit finishes normally. Write `/bin/sh` into some freeable
memory, and then use the above arbitrary write (courtesy of tcache
destruction) to write `system` into `__free_hook`; recall we've leaked libc.
Then calling `free` on the `/bin/sh` memory will call `free("/bin/sh")`, which
is now `system`, so we have a shell and so have the flag.

The full exploit can be found [here](/Treecache_Alyx/treeforce.py).

Original writeup
(https://github.com/AMACB/HSCTF-2020-writeups/blob/master/Treecache_Alyx/Treecache_Alyx.md).