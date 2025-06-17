# Membership

# Vulnerabilities

* UAF in the `change_subscription` function, i.e. one can write to a `free`'d chunk.

# Protections

* PIE  
* Canary  
* Full RELRO

# Problems

* No `show` or similar sort of functions, so we can't get a leak easily.  
* Size of the chunk will be constant `0x50`, hence chunk size is not controllable.

# Exploitation

* Usually, in a scenario like this, we will go for the overlapping chunks. Provided LIBC is 2.31, hence `tcache` is enabled.

* Allocate 13 chunks.  
* Overwrite the LSB of a chunk to make FD point to another location on the heap, suitable for the fake chunk structure.  
* Now, store a fake chunk at that address, size being `0x421`.  
* Free the chunk 2, this chunk 2 was the fake chunk with size `0x421` hence it went into the unsorted bin.  
* We then overwrite the chunk 2 size again with the `0x421` and the LSB with the `0x16a0` such that the FD would point to the `_IO_2_1_stdout`.  
* Then, delete the chunk 3, 5, 1 and 4 for restoring the overlapping chunks.  
* Now, we again overwrite the LSB of the chunk 4's FD such that it will point to the fake chunk having it's FD pointing to the `_IO_2_1_stdout_`.  
* Retrieve the `_IO_2_1_stdout_` from the bin, overwrite it's structure to get a leak from the functions printing to the `_IO_2_1_stdout_`.  
* Get the LIBC address.  
* Perform tcache poisoning to overwrite the `__free_hook` with the `system`.

Original writeup
(https://github.com/D4mianWayne/PwnLand/blob/master/CTFs/SecurinetsCTF2021/membership/README.md).