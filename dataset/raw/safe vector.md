# safe vector

## TLDR  
* out of bound read/write  
* tcache poisoning 

## Challenge  
### Description  
Result of file command  
* Arch    : x86-64  
* Library : Dynamically linked  
* Symbol  : Not stripped

Result of checksec  
* RELRO  : Full RELRO  
* Canary : Disable  
* NX     : Enable  
* PIE    : Enable 

libc version: 2.31

In this challenge, original class "safe\_vector" is defined.  

```cpp  
...

template<typename T>  
class safe_vector: public std::vector<T> {  
public:  
 void wipe() {  
   std::vector<T>::resize(0);  
   std::vector<T>::shrink_to_fit();  
 }

 T& operator[](int index) {  
   int size = std::vector<T>::size();  
   if (size == 0) {  
     throw "index out of bounds";  
   }  
   return std::vector<T>::operator[](index % size);  
 }  
};  
...  
```

### Exploit  
"safe\_vector" is not "safe".  
If the index is negative, operator allows us to access out of bound value.  

The following information about vector's dynamic memory allocation will help
your exploit.  
(It could be wrong. If you notice, let me know.)  

| size of vector<uint32_t> | chunk size of vector<uint32_t> |  
| - | - |  
| 1 | 0x20 |  
| 2 | 0x20(reallocate) |  
| 2 < | 0x20(reallocate) |  
| 4 < | 0x30 |  
| 7 < | 0x50 |  
| 16 <  | 0x90 |  
| 32 <  | 0x110 |  
| 64 <  | 0x210 |  
| 128 <  | 0x410 |  
| 256 <  | 0x810 |  
| ... | ... |

I need to link chunk to unsorted bin in order to get the address of libc.  
I used tcache poisoning to overwrite \_\_free\_hook into system().  
My exploit is
[here](https://github.com/kam1tsur3/2021_CTF/blob/master/zer0pts/pwn/safe_vector/solve.py).

## Reference

twitter: @kam1tsur3  

Original writeup
(https://github.com/kam1tsur3/2021_CTF/blob/master/zer0pts/pwn/safe_vector/README.md).