# party

Points: 500 | Solves: 1 | Category: Reverse

## Understand the program

It can be seen that there is a structure named `Person` created in the
function `0x4014b0 test()` with size `0x28`, it seems to has 5 pointer
members. so we can use IDA to define a structure:

```  
00000000 Person          struc ; (sizeof=0x28, mappedto_16)  
00000000 u               dq ?                    ; offset  
00000008 d               dq ?                    ; offset  
00000010 l               dq ?                    ; offset  
00000018 r               dq ?                    ; offset  
00000020 ptr             dq ?                    ; offset  
00000028 Person          ends  
```

change some variables' type, and there seems to have some [doubly linked
list](https://en.wikipedia.org/wiki/Doubly_linked_list) operations.

A part of the function `0x4019a0 party()` is:

```c  
v4 = v2->d;  
do  
{  
   if ( v3->ptr < v4->ptr )  
       v4 = v3;  
   v3 = v3->d;  
}  
while ( v3 != v2 );  
v4->u->d = v4->d;  
v4->d->u = v4->u;  
for ( i = v4->r; i != v4; i = i->r )  
{  
   for ( j = i->d; j != i; j = j->d )  
   {  
       j->l->r = j->r;  
       j->r->l = j->l;  
       --j->ptr->ptr;  
   }  
}  
v7 = v4->r;  
```

The first glance at the code reminds me of the [dancing
links](https://en.wikipedia.org/wiki/Dancing_Links), which most people may
feel unfamiliar, but I have used it once to solve the Sudoku puzzles.

The dancing links implement the [Algorithm
X](https://en.wikipedia.org/wiki/Knuth%27s_Algorithm_X) to determine if there
is a solution to the [exact cover](https://en.wikipedia.org/wiki/Exact_cover)
problem, and that's what the function `0x4019a0 party()` does.

Now, we can recognize the function `0x4014b0 test()` as creator of dancing
links given matrix and column set. The full matrix is stored at
`[0x40132b-0x40141d]`, which has 538 rows. Each row contains 3 integers in
range `[0, 37)`, which represents the column number. And the function
`0x401310 test()` selects a certain rows of the full matrix such that all the
3 columns are included in the given column set.

Now let's look at the function `0x4011c0 ditto()`. Its functionality is to add
one element the input set if the element is not present in the set, and call
`0x401310 test()` to determine if the exact cover problem with these column
have solutions. If all  elements pass the the test, the function returns true.

In summary, this program read a set from input (elements in range `[0, 37)`),
and the set must satisfies following 3 conditions:

1. The order of the elements must satisfy that the return value of function `0x4010f0 hash()` is `0xf6bb10ed6`.  
2. This set **can** pass `0x4011c0 ditto()`.  
3. If a element is removed from the set, and a smaller one is added, it **can not** pass `0x4011c0 ditto()`.

## Determine the size and order of the set

First let's look at function `0x4010f0 hash()`.

```c  
signed __int64 __fastcall hash(__int64 a1)  
{  
 unsigned int v1; // eax  
 signed __int64 v2; // rcx MAPDST  
 __int64 v3; // r13  
 __int64 v4; // r14  
 signed __int64 v5; // rdx  
 int v6; // ebp  
 signed __int64 v7; // rbx  
 int v8; // er12  
 signed __int64 result; // rax  
 signed __int64 v10; // [rsp+8h] [rbp-50h]  
 signed __int64 v12; // [rsp+18h] [rbp-40h]  
 signed __int64 v13; // [rsp+20h] [rbp-38h]

 v1 = std::vector<int,std::allocator<int>>::size(a1);  
 if ( v1 <= 0 )  
   return 0LL;  
 v2 = v1;  
 v3 = v1;  
 v10 = 1LL;  
 v4 = 0LL;  
 v5 = 0LL;  
 v2 = v1;  
 do  
 {  
   v13 = v5;  
   v12 = v4 + 1;  
   v6 = 0;  
   if ( v4 + 1 < v2 )  
   {  
     v6 = 0;  
     v7 = v10;  
     do  
     {  
       v8 = *std::vector<int,std::allocator<int>>::operator[](a1, v4);  
       v6 += v8 > *std::vector<int,std::allocator<int>>::operator[](a1, v7++);  
     }  
     while ( v3 != v7 );  
   }  
   result = (v2 - v4) * v13 + v6;  
   ++v10;  
   ++v4;  
   v5 = result;  
 }  
 while ( v12 != v3 );  
 return result;  
}  
```

For the first step, the function does the same thing as:

```c++  
v1 = a1.size();  
result = 0;  
for (i = 0; i < v1; i++)  
{  
   v6 = 0;  
   for (j = i + 1; j < v1; j++)  
       v6 += a1[i] > a2[j];  
   result = (v1 - i) * result + v6;  
}  
return result;  
```

By dividing the value `0xf6bb10ed6` by 1, 2, 3, ..., etc., the array before
compression can be restored, which is `[10, 8, 3, 2, 5, 5, 6, 0, 1, 2, 2, 1,
0, 0]` with length 14. The elements in this array means, for example the first
element 10 indicate that there are totally 10 elements less than the first
element starting from the second. From this we are able to obtain the order of
the set `[10, 8, 3, 2, 7, 9, 12, 0, 4, 6, 11, 5, 1, 13]`, within several easy
steps.

Let's now come back to the exact cover problem. As all rows of the matrix have
3 elements, the size of the column set must be multiple of 3 in order to make
the exact cover problem have some solution. The remainder of the size divided
by 3 must be 2 preceding function `0x4011c0 ditto()`, which add the element to
input set. In addition, the size must less than 17 at `0x4010ab`. Thus we are
now sure that the size of the input set is 14.

## Find one solution by bruteforce

Next step is to find one set that satisfies the condition 2, though it may not
satisfies the condition 3.

First consider how to find a valid set with size 15 that can pass `0x401310
test()`. There are totally $\binom{37}{15} \approx 9 \times 10^9$ possible
sets, it's not too many. But checking if a set is valid needs to run DLX
algorithm, which is time consuming.

Notice that the size of valid set is 15, and all rows of the matrix have 3
elements, therefore the solution must consist of 5 rows. One combination with
no conflicting columns corresponding to one valid set, and there are at most
$\binom{538}{5} \approx 3 \times 10^{11}$ combinations. Not many, too
(actually only $2\times10^{10}$). So we can get all valid sets by enumerate
the combination of 538 rows, without running DLX algorithm.

But our goal is not just to find a *valid set*. Instead, we need to find a
*set core*, that can always produce a valid set by appending any other
elements in range `[0, 37)`. Suppose there is a list for each core, when one
element is removed from a valid set and a core is obtained, the victim is
added to the corresponding list of the core. When the size of that list is $37
- 14 = 23$, this core is capable of generating 23 valid sets. So now we have
reached a solution.

The bruteforce algorithm is done!

As for implementation details, bit operations are applied instead of set
operations. A 37 bits integer can represent either a set or the list of cores.
Moreover, we can use hash table to store the lists, and ignore hash collisions
(this means that the core still need to be checked). For the sake of
efficiency, the algorithm is implemented in C++.

The main code is listed here:

```c++  
typedef unsigned long long ll;  
const unsigned int P = 400000007u;  
unordered_map<ll, bool> occurred;  
ll h[P];

void work_on_a_valid_set(ll vset)  
{  
   for (ll tmp = vset; tmp;)  
   {  
       ll lowbit = tmp & -tmp;  
       ll core = vset - lowbit;  
       tmp -= lowbit;  
       if (((h[core % P] |= lowbit) | core) == (1ll << 37) - 1)  
       {  
           if (occurred[core])  
               continue;  
           occurred[core] = true;  
           print_bin(core);  
       }  
   }  
}

void product_all_valid_set()  
{  
   // ...  
}  
```

In order to validate the core set that may not satisfy condition 3, we can
reuse the given program with some instructions patched by `nop`.

There are plenty of feasible solutions, the algorithm don't have to run too
long to before reaching a solution. One of the solutions is `645q9f3ozytrac`.

## Find the final set by iteration

Now we have obtained a set satisfying condition 2, and further adjustment is
required in order to make it satisfy condition 3. Consider that when a set
does not satisfy condition 3, removal of any single element followed by the
addition of a smaller one will still result in satisfiction of condition 2.

Notice that this transform is one-way. Thus as we transform a set multiple
times, it will finally reach a limit rather than come back, and then we get
the set we need.

The above can be achieved by following code:

```python  
from pwn import *

STR = 'oidn1be8!kasgm2q5jwplz7rhvy094xfu6t3c'  
ORDER = [10, 8, 3, 2, 7, 9, 12, 0, 4, 6, 11, 5, 1, 13]

context.log_level = 'error'

def check_2(flag):  
   p = process(['./party_patched', flag])  
   data = p.recvall()  
   p.close()  
   return 'hitcon' in data

def check_3(flag):  
   p = process(['./party-0efe21e5fab4f979555c100a2f4242bd', flag])  
   data = p.recvall()  
   p.close()  
   if 'hitcon' in data:  
       print(data)

def str2set(str):  
   return [STR.find(c) for c in str]

def set2str(set):  
   tmp = ''  
   for j in range(37):  
       if j in set:  
           tmp += STR[j]  
   res = ''  
   for j in range(len(tmp)):  
       res += tmp[ORDER[j]]  
   return res

def transform(flag):  
   a = str2set(flag)  
   for i in range(37):  
       if i in a:  
           b = filter(lambda j: j != i, a)  
           for j in range(i):  
               if j not in a:  
                   flag = set2str(b + [j])  
                   if check_2(flag):  
                       return flag  
   return None

if __name__ == '__main__':  
   flag = '645q9f3ozytrac'  
   while True:  
       f = transform(flag)  
       print(flag, f)  
       if f:  
           flag = f  
       else:  
           check_3(flag)  
           break

# hitcon{9renp0to!m4gic}  
```

After a dozen iterations, we can get the flag `hitcon{9renp0to!m4gic}`.

Original writeup (https://github.com/equation314/hitcon-
ctf-2018-writeup/tree/master/party).