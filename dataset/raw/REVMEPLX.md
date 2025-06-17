---  
description: REV | 100 pts - 201 solves  
---

# RevMePlx

> Description: What could possibly be hidden inside a diving logbook? author:
> Skipper|RedRocket

Running the elf, it asks us for the name of a diver:

```shell  
$ ./rev  
| >>> REEF RANGERS Dive Panel <<< |  
| ------------------------------- |  
|    Please provide Diver Name:   |

```  
Not knowing them we can launch `strings` on the executable and see what we can
find:

```shell  
$ strings ./rev  
[...]  
CSR{  
_submarines_  
_solved_n1c3!}  
Jeremy  
Simon  
Adminiman  
Your dive count is: 81  
Welcome instructor!  
Your dive count is: 410  
Your dive count is: 0  
To show today's drydock report, please enter passcode:  
No diving recore of diver  
found!  
| >>> REEF RANGERS Dive Panel <<< |  
| ------------------------------- |  
|    Please provide Diver Name:   |  
[...]  
```

The flag appears to be there, but it won't work if we try to submit it.
however, we also find names of the divers.  
Opening the executable in Ghidra we immediately notice that it's a cpp
executable. The `main()` function, looks a bit confusing but we notice that
there's a call to an interesting `door_lock()` function following an if
statement. After a couple of attempts we discover that the diver triggering
that function is `Jeremy`.  
Looking more closely at the `door_lock()` function, we know that it takes
`param_1` as input and does the following check:

```c  
if (param_1 * 2 >> 8 == 0x539) {  
```

Right-shifting a number of `n` bits also means that it's being divided by 2 to
the power of `n`.

```python  
In [1]: (0x539 * (2**8)) / 2  
Out[1]: 171136.0  
```  
Or  
```python  
In [2]: (0x539 << 8) / 2  
Out[2]: 171136.0  
```

Will get us the magic number.

```shell  
$ ./rev  
| >>> REEF RANGERS Dive Panel <<< |  
| ------------------------------- |  
|    Please provide Diver Name:   |  
Jeremy  
Your dive count is: 0  
To show today's drydock report, please enter passcode:  
171136.0  
CSR{11_submarines_45864441_solved_n1c3!}  
```  
> CSR{11_submarines_45864441_solved_n1c3!}

Original writeup
(https://github.com/simonedimaria/CTF/blob/main/events/CyberSecurityRumble/RevMePlx/revmeplx.md).