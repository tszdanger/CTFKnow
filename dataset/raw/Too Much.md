# Too Much  
Here is the Challenge Description  
```  
I found a program that generates the flag of this challenge, but the
implementation of one of its functions is not available. This function seems
simple, but I am confused because of the large number of numbers! Can you help
me find the flag before the competition is over?!  
```

```python  
def func(x):  
   # Returns the number of distinct pairs (y, z) from the numbers in the file
"numbers.txt" whose y != z and (y + z) == x  
   # Note that two pairs (y, z) and (z, y) are considered the same and are
counted only once

def get_flag(res):  
   flag = []  
   for i in range(len(res)):  
       flag.append(chr(func(res[i])))  
   flag = ''.join(flag)  
   return flag

if __name__ == "__main__":  
   res = [751741232, 519127658, 583555720, 3491231752, 3333111256, 481365731,
982100628, 1001121327, 3520999746,  
          915725624, 3218509573, 3621224627, 3270950626, 3321456817, 3091205444, 999888800, 475855017, 448213157,  
          3222412857, 820711846, 3710211491, 3119823672, 3333211607, 812955676, 971211391, 3210953872, 289789909,  
          781213400, 578265122, 910021887, 653886578, 3712776506, 229812345, 582319118, 1111276998, 1151016390,  
          700123328, 1074521304, 3210438183, 817210125, 501231350, 753244584, 3240911853, 415234677, 469125436,  
          592610671, 612980665, 291821367, 344199617, 1011100412, 681623864, 897219249, 3132267885, 565913000,  
          301203203, 3100544737, 432812663, 1012813485, 510928797, 671553831, 3216409218, 3191288433, 698777123,  
          3512778698, 810476845, 3102989588, 3621432709, 812321695, 526486561, 378912454, 3316207359, 623111580,  
          344209171, 537454826, 691277475, 2634678623, 1112182335, 792111856, 762989676, 666210267, 871278369,  
          581009345, 391231132, 921732469, 717217468, 3101412929, 3101217354, 831912337, 532666530, 701012510,  
          601365919, 492699680, 2843119525]  
   print("The flag is", get_flag(res))  
```

# Solution

No need to check every 2 pairs. here are the required steps for better and
faster solution

1. For every `x` read whole numbers, if they are greater than `x` ignore them.  
2. Subtract whole numbers from x and keep the results in a new list.  
3. Intersect the new list with the old list to see which results are same  
4. because we have redundant numbers, Caculate `size of the new list / 2` and thats the answer

```python  
def intersection(lst1, lst2):  
   lst3 = [value for value in lst1 if value in lst2]  
   return lst3

def func(x):  
   # Returns the number of distinct pairs (y, z) from the numbers in the file
"numbers.txt" whose y != z and (y + z) == x  
   # Note that two pairs (y, z) and (z, y) are considered the same and are
counted only once

   numbers = open('numbers.txt', 'r').readlines()  
   numbers = set(numbers)  
  
   results = []  
   for num in numbers:

       num = int(num.rstrip("\n"))  
       if x < num:  
           continue

       tmp = x - num  
       results.append(str(tmp)+"\n")

   new_list = intersection(results, numbers)

   print(f"{len(new_list)//2} : {chr(len(new_list)//2)}")

   return(len(new_list)//2)

def get_flag(res):  
   flag = []  
   for i in range(len(res)):  
       flag.append(chr(func(res[i])))  
   flag = ''.join(flag)  
   return flag

if __name__ == "__main__":  
   res = [751741232, 519127658, 583555720, 3491231752, 3333111256, 481365731,
982100628, 1001121327, 3520999746,  
          915725624, 3218509573, 3621224627, 3270950626, 3321456817, 3091205444, 999888800, 475855017, 448213157,  
          3222412857, 820711846, 3710211491, 3119823672, 3333211607, 812955676, 971211391, 3210953872, 289789909,  
          781213400, 578265122, 910021887, 653886578, 3712776506, 229812345, 582319118, 1111276998, 1151016390,  
          700123328, 1074521304, 3210438183, 817210125, 501231350, 753244584, 3240911853, 415234677, 469125436,  
          592610671, 612980665, 291821367, 344199617, 1011100412, 681623864, 897219249, 3132267885, 565913000,  
          301203203, 3100544737, 432812663, 1012813485, 510928797, 671553831, 3216409218, 3191288433, 698777123,  
          3512778698, 810476845, 3102989588, 3621432709, 812321695, 526486561, 378912454, 3316207359, 623111580,  
          344209171, 537454826, 691277475, 2634678623, 1112182335, 792111856, 762989676, 666210267, 871278369,  
          581009345, 391231132, 921732469, 717217468, 3101412929, 3101217354, 831912337, 532666530, 701012510,  
          601365919, 492699680, 2843119525]  
   print("The flag is", get_flag(res))  
```

And here is the result after less than a minute which is fast enough for this
numbers  
```  
The flag is
TMUCTF{r4nd0m_fl46_f0r_fun!_SzC!$JvnbrRh6kc*1@L!4vMueH1k0xKPJem@vh6Y2&Sb2CJzwjnTfU6wVZyePOK3}  
```

[solution code](https://github.com/KooroshRZ/CTF-
Writeups/blob/main/TMU2021/Misc/TooMuch/solve.py)

> KouroshRZ for **AbyssalCruelty**

Original writeup (https://kooroshrz.github.io/CTF-
Writeups/TMU2021/Misc/TooMuch/).The challenge is an "angrable" challenge, cause the input is check with simple
mathematic operations. We can use these 2 piece of cose as an oracle for
desired address and wrong address:  
```c  
puts("Congrats!!! You have cracked my code.");

puts("Please try harder!!!!")  
```

# EXPLOIT  
```python  
import angr, claripy  
target = angr.Project('rev', auto_load_libs=False)  
input_len = 200  
inp = [claripy.BVS('flag_%d' %i, 8) for i in range(input_len)]  
flag = claripy.Concat(*inp + [claripy.BVV(b'\n')])

desired = 0x46d6  
wrong = 0x46e4

st = target.factory.full_init_state(args=["./rev"], stdin=flag)  
for k in inp:  
   st.solver.add(k < 0x7f)  
   st.solver.add(k > 0x20)

sm = target.factory.simulation_manager(st)  
sm.run()  
y = []  
for x in sm.deadended:  
   if b"Congrats!!! You have cracked my code." in x.posix.dumps(1):  
       y.append(x)

#grab the first ouptut  
valid = y[0].posix.dumps(0)  
print(valid)  
```  
# FLAG  
`darkCON{4r3_y0u_r34lly_th1nk1n9_th4t_y0u_c4n_try_th15_m4nu4lly???_Ok_I_th1nk_y0u_b3tt3r_us3_s0m3_aut0m4t3d_t00ls_l1k3_4n9r_0r_Z3_t0_m4k3_y0ur_l1f3_much_e4s13r.C0ngr4ts_f0r_s0lv1in9_th3_e4sy_ch4ll3ng3}`  
                                                   

Original writeup
(https://github.com/Internaut401/CTF_Writeup/blob/master/2021/darkCON/too%20much.md).