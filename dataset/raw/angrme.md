# Description

```  
I hope you do not need more than three lines of python to solve this.  
```

# Solution

I got a binary and the hint that it is solvable with the symbolic execution
framework "angr".  
After using taking a small overview with r2 I figured it only had two paths,
one which lead to ":)" in stdout and multiple jumps to ":(".

So I used angr to search for ':)'

```python  
import angr  
import claripy

proj = angr.Project('angrme')  
simgr = proj.factory.simgr()  
simgr.explore(find=lambda s: b":)" in s.posix.dumps(1))  
s = simgr.found[0]  
print(s.posix.dumps(0))  
```

Flag: hxp{4nd_n0w_f0r_s0m3_r3al_ch4ll3ng3}  

Original writeup
(https://github.com/sw1ss/ctf/tree/master/2018-12-09-hxpCTF2018/angrme).