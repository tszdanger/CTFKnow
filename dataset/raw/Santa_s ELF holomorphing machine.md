We are given 802 lines of data.  
Each line contains either a function `u(x,y)` or a function `v(x,y)` and an
imaginary number `z=x+y*i`.  
The task is to compute the value `f(z)` of an unknown holomorphic function `f:
C->C` at the position `z`. We don't know `f`. But we know either the real part
`Re(f(z)) = u(x,y)` or the imaginary part `Im(f(z)) = v(x,y)` of `f(z)`.

To solve this challenge we read up on [holomorphic
functions](https://en.wikipedia.org/wiki/Holomorphic_function) and the
[Cauchy-Riemann
equations](https://en.wikipedia.org/wiki/Cauchy%E2%80%93Riemann_equations).

Since `f` is a holomorphic function, `u(x,y)` and `v(x,y)` fulfill the Cauchy-
Riemann equations:  
```  
du/dx = dv/dy  
```  
and  
```  
du/dy = -dv/dx  
```

This means that if we know either `u` or `v`, we can compute the other
function up to an unknown constant which is introduced when integrating over
`x` and `y`.

The following Sage9 script parses the given data. From the given function `u`
or `v` it computes the missing second function. To do so, it assumes the
constant to be zero. It then computes the value `f(z)` and plots each value to
the x-y-plane.  
```python3  
#!/usr/bin/sage  
import matplotlib.pyplot as plt  
ll = list()  
llx = list()  
lly = list()  
for _ in range(802):  
   line = input()  
   uvs, zs = line.split('; ')  
   uv, uvt = uvs.split(' =')  
   zt = zs.split(' = ')[1]  
   uva, uvb = uvt.split(' + ')  
   uva, uvb = int(uva.split(' * ')[0]), int(uvb.split(' * ')[0])  
   zx, zy = zt.split(' + ')  
   zx, zy = float(zx), float(zy.split('*')[0])  
   xx, yy = 0, 0  
   if uv == 'u':  
       xx =  uva * zx + uvb * zy  
       yy = -uvb * zx + uva * zy  
       pass  
   else:  
       xx =  uvb * zx - uva * zy  
       yy =  uva * zx + uvb * zy  
       pass  
   yy = 20 - yy  
   print(xx, yy)  
   ll.append((xx, -yy))  
   llx.append(xx)  
   lly.append(yy)  
   pass  
plt.scatter(llx, lly)  
plt.show()  
```

The plot prints the flag to the screen. Since it is printed bottom up, we
inverted the y-coordinates with `yy = 20 - yy`. The flag is  
```  
X-MAS{C4uchy_4nd_Ri3m4nn_ar3_c0ming_t0_t0wn}  
```