# VirtualJava

## Description

There's nothing like executing my own code in Java in my own special way.

[VirtualJava.java](VirtualJava.java)

## Solution

The [class](VirtualJava.java) operates like some kind of assembly code.

It parses through the input characters and obtain an output. If the output in
each step falls to owo[1], it would be wrong.

It's too tedious to reverse it artificially, so I reversed it using the given
[code](VirtualJavaSolve.java) with some modification.  
  
Each step I at a printable character to the string and check the outcome. If
the output was good, add it to the answer and move on to next word.

```  
       for (int i = 32; i < 127; ++i){  
           String aa = Character.toString((char)i);  
           String a = ans + aa;  
           ...  
           boolean right=true;  
           for (int j = 0; j < c.length; j++) {  
               String s = getOutput(Math.abs(java.run(j, (int) c[j])));  
               if (s.equals(owo[1])) {  
                   right = false;  
                   break;  
               }  
           }  
           if (right == true){  
               System.out.println("yes");  
               ans = ans + aa;  
           }  
```

Finally, it split out the answer automatically.

```  
hsctf{y0u_d3f34t3d_th3_b4by_vm}  
```  

Original writeup (https://github.com/kuruwa2/ctf-
writeups/tree/master/HSCTF%206/VirtualJava).