This is really more of a programming task rather than. We interpret the binary
digits as input to a 7 segment display:

![7-segment-display](https://www.electronics-tutorials.ws/wp-
content/uploads/2013/10/segment4.gif)

Implementation of the 7 segment display "pretty printing" is found in the URL.

__Input:__

```  
01001110-00100000-00111010-00001100-11011110-00011110-00000000-01100000-00101010-01111010-00100000-11110110-00111010-00000000-11111110-00001100-00111000-11011110-00000000-10111100-00001010-11011110-11011110-00101010-00000000-01110110-11011110-00001100-00001100-00111010-01010110-00000000-11111100-00001010-11111010-00101010-11110110-11011110-00000000-11101110-11011110-01111011-00000000-10001110-00001100-11111010-11110110-00000000-00100000-10110110-00000000-00011101-10011111-01111011-10110111-11111110-00001010-00100000-00101010-11110111-01111000-00111010-01100111-10001100-00111011-10101010-11011110  
```

__Output:__

```raw  
                                XXX                      
X   X                   X       X   X   X  
X   X                   X       X   X   X  
X   X                   X       X   X   X  
XXX             XXX             XXX     XXX  
X           X   X   X   X       X       X  
X           X   X   X   X       X       X  
X           X   X   X   X       X       X  
                XXX             XXX     XXX            

                                XXX                      
   X               X           X   X  
   X               X           X   X  
   X               X           X   X  
        XXX     XXX             XXX     XXX              
   X   X   X   X   X       X       X   X   X  
   X   X   X   X   X       X       X   X   X  
   X   X   X   X   X       X       X   X   X  
                XXX             XXX     XXX            

XXX                     XXX  
X   X   X               X   X  
X   X   X               X   X  
X   X   X               X   X  
XXX                     XXX  
X   X   X       X   X   X  
X   X   X       X   X   X  
X   X   X       X   X   X  
XXX             XXX     XXX  

XXX             XXX     XXX  
X               X   X   X   X  
X               X   X   X   X  
X               X   X   X   X  
        XXX     XXX     XXX     XXX              
X   X   X       X       X       X   X  
X   X   X       X       X       X   X  
X   X   X       X       X       X   X  
XXX             XXX     XXX  

        XXX                                              
X   X   X   X   X       X               X   X  
X   X   X   X   X       X               X   X  
X   X   X   X   X       X               X   X  
XXX     XXX                     XXX     XXX  
   X   X       X       X       X   X  
   X   X       X       X       X   X  
   X   X       X       X       X   X  
XXX     XXX                     XXX     XXX  

XXX             XXX             XXX     XXX  
X   X               X           X   X   X   X  
X   X               X           X   X   X   X  
X   X               X           X   X   X   X  
        XXX     XXX     XXX     XXX     XXX              
X   X   X       X   X   X   X       X   X  
X   X   X       X   X   X   X       X   X  
X   X   X       X   X   X   X       X   X  
XXX             XXX             XXX     XXX  

XXX     XXX  
X   X   X   X       X  
X   X   X   X       X  
X   X   X   X       X  
XXX     XXX     XXX  
X   X   X       X   X  
X   X   X       X   X  
X   X   X       X   X  
        XXX     XXX  X         

XXX             XXX     XXX  
X       X           X   X   X  
X       X           X   X   X  
X       X           X   X   X  
XXX             XXX     XXX  
X       X       X   X       X  
X       X       X   X       X  
X       X       X   X       X  
                XXX     XXX            

        XXX              
       X                 
       X                 
       X                 
        XXX              
   X       X  
   X       X  
   X       X  
        XXX            

        XXX             XXX     XXX                             XXX                             XXX             XXX     XXX      
X       X           X   X       X   X                           X   X       X
X   X   X                       X   X  
X       X           X   X       X   X                           X   X       X
X   X   X                       X   X  
X       X           X   X       X   X                           X   X       X
X   X   X                       X   X  
        XXX     XXX     XXX     XXX     XXX             XXX     XXX             XXX     XXX             XXX     XXX     XXX      
X       X       X   X       X   X   X   X           X   X   X       X   X   X
X   X       X   X       X   X   X   X   X  
X       X       X   X       X   X   X   X           X   X   X       X   X   X
X   X       X   X       X   X   X   X   X  
X       X       X   X       X   X   X   X           X   X   X       X   X   X
X   X       X   X       X   X   X   X   X  
XXX  X  XXX  X  XXX  X  XXX  X  XXX                             XXX  X  XXX
XXX          X          XXX  X          XXX  
```

__Flag:__

```  
d4rk{L.E.d.s.Bring.Joy.To.me}c0de  
```  

Original writeup (https://github.com/pberba/ctf-
solutions/blob/master/20180816_hackcon/crypto/50_light_n_easy/README.md).