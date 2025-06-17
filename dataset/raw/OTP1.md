This is XOR cipher with the flag as repeated key.  
```php  
//For these problems I'll only change these 2 lines:  
$flag = trim(file_get_contents("../../flag1.txt"));  
$key = pad_string($flag, 0);  
```

We use [CyberChef](https://gchq.github.io/CyberChef/) to dump ciphertext to
file, then [xortool](https://github.com/hellman/xortool) to find the key
length of 25 and try to reveal some part of the flag.  
```  
$ xortool otp1.dat  
The most probable key lengths:  
2:   9.6%  
5:  15.6%  
10:  13.0%  
13:   7.7%  
15:  10.3%  
20:   8.6%  
22:   6.1%  
25:  15.4%  
30:   6.1%  
50:   7.6%  
Key-length can be 5*n  
Most possible char is needed to guess the key!  
$ xortool -l 25 -c 'E' otp1.dat  
4 possible key(s) of length 25:  
UDCTFjw?}r!mtNe0N

Original writeup (https://github.com/CTF-STeam/ctf-
writeups/tree/master/2021/BlueHensCTF#otp1-crypto---284-pts).