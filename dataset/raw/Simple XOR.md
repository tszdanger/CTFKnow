# Simple XOR

Category: Cryptography

Files:  
- enc

## Description

Right! an XOR challenge a pretty basic one. Below is the source code of the
script that was used to encrypt the message containing the flag, Help me get
the flag back!

```python  
message = 'urchinsec{fake_flag}' # message comes here  
key = 'a' # key comes here  
encrypted = ''.join([chr(ord(x) ^ ord(key)) for x in message])  
with open("enc", "w") as enc:  
   enc.write(encrypted)

print("encrypted")  
```

## enc  
	0c0b 1a11 1017 0a1c 1a02 0116 0b0b 1017  
	1e26 1400 260e 1800 260d 1626 0d11 1c26  
	0d49 0904 

## Writeup  
https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR_Brute_Force(1,100,0,'Standard',false,true,false,'ur')&input=MGMgMGIgMWEgMTEgMTAgMTcgMGEgMWMgMWEgMDIgMDEgMTYgMGIgMGIgMTAgMTcgMWUgMjYgMTQgMDAgMjYgMGUgMTggMDAgMjYgMGQgMTYgMjYgMGQgMTEgMWMgMjYgMGQgNDkgMDkgMDQ

	urchinsec{xorring_my_way_to_the_t0p}

Original writeup (https://www.youtube.com/watch?v=j_PXf2DWDVk).