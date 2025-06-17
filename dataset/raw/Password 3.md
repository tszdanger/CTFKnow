# Password 3

## Task

This one won’t be so easy

File: password3.py

## Solution

This one was also very easy:

```python  
def checkPassword(password):  
 if(len(password) != 40):  
   return False  
 newPass = list(password)  
 for i in range(0,40):  
   newPass[i] = chr(ord(newPass[i]) ^ 0x55)  
 finalPass = "".join(newPass)  
 passBytes = finalPass.encode("ascii")  
 base64_bytes = base64.b64encode(passBytes)  
 base64_string = base64_bytes.decode("ascii")  
 return base64_string ==
"FgwWARMuF2UhPQotZScKFTsxCjcVJmYKY2FqCiE9FSEmCjJlMTksKA=="  
```

This is just single-byte XOR. We just need to write the inverse of it:

```python  
base64_string = "FgwWARMuF2UhPQotZScKFTsxCjcVJmYKY2FqCiE9FSEmCjJlMTksKA=="  
base64_bytes = base64.b64decode(base64_string)  
finalPass = base64_bytes.decode("ascii")  
newPass = list(finalPass)  
for i in range(0, 40):  
   newPass[i] = chr(ord(newPass[i]) ^ 0x55)  
print(''.join(newPass))  
```