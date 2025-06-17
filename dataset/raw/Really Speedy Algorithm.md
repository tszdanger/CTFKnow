This challenge requires solving 100 RSA problems consecutively with maximum 1s
for each problem.

There are 6 different types of problems:  
- Finding n given p and q  
- Finding q given n and p  
- Finding d given p, q and e  
- Finding phi given p and q  
- Finding pt given p, q (or phi), e and ct  
- Finding ct given p, q (or phi), e and pt

This is boresome and I only tried at the last minutes. Thereforce I didn't
manage to solve it on time.

Anyway, here's the code:

```  
import socket

# Extended Euclidean Algorithm  
def egcd(a, b):  
   if a == 0:  
       return (b, 0, 1)  
   g, y, x = egcd(b % a, a)  
   return (g, x - (b // a) * y, y)

# application of Extended Euclidean Algorithm to find a modular inverse  
def modinv(a, m):  
   g, x, y = egcd(a, m)  
   if g != 1:  
       raise Exception('modular inverse does not exist')  
   return x % m

def find_pt(p, q, e, ct):  
   n = p * q  
   phi = (p - 1) * (q - 1)  
   d = modinv(e, phi)  
   pt = pow(ct, d, n)  
   return pt

def find_ct(p, q, e, pt):  
   n = p * q  
   phi = (p - 1) * (q - 1)  
   ct = pow(pt, e, n)  
   return ct

def find_d(p, q, e):  
   n = p * q  
   phi = (p - 1) * (q - 1)  
   d = modinv(e, phi)  
   return d

IP = '88.198.219.20'  
PORT = 23125

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
s.connect((IP, PORT))  
s.setblocking(0)

buffer = b''

while True:  
   # Read until a prompt or line break  
   try:  
       chunk = s.recv(4096)  
       buffer += chunk  
       print(chunk.decode(), end='')  
   except BlockingIOError:  
       pass

   if b'\n' not in buffer and not buffer.endswith(b': '):  
       continue

   # Grab the oldest line  
   buffer = buffer.split(b'\n', 1)  
   if len(buffer) == 1:  
       line, buffer = buffer[0], b''  
   else:  
       line, buffer = buffer

   # Llines start with [`]  
    if line[:1] != b'[':  
        continue`

   # Use slicing not indexing because indexing bytes returns ints  
   mode = line[1:2]  
   vari = line[4:7]  
   #print(vari)  
   if mode == b'*':  
       print('*')  
   elif mode == b'c':  
       p,q,e,n,pt,ct,phi = 0,0,0,0,0,0,0  
       print('c')  
   elif mode == b':':  
       if vari == b'p: ':  
           p = int(line[7:].decode())  
           #print(p)  
       elif vari == b'q: ':  
           q = int(line[7:].decode())  
           #print('q: ' + str(q))  
       elif vari == b'e: ':  
           e = int(line[7:].decode())  
           #print(e)  
       elif vari == b'n: ':  
           n = int(line[7:].decode())  
           #print(n)  
       elif vari == b'phi':  
           phi = int(line[9:].decode())  
           #print(phi)  
       elif vari == b'pt:':  
           pt = int(line[8:].decode())  
           #print(pt)  
       elif vari == b'ct:':  
           ct = int(line[8:].decode())  
           #print(ct)  
   elif mode == b'!':  
       #print('!')  
       if line == b'[!] A good cryptologist should be faster than that!':  
           break;  
       elif line == b'[!] INCORRECT ANSWER!':  
           break;  
   elif mode == b'?':  
       #print('?')  
       if vari == b'n: ':  
           n = p * q  
           #print(n)  
           s.sendall((str(n) + '\n').encode())  
       elif vari == b'q: ':  
           q = n // p  
           #print(q)  
           s.sendall((str(q) + '\n').encode())  
       elif vari == b'd: ':  
           d = find_d(p, q, e)  
           #print(d)  
           s.sendall((str(d) + '\n').encode())  
       elif vari == b'phi':  
           phi = (p - 1) * (q - 1)  
           #print(phi)  
           s.sendall((str(phi) + '\n').encode())  
       elif vari == b'pt:':  
           if q == 0:  
               q = (phi // (p - 1)) + 1  
           #print('q: ' + str(q))  
           pt = find_pt(p, q, e, ct)  
           #print(pt)  
           s.sendall((str(pt) + '\n').encode())  
       elif vari == b'ct:':  
           if q == 0:  
               q = (phi // (p - 1)) + 1  
           #print('q: ' + str(q))  
           ct = find_ct(p, q, e, pt)  
           #print(ct)  
           s.sendall((str(ct) + '\n').encode())  
   else:  
       print(line)  
```

Result:

```  
[c] Challenge 100:  
[:] p:
6892503881845816135437970025250733877066829303171701023363747158858557273648035991068180509649935204522542306573221659692941997106933628410204032749970179  
[:] q:
6892503881845816135437970025250733877066829303171701023363747158858557273648035991068180509649935204522542306573221659692941997106933628410204032749970179  
[:] e: 65537  
[?] d: c  
[!] Correct answer

[F] FLAG: ractf{F45t35tCryp70gr4ph3rAr0und}  
```