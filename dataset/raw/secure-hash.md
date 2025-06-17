Hackover CTF 2018: secure-hash  
==============================

## Description

We advise you to replace uses of `unordered_hash` with our new
`SecureHashtable`  
class, since we added advanced crypto to make it 14.3 times more secure.

Update: the binary was compiled with g++ and libstdc++, 64bit

We're running a demo version, try it now:

`nc secure-hash.ctf.hackover.de 1337`

## Solution

We're given two options in the main menu: register a new user and log in.
We're  
given the source code of the server so we can see that it will print the flag  
if we manage to log in as root.

```cpp  
if (table.lookup_keyvalue(name, password)) {  
   printf("Success! Logged in as %s\n", name.c_str());  
   if (name == "root") {  
       printf("You win, the flag is %s\n", flag.c_str());  
       return 0;  
   }  
} else {  
   printf("Invalid credentials!\n");  
}  
```

However the server doesn't let us register as root.

```cpp  
if (name == "root") {  
   printf("You are not root!\n");  
   continue;  
}  
table.insert_keyvalue(name, password);  
```

`insert_keyvalue` computes `sha512(username || password)` and stores it in an  
`unordered_set`. `lookup_keyvalue` lets us log in is `sha512(username ||
password)`  
is found in the storage.

To bypass this we can just register as `roota` with password `sdf` and then
log  
in as `root` with password `asdf` because the concatenation of username and  
password is the same in both cases and so the two hashes will be the same.

Flag: `hackover18{00ps_y0u_mu5t_h4ve_h1t_a_v3ry_unlikely_5peci4l_c4s3}`.  

Original writeup (https://github.com/ctf-
epfl/writeups/tree/master/hackover18/secure-hash).