# Task  
Salt and Pepper, Salty and Spicy! Can we attack these unnormalized served
foods?  

nc 02.cr.yp.toc.tf 28010  
  
Source code is provided:

```  
#!/usr/bin/env python3

from hashlib import md5, sha1  
import sys  
from secret import salt, pepper  
from flag import flag

assert len(salt) == len(pepper) == 19  
assert md5(salt).hexdigest()    == '5f72c4360a2287bc269e0ccba6fc24ba'  
assert sha1(pepper).hexdigest() == '3e0d000a4b0bd712999d730bc331f400221008e0'

def auth_check(salt, pepper, username, password, h):  
	return sha1(pepper + password + md5(salt + username).hexdigest().encode('utf-8')).hexdigest() == h

def die(*args):  
	pr(*args)  
	quit()

def pr(*args):  
	s = " ".join(map(str, args))  
	sys.stdout.write(s + "\n")  
	sys.stdout.flush()

def sc():  
	return sys.stdin.readline().strip()

def main():  
	border = "+"  
	pr(border*72)  
	pr(border, "  welcome to hash killers battle, your mission is to login into the ", border)  
	pr(border, "  ultra secure authentication server with provided information!!    ", border)  
	pr(border*72)

	USERNAME = b'n3T4Dm1n'  
	PASSWORD = b'P4s5W0rd'

	while True:  
		pr("| Options: \n|\t[L]ogin to server \n|\t[Q]uit")  
		ans = sc().lower()  
		if ans == 'l':  
			pr('| send your username, password as hex string separated with comma: ')  
			inp = sc()  
			try:  
				inp_username, inp_password = [bytes.fromhex(s) for s in inp.split(',')]  
			except:  
				die('| your input is not valid, bye!!')  
			pr('| send your authentication hash: ')  
			inp_hash = sc()  
			if USERNAME in inp_username and PASSWORD in inp_password:  
				if auth_check(salt, pepper, inp_username, inp_password, inp_hash):  
					die(f'| Congrats, you are master in hash killing, and it is the flag: {flag}')  
				else:  
					die('| your credential is not valid, Bye!!!')  
			else:  
				die('| Kidding me?! Bye!!!')  
		elif ans == 'q':  
			die("Quitting ...")  
		else:  
			die("Bye ...")

if __name__ == '__main__':  
	main()  
```

# Analysis  
To get the flag, we need a successful login into the server.

We have to provide three parameters:

- username, which must contain the string "n3T4Dm1n", without double quotes;  
- password, which must contain the string "P4s5W0rd", without double quotes;  
- hash, which is used to make the authentication check in the following way:  
   + sha1(pepper + password + md5(salt + username).hexdigest().encode('utf-8')).hexdigest() == hash  
  
   + So it's clear that the 'hash' parameter must be an hex-encoded sha-1.  
  
To summarize: we need to provide constrained username and password and
unconstrained hash, such that the "signature" is valid.

The problem is that we don't know salt and pepper, which are the secrets for
the signature: in fact this is a "baby HMAC".  
  
But if we look at the first lines of the source code, we see that we are
provided with:

- length of both salt and pepper;  
- MD5(salt);  
- SHA1(pepper).

Having MD5(salt) is equal to having a signature made with the salt for an
empty message, and the same holds for SHA1(pepper).

Making some research about attacks against cryptographic hash functions, we
found that what we were looking for was an hash length extension attack.

We found an implementation, along with a detailed explanation,
[here](https://github.com/iagox86/hash_extender).

# Exploit  
In these cases it's useful to modify the challenge source code to make some
local tests first.

We modify the first lines like that:

```  
from hashlib import md5, sha1  
import sys  
# from secret import salt, pepper  
# from flag import flag  
salt = b"A" * 19  
pepper = b"B" * 19  
flag = "CCTF{lets_make_local_t3sts}"

assert len(salt) == len(pepper) == 19  
# assert md5(salt).hexdigest()  == '5f72c4360a2287bc269e0ccba6fc24ba'  
assert md5(salt).hexdigest() == '7ae4d6728e33ff002bf67a2e5194ccb1'  
# assert sha1(pepper).hexdigest() ==
'3e0d000a4b0bd712999d730bc331f400221008e0'  
assert sha1(pepper).hexdigest() == '8923ecf3550e9ca6cbb26066590fb619a2d65e71'  
```

At this point, we play a little bit with hash_extender from command line to
see how it works, and to check if we can forge valid signatures, with some
known secrets.

After that we write an exploit which can work both locally and remotely:

- the first call to hash_extender is to generate a valid MD5 signature with the username; we take from the output the generated signature and the generated username, which contains a certain number of bytes used to perform the attack and the actual username that we desired to append;  
- the second call to hash_extender is to generate the final SHA1 signature, which must contain the password and the MD5 signature hex-encoded; from the output we take the generated signature and password.

In both cases, the 'data' (-d) parameter is empty because we have the hashes
of salt and pepper, which are like signatures for empty messages, like we said
before.

Now we're ready to present the exploit:

```  
from pwn import remote, process  
import subprocess  
import re

def main():  
   local = False  
   username = 'n3T4Dm1n'  
   password = 'P4s5W0rd'  
   if local:  
       md5_salt = '7ae4d6728e33ff002bf67a2e5194ccb1'  
       sha1_pepper = '8923ecf3550e9ca6cbb26066590fb619a2d65e71'  
   else:  
       md5_salt = '5f72c4360a2287bc269e0ccba6fc24ba'  
       sha1_pepper = '3e0d000a4b0bd712999d730bc331f400221008e0'

   result = subprocess.check_output(["./hash_extender", "-f", "md5", "-d", "",
"-s", md5_salt, "-a", username, "-l", "19"]).decode()  
   new_signature, new_username = re.findall(r"[a-fA-F0-9]{4,}", result) # hex-
encoded  
  
   result = subprocess.check_output(["./hash_extender", "-f", "sha1", "-d",
"", "-s", sha1_pepper, "-a", password + new_signature, "-l", "19"]).decode()  
   final_signature, new_password = re.findall(r"[a-fA-F0-9]{4,}", result) #
hex-encoded  
  
   new_password = new_password[:-64]

   print("intermediate signature =", new_signature)  
   print("final signature =", final_signature)  
   print("username =", new_username)  
   print("password =", new_password)

   if local:  
       r = process(["python", "salt_pepper.py"])  
   else:  
       r = remote("02.cr.yp.toc.tf", 28010)  
   r.recvuntil(b'uit')  
   r.recvline()  
   r.sendline(b'L')  
   r.recvuntil(b'comma:')  
   r.recvline()  
   r.sendline(",".join([new_username, new_password]).encode())  
   r.recvuntil(b'hash:')  
   r.recvline()  
   r.sendline(final_signature.encode())  
   r.interactive()

if __name__ == "__main__":  
   main()

```

CCTF{Hunters_Killed_82%_More_Wolves_Than_Quota_Allowed_in_Wisconsin}

Original writeup
(https://pwnthenope.github.io/writeups/2021/08/01/salt_and_pepper.html).