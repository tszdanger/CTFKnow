# Homebrew - Crypto/web (200)

Homebrew Inc learned the hard way to no longer store passwords in plaintext.
Log in as admin into their new user system.

Service: http://18.205.93.120:1207

## Service Analysis

This challenge started out with a simple web service without much
functionality. One of the pages references "self-describing REST APIs" which a
quick google search reveals are just REST API descriptions in OPTIONS
requests. With that in mind, I went about writing a short script to send an
OPTIONS request for `/signup` and `/login`. These in turn reveal that there
are a couple extra REST API endpoints `/signup/step1`, `/login/step1`, and
`/login/step2`. When working the problem I completely blew past the "SRP
signup" and "SRP login" descriptions, but had I not, this would have saved a
lot of time. Looking at the protocol, its eventually clear that it very
closely resembles the [Secure Remote Password
protocol](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol).
Searching a little further gets us to an intended solution described in a
[cryptopal challenge](http://cryptopals.com/sets/5/challenges/37). Basically,
all that you need to do is send `0`, `N`, `2*N`, etc as your `A` value and
you'll be logged in automatically. This was simple enough to writeup with a
script and gives us the flag.

```python  
import requests  
import os  
import json  
import Crypto.Hash.SHA256 as SHA256  
import sys  
import hmac  
import math  
import binascii

URI = 'http://18.205.93.120:1207'  
jar = requests.cookies.RequestsCookieJar()

def get_sha256(data):  
	if type(data) == str:  
		data = data.encode('ascii')  
	s = SHA256.new()  
	s.update(data)  
	return s.hexdigest()

def get_proof(salt,K):  
	return hmac.new(str(salt).encode('ascii'),K.encode('ascii'),SHA256).hexdigest()

def print_spec(path):

	print('>'*80, path)  
	r = requests.options(URI+path)  
	j = r.json()  
	print(json.dumps(j,indent=2))  
	return j

def validate():  
	j = print_spec('/signup')  
	N = j['params']['N']  
	g = j['params']['g']  
	k = j['params']['k']

	js1 = print_spec('/signup/step1')  
	I = js1['prereq_example']['I']  
	P = js1['prereq_example']['P']  
	salt = js1['prereq_example']['salt']  
	xH = js1['prereq_example']['xH']  
	x = js1['prereq_example']['x']  
	v = js1['prereq_example']['v']  
	assert xH == get_sha256(str(salt)+P)  
	assert x == int(xH,16)  
	assert v == pow(g,x,N)

	jl = print_spec('/login')

	jl1 = print_spec('/login/step1')  
	I = jl1['prereq_example']['I']  
	a = jl1['prereq_example']['a']  
	A = jl1['prereq_example']['A']  
	assert A == pow(g,a,N)

	jl2 = print_spec('/login/step2')  
	a = jl2['prereq_example']['a']  
	A = jl2['prereq_example']['A']  
	B = jl2['prereq_example']['B']  
	salt = jl2['prereq_example']['salt']  
	P = jl2['prereq_example']['P']  
	uH = jl2['prereq_example']['uH']  
	u = jl2['prereq_example']['u']  
	xH = jl2['prereq_example']['xH']  
	x = jl2['prereq_example']['x']  
	S = jl2['prereq_example']['S']  
	K = jl2['prereq_example']['K']  
	proof = jl2['req_example']['proof']  
	assert uH == get_sha256(str(A)+str(B))  
	assert u == int(uH,16)  
	assert xH == get_sha256(str(salt)+P)  
	assert x == int(xH,16)  
	assert S == pow(B-k*pow(g,x,N),(a+u*x),N)  
	assert K == get_sha256(str(S))

	print(proof)  
	print(get_proof(salt,K))  
	print(hmac.new(str(salt).encode('ascii'),K.encode('ascii'),SHA256).hexdigest())  
	assert proof == get_proof(salt,K)

	a = random.randint(1,2**32-1)  
	A = pow(g,a,N)  
	b = random.randint(1,2**32-1)  
	B = k*v+pow(g,b,N)  
	uH = get_sha256(str(A)+str(B))  
	u = int(uH,16)

	S1 = pow(B-k*v,(a+u*x),N)  
	S2 = pow(A*pow(v,u,N),b,N)  
	print('S1:',S1%N)  
	print('S2:',S2%N)  
	assert S1 == S2

	sys.exit(0)

if __name__ == '__main__':  
	validate()

	j = print_spec('/signup')  
	N = j['params']['N']  
	g = j['params']['g']  
	k = j['params']['k']

	r = requests.post(URI+'/login/step1',json={'I':'admin','A':2*N})  
	print(r.text)  
	print(r.cookies)  
	cook = r.cookies  
	j = r.json()  
	salt = j['salt']  
	B = j['B']

	S = 0  
	K = get_sha256(str(S))  
	print('salt:',salt)  
	print('K:',K)  
	proof = get_proof(salt,K)  
	r = requests.post(URI+'/login/step2',json={'proof':proof},cookies=cook)  
	print(r.text)

```  

Original writeup
(https://github.com/nononovak/otwadvent2018-ctfwriteup/blob/master/day7.md).