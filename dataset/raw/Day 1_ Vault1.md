# Vault1 - Misc (300)

Santa's elves installed a secure vault to store Santa's secret documents. Can
you crack it?

Service: telnet 18.205.93.120 1201

## The Setup

The setup for this challenge was a network service which had a series of 20
"wheels" and asked you for a shift amount for each wheel. This was the only
challenge which gave out [a hint on
twitter](https://twitter.com/OverTheWireCTF/status/1069049150350794752) and
was relatively straightforward. Essentially, if you put in a wheel spin which
was greater than 26 and it spun to the right letter, then the spin amount was
reduced modulo 26. After discovering this, I spent a lot of time automating
how to count the number of spins for each wheel and writing a program to
automate this and solve for the flag.

## Solving the Vault

Since this challenge devolved to a programming problem, I'll keep my
description brief and get to the solution. I wrote it in python with a package
I hadn't used before (asyncio, telnetlib3) using some starter code (and the
fact that the "service" described was telnet). Basically my solution records
the incoming data, when it gets a prompt for an access code it looks back for
the start spin. Then it computes the number of spins for unsolved wheels, and
submits that value. To count the number of spins for each wheel, it parses out
the escape code sequence which moves the cursor and counts how many times that
is moved to the middle wheel location. My code is given below.

```python  
import asyncio, telnetlib3  
import re  
import socket

def chunk_ansi(data):  
	arr = []  
	last_end = 0  
	pat = re.compile('\x1b\[([0-9;]*)(\w)')  
	for match in re.finditer(pat,data):  
		start = match.start()  
		end = match.end()  
		if last_end != start:  
			arr.append(data[last_end:start])  
		if match.group(2) == 'H':  
			arr.append(tuple(int(x) for x in match.group(1).split(';')))  
		last_end = end  
	if last_end != len(data):  
		arr.append(data[last_end:])  
	return arr

def text_from_ansi(arr):  
	return ''.join([x for x in arr if type(x) == str])

def find_start(data):

	pat = re.compile('\w{20}\s{40}(\w{20})\s{40}\w{20}\s{40}')  
	match = re.search(pat,data)  
	if match is None:  
		return None  
	return match.group(1)

def find_spin(data):

	pat = re.compile('\w{20}\s{40}(\w{20})\s{40}\w{20}\s{20}\w\s{2}\w\s{2}\w\s{2}')

	match = re.search(pat,data)  
	if match is None:  
		return '.',[]

	index = match.end()-9  
	arr = []  
	while 'x' not in data[index:index+9]:  
		if data[index:index+9-1] != data[index-9+1:index] and data[index+1:index+9] != data[index-9:index-1]:  
			arr.append(index)  
		print(index, '<<'+data[index:index+9]+'>>')  
		index = index + 9  
	arr.append(index)  
	arr = [(arr[i+1]-arr[i])//27 for i in range(len(arr)-1)]  
	return match.group(1),arr

alph = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

@asyncio.coroutine  
def shell(reader, writer):  
	full_outp = ''  
	last_guess = None  
	last_arr = None  
	got_access_denied = True  
	solved = ['.']*20  
	outfile = open('challenge1.out','w')

	sent_solved = False  
	while True:  
		outp = yield from reader.read(1024)  
		if not outp:  
			# EOF  
			return  
		print(text_from_ansi(chunk_ansi(outp)), flush=True, file=outfile)  
		full_outp = full_outp + outp

		arr = chunk_ansi(full_outp)  
		buf = text_from_ansi(arr)

		if buf.endswith('Enter access code: ') and got_access_denied:  
			got_access_denied = False

			if '.' not in solved:  
				writer.write(''.join(solved) + '\n')  
				full_outp = ''  
				continue  
			start = find_start(buf)  
			print('start:',start)  
			if last_guess is None:  
				last_guess = ['A']*20  
			else:  
				last_guess = [alph[(alph.index(ch)+1)%26] for ch in last_guess]  
			arr = [27] * 20  
			for i in range(20):  
				if solved[i] != '.':  
					last_guess[i] = solved[i]  
					#arr[i] = 0  
				while alph[(alph.index(start[i])+arr[i])%26] != last_guess[i]:  
					arr[i] += 1  
			print('next guess:', last_guess)  
			last_arr = arr  
			arr_st = ' '.join(str(x) for x in arr) + '\n'  
			print('Sending:', arr_st.encode('ascii'))  
			writer.write(arr_st)  
			full_outp = ''

		if buf.endswith('Wrong access code: Access Denied!'):  
			got_access_denied = True  
			print('access denied received')  
			counts = [(arr.count((6,i))-3)//3 for i in range(7,87,4)]  
			print('countarr:',counts)  
			print('last_arr:',last_arr)  
			print('last guess:',last_guess)  
			for i in range(20):  
				if counts[i] != last_arr[i]:  
					assert solved[i] == '.' or solved[i] == last_guess[i]  
					solved[i] = last_guess[i]  
			print('new solved:',solved)  
			full_outp = ''

	print(outp, end='', flush=True)  
	print(outp.encode('utf-8'), end='', flush=True)  
	print(arr, flush=True)  
	print(buf.encode('utf-8'), flush=True)  
	print(buf, flush=True)  
	print()

if __name__ == '__main__':

	loop = asyncio.get_event_loop()  
	coro = telnetlib3.open_connection('172.30.30.30', 1201, shell=shell)  
	reader, writer = loop.run_until_complete(coro)  
	loop.run_until_complete(writer.protocol.waiter_closed)

```

Running this code will eventually solve the right wheel locations and give the
flag. For some reason I don't understand, the wheel spin modulus calculation
doesn't always work, but running the attack will eventually succeed.

```  
~/aotw$ time ./challenge1.py  
start: DQNTSTXJDCQPRCLBKTVQ  
next guess: ['A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
'A', 'A', 'A', 'A', 'A', 'A', 'A']  
Sending: b'49 36 39 33 34 33 29 43 49 50 36 37 35 50 41 51 42 33 31 36\n'  
access denied received  
countarr: [49, 36, 13, 33, 34, 33, 29, 43, 49, 50, 36, 37, 35, 50, 41, 51, 42,
33, 5, 36]  
last_arr: [49, 36, 39, 33, 34, 33, 29, 43, 49, 50, 36, 37, 35, 50, 41, 51, 42,
33, 31, 36]  
last guess: ['A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
'A', 'A', 'A', 'A', 'A', 'A', 'A']  
new solved: ['.', '.', 'A', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
'.', '.', '.', '.', '.', 'A', '.']  
start: ZQOPQURZSNQPAGQHITCF  
next guess: ['B', 'B', 'A', 'B', 'B', 'B', 'B', 'B', 'B', 'B', 'B', 'B', 'B',
'B', 'B', 'B', 'B', 'B', 'A', 'B']  
Sending: b'28 37 38 38 37 33 36 28 35 40 37 38 27 47 37 46 45 34 50 48\n'  
access denied received  
countarr: [28, 37, 12, 38, 37, 33, 36, 28, 35, 40, 37, 38, 27, 47, 37, 46, 45,
8, 2, 48]  
last_arr: [28, 37, 38, 38, 37, 33, 36, 28, 35, 40, 37, 38, 27, 47, 37, 46, 45,
34, 50, 48]  
last guess: ['B', 'B', 'A', 'B', 'B', 'B', 'B', 'B', 'B', 'B', 'B', 'B', 'B',
'B', 'B', 'B', 'B', 'B', 'A', 'B']  
new solved: ['.', '.', 'A', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
'.', '.', '.', '.', 'B', 'A', '.']  
start: ZAVUACOGSSURNITRJXVX  
next guess: ['C', 'C', 'A', 'C', 'C', 'C', 'C', 'C', 'C', 'C', 'C', 'C', 'C',
'C', 'C', 'C', 'C', 'B', 'A', 'C']  
Sending: b'29 28 31 34 28 52 40 48 36 36 34 37 41 46 35 37 45 30 31 31\n'  
access denied received  
countarr: [29, 28, 5, 34, 28, 52, 40, 48, 36, 36, 34, 37, 41, 46, 35, 37, 45,
4, 5, 31]  
last_arr: [29, 28, 31, 34, 28, 52, 40, 48, 36, 36, 34, 37, 41, 46, 35, 37, 45,
30, 31, 31]  
last guess: ['C', 'C', 'A', 'C', 'C', 'C', 'C', 'C', 'C', 'C', 'C', 'C', 'C',
'C', 'C', 'C', 'C', 'B', 'A', 'C']  
new solved: ['.', '.', 'A', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
'.', '.', '.', '.', 'B', 'A', '.']  
start: BWUPRYORYACDZOOEZNJI  
next guess: ['D', 'D', 'A', 'D', 'D', 'D', 'D', 'D', 'D', 'D', 'D', 'D', 'D',
'D', 'D', 'D', 'D', 'B', 'A', 'D']  
Sending: b'28 33 32 40 38 31 41 38 31 29 27 52 30 41 41 51 30 40 43 47\n'  
access denied received  
countarr: [28, 33, 6, 40, 38, 31, 41, 38, 31, 29, 27, 52, 30, 41, 41, 1, 30,
12, 9, 47]  
last_arr: [28, 33, 32, 40, 38, 31, 41, 38, 31, 29, 27, 52, 30, 41, 41, 51, 30,
40, 43, 47]  
last guess: ['D', 'D', 'A', 'D', 'D', 'D', 'D', 'D', 'D', 'D', 'D', 'D', 'D',
'D', 'D', 'D', 'D', 'B', 'A', 'D']  
new solved: ['.', '.', 'A', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
'.', '.', 'D', '.', 'B', 'A', '.']  
start: TTXKFYTIKVAGHAPGFEZB  
next guess: ['E', 'E', 'A', 'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E',
'E', 'E', 'D', 'E', 'B', 'A', 'E']  
Sending: b'37 37 29 46 51 32 37 48 46 35 30 50 49 30 41 49 51 49 27 29\n'  
access denied received  
countarr: [37, 37, 3, 46, 51, 32, 37, 48, 46, 35, 30, 50, 49, 30, 41, 3, 1, 3,
1, 3]  
last_arr: [37, 37, 29, 46, 51, 32, 37, 48, 46, 35, 30, 50, 49, 30, 41, 49, 51,
49, 27, 29]  
last guess: ['E', 'E', 'A', 'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E',
'E', 'E', 'D', 'E', 'B', 'A', 'E']  
new solved: ['.', '.', 'A', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
'.', '.', 'D', 'E', 'B', 'A', 'E']  
start: ZNZCRNFOWHDYVIMMTHNI  
next guess: ['F', 'F', 'A', 'F', 'F', 'F', 'F', 'F', 'F', 'F', 'F', 'F', 'F',
'F', 'F', 'D', 'E', 'B', 'A', 'E']  
Sending: b'32 44 27 29 40 44 52 43 35 50 28 33 36 49 45 43 37 46 39 48\n'  
access denied received  
countarr: [32, 44, 1, 29, 40, 44, 52, 43, 35, 50, 28, 33, 36, 3, 45, 9, 11, 6,
13, 4]  
last_arr: [32, 44, 27, 29, 40, 44, 52, 43, 35, 50, 28, 33, 36, 49, 45, 43, 37,
46, 39, 48]  
last guess: ['F', 'F', 'A', 'F', 'F', 'F', 'F', 'F', 'F', 'F', 'F', 'F', 'F',
'F', 'F', 'D', 'E', 'B', 'A', 'E']  
new solved: ['.', '.', 'A', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
'F', '.', 'D', 'E', 'B', 'A', 'E']  
start: ZJGGGUQGCVSWCRAERABF  
next guess: ['G', 'G', 'A', 'G', 'G', 'G', 'G', 'G', 'G', 'G', 'G', 'G', 'G',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'33 49 46 52 52 38 42 52 30 37 40 36 30 40 32 51 39 27 51 51\n'

access denied received  
countarr: [33, 49, 6, 52, 52, 38, 42, 52, 30, 11, 40, 36, 30, 12, 6, 51, 13,
1, 51, 51]  
last_arr: [33, 49, 46, 52, 52, 38, 42, 52, 30, 37, 40, 36, 30, 40, 32, 51, 39,
27, 51, 51]  
last guess: ['G', 'G', 'A', 'G', 'G', 'G', 'G', 'G', 'G', 'G', 'G', 'G', 'G',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['.', '.', 'A', '.', '.', '.', '.', '.', '.', 'G', '.', '.', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: CWUJQDQHPUHBRVAYZUVY  
next guess: ['H', 'H', 'A', 'H', 'H', 'H', 'H', 'H', 'H', 'G', 'H', 'H', 'H',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'31 37 32 50 43 30 43 52 44 38 52 32 42 36 32 31 31 33 31 32\n'  
access denied received  
countarr: [31, 37, 6, 50, 43, 30, 43, 52, 44, 12, 52, 32, 42, 10, 6, 5, 5, 7,
5, 32]  
last_arr: [31, 37, 32, 50, 43, 30, 43, 52, 44, 38, 52, 32, 42, 36, 32, 31, 31,
33, 31, 32]  
last guess: ['H', 'H', 'A', 'H', 'H', 'H', 'H', 'H', 'H', 'G', 'H', 'H', 'H',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['.', '.', 'A', '.', '.', '.', '.', '.', '.', 'G', '.', '.', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: VQMEUGXPJFLAMDNWPCUH  
next guess: ['I', 'I', 'A', 'I', 'I', 'I', 'I', 'I', 'I', 'G', 'I', 'I', 'I',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'39 44 40 30 40 28 37 45 51 27 49 34 48 28 45 33 41 51 32 49\n'  
access denied received  
countarr: [39, 44, 12, 30, 40, 28, 37, 45, 51, 1, 49, 34, 48, 2, 7, 7, 11, 1,
6, 3]  
last_arr: [39, 44, 40, 30, 40, 28, 37, 45, 51, 27, 49, 34, 48, 28, 45, 33, 41,
51, 32, 49]  
last guess: ['I', 'I', 'A', 'I', 'I', 'I', 'I', 'I', 'I', 'G', 'I', 'I', 'I',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['.', '.', 'A', '.', '.', '.', '.', '.', '.', 'G', '.', '.', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: GTTGWUCHYDPLCTMKKKFQ  
next guess: ['J', 'J', 'A', 'J', 'J', 'J', 'J', 'J', 'J', 'G', 'J', 'J', 'J',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'29 42 33 29 39 41 33 28 37 29 46 50 33 38 46 45 46 43 47 40\n'  
access denied received  
countarr: [29, 42, 7, 29, 39, 41, 33, 28, 37, 29, 46, 50, 33, 12, 6, 7, 6, 9,
5, 12]  
last_arr: [29, 42, 33, 29, 39, 41, 33, 28, 37, 29, 46, 50, 33, 38, 46, 45, 46,
43, 47, 40]  
last guess: ['J', 'J', 'A', 'J', 'J', 'J', 'J', 'J', 'J', 'G', 'J', 'J', 'J',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['.', '.', 'A', '.', '.', '.', '.', '.', '.', 'G', '.', '.', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: JTFEGDSFBEQUKSPEDMJV  
next guess: ['K', 'K', 'A', 'K', 'K', 'K', 'K', 'K', 'K', 'G', 'K', 'K', 'K',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'27 43 47 32 30 33 44 31 35 28 46 42 52 39 43 51 27 41 43 35\n'  
access denied received  
countarr: [27, 43, 5, 32, 30, 33, 44, 31, 35, 28, 46, 42, 52, 13, 9, 51, 1,
11, 9, 9]  
last_arr: [27, 43, 47, 32, 30, 33, 44, 31, 35, 28, 46, 42, 52, 39, 43, 51, 27,
41, 43, 35]  
last guess: ['K', 'K', 'A', 'K', 'K', 'K', 'K', 'K', 'K', 'G', 'K', 'K', 'K',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['.', '.', 'A', '.', '.', '.', '.', '.', '.', 'G', '.', '.', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: EKIEIWHSZEWKDJGYLXGZ  
next guess: ['L', 'L', 'A', 'L', 'L', 'L', 'L', 'L', 'L', 'G', 'L', 'L', 'L',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'33 27 44 33 29 41 30 45 38 28 41 27 34 48 52 31 45 30 46 31\n'  
access denied received  
countarr: [33, 27, 8, 7, 3, 41, 30, 45, 38, 2, 41, 27, 34, 4, 0, 5, 7, 4, 6,
5]  
last_arr: [33, 27, 44, 33, 29, 41, 30, 45, 38, 28, 41, 27, 34, 48, 52, 31, 45,
30, 46, 31]  
last guess: ['L', 'L', 'A', 'L', 'L', 'L', 'L', 'L', 'L', 'G', 'L', 'L', 'L',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['.', '.', 'A', 'L', 'L', '.', '.', '.', '.', 'G', '.', '.', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: ECFKJPQPQIZOQFCMNRWL  
next guess: ['M', 'M', 'A', 'L', 'L', 'M', 'M', 'M', 'M', 'G', 'M', 'M', 'M',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'34 36 47 27 28 49 48 49 48 50 39 50 48 52 30 43 43 36 30 45\n'  
access denied received  
countarr: [34, 36, 5, 1, 2, 49, 4, 49, 48, 2, 39, 2, 48, 0, 30, 9, 9, 10, 4,
7]  
last_arr: [34, 36, 47, 27, 28, 49, 48, 49, 48, 50, 39, 50, 48, 52, 30, 43, 43,
36, 30, 45]  
last guess: ['M', 'M', 'A', 'L', 'L', 'M', 'M', 'M', 'M', 'G', 'M', 'M', 'M',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['.', '.', 'A', 'L', 'L', '.', 'M', '.', '.', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: XPVDHKTNKOYAXKYTDYFK  
next guess: ['N', 'N', 'A', 'L', 'L', 'N', 'M', 'N', 'N', 'G', 'N', 'M', 'N',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'42 50 31 34 30 29 45 52 29 44 41 38 42 47 34 36 27 29 47 46\n'  
access denied received  
countarr: [10, 50, 5, 8, 4, 29, 7, 52, 29, 8, 41, 12, 42, 5, 8, 10, 1, 29, 5,
6]  
last_arr: [42, 50, 31, 34, 30, 29, 45, 52, 29, 44, 41, 38, 42, 47, 34, 36, 27,
29, 47, 46]  
last guess: ['N', 'N', 'A', 'L', 'L', 'N', 'M', 'N', 'N', 'G', 'N', 'M', 'N',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', '.', 'A', 'L', 'L', '.', 'M', '.', '.', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: UTNZOPHGKFLWKCWYJOGS  
next guess: ['N', 'O', 'A', 'L', 'L', 'O', 'M', 'O', 'O', 'G', 'O', 'M', 'O',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'45 47 39 38 49 51 31 34 30 27 29 42 30 29 36 31 47 39 46 38\n'  
access denied received  
countarr: [7, 47, 13, 12, 3, 51, 5, 34, 30, 1, 29, 10, 30, 3, 10, 5, 5, 13, 6,
12]  
last_arr: [45, 47, 39, 38, 49, 51, 31, 34, 30, 27, 29, 42, 30, 29, 36, 31, 47,
39, 46, 38]  
last guess: ['N', 'O', 'A', 'L', 'L', 'O', 'M', 'O', 'O', 'G', 'O', 'M', 'O',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', '.', 'A', 'L', 'L', '.', 'M', '.', '.', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: PUWPGIIJKNYCPGETUTAI  
next guess: ['N', 'P', 'A', 'L', 'L', 'P', 'M', 'P', 'P', 'G', 'P', 'M', 'P',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'50 47 30 48 31 33 30 32 31 45 43 36 52 51 28 36 36 34 52 48\n'  
access denied received  
countarr: [2, 47, 4, 4, 5, 33, 4, 32, 31, 7, 43, 10, 52, 1, 2, 10, 10, 8, 0,
4]  
last_arr: [50, 47, 30, 48, 31, 33, 30, 32, 31, 45, 43, 36, 52, 51, 28, 36, 36,
34, 52, 48]  
last guess: ['N', 'P', 'A', 'L', 'L', 'P', 'M', 'P', 'P', 'G', 'P', 'M', 'P',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', '.', 'A', 'L', 'L', '.', 'M', '.', '.', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: JLECQGCTTKTQTTITIFWI  
next guess: ['N', 'Q', 'A', 'L', 'L', 'Q', 'M', 'Q', 'Q', 'G', 'Q', 'M', 'Q',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'30 31 48 35 47 36 36 49 49 48 49 48 49 38 50 36 48 48 30 48\n'  
access denied received  
countarr: [4, 5, 48, 9, 5, 36, 10, 49, 49, 48, 49, 48, 49, 12, 2, 10, 48, 48,
4, 48]  
last_arr: [30, 31, 48, 35, 47, 36, 36, 49, 49, 48, 49, 48, 49, 38, 50, 36, 48,
48, 30, 48]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'Q', 'M', 'Q', 'Q', 'G', 'Q', 'M', 'Q',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', '.', 'M', '.', '.', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: JTWKAGWVXXPZZJTYACPK  
next guess: ['N', 'Q', 'A', 'L', 'L', 'R', 'M', 'R', 'R', 'G', 'R', 'M', 'R',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'30 49 30 27 37 37 42 48 46 35 28 39 44 48 39 31 30 51 37 46\n'  
access denied received  
countarr: [4, 3, 4, 1, 11, 37, 10, 48, 46, 9, 28, 13, 44, 4, 13, 5, 4, 1, 11,
6]  
last_arr: [30, 49, 30, 27, 37, 37, 42, 48, 46, 35, 28, 39, 44, 48, 39, 31, 30,
51, 37, 46]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'R', 'M', 'R', 'R', 'G', 'R', 'M', 'R',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', '.', 'M', '.', '.', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: RIOADHJYUMSEQEQHYINA  
next guess: ['N', 'Q', 'A', 'L', 'L', 'S', 'M', 'S', 'S', 'G', 'S', 'M', 'S',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'48 34 38 37 34 37 29 46 50 46 52 34 28 27 42 48 32 45 39 30\n'  
access denied received  
countarr: [4, 8, 12, 11, 8, 37, 3, 46, 50, 6, 52, 8, 28, 1, 10, 4, 32, 7, 13,
4]  
last_arr: [48, 34, 38, 37, 34, 37, 29, 46, 50, 46, 52, 34, 28, 27, 42, 48, 32,
45, 39, 30]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'S', 'M', 'S', 'S', 'G', 'S', 'M', 'S',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', '.', 'M', '.', '.', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: IDARSXCJNWHVHUWXKJMW  
next guess: ['N', 'Q', 'A', 'L', 'L', 'T', 'M', 'T', 'T', 'G', 'T', 'M', 'T',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'31 39 52 46 45 48 36 36 32 36 38 43 38 37 36 32 46 44 40 34\n'  
access denied received  
countarr: [31, 39, 52, 46, 45, 48, 36, 36, 32, 36, 38, 43, 38, 37, 36, 32, 46,
44, 40, 34]  
last_arr: [31, 39, 52, 46, 45, 48, 36, 36, 32, 36, 38, 43, 38, 37, 36, 32, 46,
44, 40, 34]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'T', 'M', 'T', 'T', 'G', 'T', 'M', 'T',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', '.', 'M', '.', '.', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: XHVPRKWNZXPVJCKCKCHV  
next guess: ['N', 'Q', 'A', 'L', 'L', 'U', 'M', 'U', 'U', 'G', 'U', 'M', 'U',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'42 35 31 48 46 36 42 33 47 35 31 43 37 29 48 27 46 51 45 35\n'  
access denied received  
countarr: [10, 9, 5, 48, 6, 36, 42, 33, 47, 9, 31, 9, 37, 3, 48, 1, 6, 1, 7,
35]  
last_arr: [42, 35, 31, 48, 46, 36, 42, 33, 47, 35, 31, 43, 37, 29, 48, 27, 46,
51, 45, 35]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'U', 'M', 'U', 'U', 'G', 'U', 'M', 'U',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', '.', 'M', '.', '.', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: QROMPZUXYKSOWFFYADXL  
next guess: ['N', 'Q', 'A', 'L', 'L', 'V', 'M', 'V', 'V', 'G', 'V', 'M', 'V',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'49 51 38 51 48 48 44 50 49 48 29 50 51 52 27 31 30 50 29 45\n'  
access denied received  
countarr: [3, 1, 12, 1, 4, 48, 8, 50, 49, 4, 29, 2, 51, 0, 1, 5, 4, 2, 3, 7]  
last_arr: [49, 51, 38, 51, 48, 48, 44, 50, 49, 48, 29, 50, 51, 52, 27, 31, 30,
50, 29, 45]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'V', 'M', 'V', 'V', 'G', 'V', 'M', 'V',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', '.', 'M', '.', '.', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: BYSSWVMVVEFWYQSDFVAJ  
next guess: ['N', 'Q', 'A', 'L', 'L', 'W', 'M', 'W', 'W', 'G', 'W', 'M', 'W',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'38 44 34 45 41 27 52 27 27 28 43 42 50 41 40 52 51 32 52 47\n'  
access denied received  
countarr: [12, 8, 8, 7, 11, 27, 52, 27, 27, 2, 43, 10, 50, 11, 12, 0, 1, 6,
52, 5]  
last_arr: [38, 44, 34, 45, 41, 27, 52, 27, 27, 28, 43, 42, 50, 41, 40, 52, 51,
32, 52, 47]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'W', 'M', 'W', 'W', 'G', 'W', 'M', 'W',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', '.', 'M', '.', '.', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: KAIHAOBVTIXGOOLDCEIG  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'X', 'X', 'G', 'X', 'M', 'X',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'29 42 44 30 37 35 37 28 30 50 52 32 35 43 47 52 28 49 44 50\n'  
access denied received  
countarr: [3, 10, 8, 4, 11, 9, 11, 28, 30, 2, 52, 6, 35, 9, 5, 0, 2, 3, 8, 2]  
last_arr: [29, 42, 44, 30, 37, 35, 37, 28, 30, 50, 52, 32, 35, 43, 47, 52, 28,
49, 44, 50]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'X', 'X', 'G', 'X', 'M', 'X',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', '.', '.', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: QKAHSKXYJVSFGJBCGEQK  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Y', 'Y', 'G', 'Y', 'M', 'Y',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'49 32 52 30 45 39 41 52 41 37 32 33 44 48 31 27 50 49 36 46\n'  
access denied received  
countarr: [3, 6, 0, 4, 7, 13, 11, 52, 11, 11, 32, 7, 44, 4, 5, 1, 2, 3, 10, 6]  
last_arr: [49, 32, 52, 30, 45, 39, 41, 52, 41, 37, 32, 33, 44, 48, 31, 27, 50,
49, 36, 46]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Y', 'Y', 'G', 'Y', 'M', 'Y',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', '.', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: STXJRZWTKUFZCULJCVVI  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Z', 'M', 'Z',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'47 49 29 28 46 50 42 32 40 38 46 39 49 37 47 46 28 32 31 48\n'  
access denied received  
countarr: [5, 3, 3, 28, 6, 2, 10, 6, 12, 12, 46, 13, 49, 11, 5, 6, 28, 6, 5,
4]  
last_arr: [47, 49, 29, 28, 46, 50, 42, 32, 40, 38, 46, 39, 49, 37, 47, 46, 28,
32, 31, 48]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Z', 'M', 'Z',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: BLPFVFRHGCUPEZCFVRHX  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'A', 'M', 'A',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'38 31 37 32 42 44 47 44 44 30 32 49 48 32 30 50 35 36 45 33\n'  
access denied received  
countarr: [12, 31, 11, 6, 10, 8, 5, 8, 8, 4, 32, 3, 48, 6, 4, 2, 35, 10, 7, 7]  
last_arr: [38, 31, 37, 32, 42, 44, 47, 44, 44, 30, 32, 49, 48, 32, 30, 50, 35,
36, 45, 33]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'A', 'M', 'A',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: QYXYGOFJBMIPIDQJQEPE  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'B', 'M', 'B',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'49 44 29 39 31 35 33 42 49 46 45 49 45 28 42 46 40 49 37 52\n'  
access denied received  
countarr: [3, 8, 3, 13, 5, 9, 7, 10, 3, 6, 45, 3, 45, 2, 10, 6, 12, 3, 11, 0]  
last_arr: [49, 44, 29, 39, 31, 35, 33, 42, 49, 46, 45, 49, 45, 28, 42, 46, 40,
49, 37, 52]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'B', 'M', 'B',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: CRMPIFZWDUMGSKVQHWQS  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'C', 'M', 'C',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'37 51 40 48 29 44 39 29 47 38 42 32 36 47 37 39 49 31 36 38\n'  
access denied received  
countarr: [11, 1, 12, 4, 3, 8, 13, 3, 5, 12, 42, 6, 36, 5, 11, 13, 3, 31, 10,
12]  
last_arr: [37, 51, 40, 48, 29, 44, 39, 29, 47, 38, 42, 32, 36, 47, 37, 39, 49,
31, 36, 38]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'C', 'M', 'C',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: KMQEKXHPQCWGELIHGFZR  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'D', 'M', 'D',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'29 30 36 33 27 52 31 36 34 30 33 32 51 46 50 48 50 48 27 39\n'  
access denied received  
countarr: [3, 30, 10, 7, 1, 0, 5, 10, 8, 4, 33, 6, 51, 6, 2, 4, 2, 4, 1, 13]  
last_arr: [29, 30, 36, 33, 27, 52, 31, 36, 34, 30, 33, 32, 51, 46, 50, 48, 50,
48, 27, 39]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'D', 'M', 'D',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: RQCLYXMSVGVTGGRIEACZ  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'E', 'M', 'E',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'48 52 50 52 39 52 52 33 29 52 35 45 50 51 41 47 52 27 50 31\n'  
access denied received  
countarr: [4, 0, 2, 0, 13, 52, 52, 7, 3, 52, 35, 7, 50, 1, 11, 5, 0, 1, 2, 5]  
last_arr: [48, 52, 50, 52, 39, 52, 52, 33, 29, 52, 35, 45, 50, 51, 41, 47, 52,
27, 50, 31]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'E', 'M', 'E',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: TDMFINOWVHCOVAWVCJKN  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'F', 'M', 'F',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'46 39 40 32 29 36 50 29 29 51 29 50 36 31 36 34 28 44 42 43\n'  
access denied received  
countarr: [6, 13, 12, 6, 3, 10, 2, 29, 3, 1, 29, 2, 36, 5, 10, 8, 2, 8, 10, 9]  
last_arr: [46, 39, 40, 32, 29, 36, 50, 29, 29, 51, 29, 50, 36, 31, 36, 34, 28,
44, 42, 43]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'F', 'M', 'F',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: LTEWJWSYLXXAJHKULIXO  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'G', 'M', 'G',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'28 49 48 41 28 27 46 27 39 35 35 38 49 50 48 35 45 45 29 42\n'  
access denied received  
countarr: [2, 3, 4, 11, 2, 1, 6, 1, 13, 9, 35, 12, 49, 2, 4, 9, 7, 7, 3, 10]  
last_arr: [28, 49, 48, 41, 28, 27, 46, 27, 39, 35, 35, 38, 49, 50, 48, 35, 45,
45, 29, 42]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'G', 'M', 'G',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: PUTHLXYRPOEMKZPZIDIM  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'H', 'M', 'H',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'50 48 33 30 52 52 40 34 35 44 29 52 49 32 43 30 48 50 44 44\n'  
access denied received  
countarr: [2, 4, 7, 4, 0, 0, 12, 8, 9, 8, 29, 0, 49, 6, 9, 30, 4, 2, 8, 8]  
last_arr: [50, 48, 33, 30, 52, 52, 40, 34, 35, 44, 29, 52, 49, 32, 43, 30, 48,
50, 44, 44]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'H', 'M', 'H',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: UGJHKZKCLYJAFDMSICTY  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'I', 'M', 'I',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'45 36 43 30 27 50 28 49 39 34 51 38 29 28 46 37 48 51 33 32\n'  
access denied received  
countarr: [7, 10, 9, 4, 1, 2, 2, 3, 13, 8, 51, 12, 29, 2, 6, 11, 4, 1, 7, 32]  
last_arr: [45, 36, 43, 30, 27, 50, 28, 49, 39, 34, 51, 38, 29, 28, 46, 37, 48,
51, 33, 32]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'I', 'M', 'I',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: ARGGCRZRCOJXEGWFKEQH  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'J', 'M', 'J',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'39 51 46 31 35 32 39 34 48 44 52 41 31 51 36 50 46 49 36 49\n'  
access denied received  
countarr: [13, 1, 6, 5, 9, 6, 13, 8, 4, 8, 52, 11, 31, 1, 10, 2, 6, 3, 10, 3]  
last_arr: [39, 51, 46, 31, 35, 32, 39, 34, 48, 44, 52, 41, 31, 51, 36, 50, 46,
49, 36, 49]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'J', 'M', 'J',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: XUMOORKOFPYOQDWGDMGV  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'K', 'M', 'K',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'42 48 40 49 49 32 28 37 45 43 38 50 46 28 36 49 27 41 46 35\n'  
access denied received  
countarr: [10, 4, 12, 3, 3, 6, 2, 11, 7, 9, 38, 2, 46, 2, 10, 3, 1, 11, 6, 9]  
last_arr: [42, 48, 40, 49, 49, 32, 28, 37, 45, 43, 38, 50, 46, 28, 36, 49, 27,
41, 46, 35]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'K', 'M', 'K',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: UCYZZCIREVPTIOITGTXA  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'L', 'M', 'L',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'45 40 28 38 38 47 30 34 46 37 48 45 29 43 50 36 50 34 29 30\n'  
access denied received  
countarr: [7, 12, 2, 12, 12, 5, 4, 8, 6, 11, 48, 7, 29, 9, 2, 10, 2, 8, 3, 4]  
last_arr: [45, 40, 28, 38, 38, 47, 30, 34, 46, 37, 48, 45, 29, 43, 50, 36, 50,
34, 29, 30]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'L', 'M', 'L',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: UPRILATVBDMPOJWQSQCL  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'M', 'M', 'M',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'45 27 35 29 52 49 45 30 49 29 52 49 50 48 36 39 38 37 50 45\n'  
access denied received  
countarr: [7, 1, 9, 3, 0, 3, 7, 4, 3, 3, 52, 3, 50, 4, 10, 13, 12, 11, 2, 7]  
last_arr: [45, 27, 35, 29, 52, 49, 45, 30, 49, 29, 52, 49, 50, 48, 36, 39, 38,
37, 50, 45]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'M', 'M', 'M',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: QSYQMTMTEBJHQJIJKTQO  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'N', 'M', 'N',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'49 50 28 47 51 30 52 32 46 31 30 31 49 48 50 46 46 34 36 42\n'  
access denied received  
countarr: [3, 2, 2, 5, 1, 4, 0, 6, 6, 5, 30, 5, 49, 4, 2, 6, 6, 8, 10, 10]  
last_arr: [49, 50, 28, 47, 51, 30, 52, 32, 46, 31, 30, 31, 49, 48, 50, 46, 46,
34, 36, 42]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'N', 'M', 'N',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: KRIQQVMAYHEMWZTKMCIR  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'O', 'M', 'O',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'29 51 44 47 47 28 52 51 52 51 36 52 44 32 39 45 44 51 44 39\n'  
access denied received  
countarr: [3, 1, 8, 5, 5, 2, 0, 1, 0, 1, 36, 0, 44, 6, 13, 7, 8, 1, 8, 13]  
last_arr: [29, 51, 44, 47, 47, 28, 52, 51, 52, 51, 36, 52, 44, 32, 39, 45, 44,
51, 44, 39]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'O', 'M', 'O',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: MEYNEEQFMJOZMVBMGXBO  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'P', 'M', 'P',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'27 38 28 50 33 45 48 46 38 49 27 39 29 36 31 43 50 30 51 42\n'  
access denied received  
countarr: [1, 12, 28, 2, 7, 7, 4, 6, 12, 3, 27, 13, 29, 10, 5, 9, 2, 4, 1, 10]  
last_arr: [27, 38, 28, 50, 33, 45, 48, 46, 38, 49, 27, 39, 29, 36, 31, 43, 50,
30, 51, 42]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'P', 'M', 'P',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', '.', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: SQQJGCFAJGSXCKNMSTZF  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Q', 'M', 'Q',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'47 52 36 28 31 47 33 51 41 52 50 41 40 47 45 43 38 34 27 51\n'  
access denied received  
countarr: [5, 0, 10, 2, 5, 5, 7, 1, 11, 0, 2, 11, 40, 5, 7, 9, 12, 8, 1, 1]  
last_arr: [47, 52, 36, 28, 31, 47, 33, 51, 41, 52, 50, 41, 40, 47, 45, 43, 38,
34, 27, 51]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Q', 'M', 'Q',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Q', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: PLWSPCSGNWWSYWZHYNZH  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Q', 'M', 'R',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'50 31 30 45 48 47 46 45 37 36 46 46 45 35 33 48 32 40 27 49\n'  
access denied received  
countarr: [2, 5, 4, 7, 4, 5, 6, 7, 11, 10, 6, 6, 45, 9, 7, 4, 6, 12, 1, 3]  
last_arr: [50, 31, 30, 45, 48, 47, 46, 45, 37, 36, 46, 46, 45, 35, 33, 48, 32,
40, 27, 49]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Q', 'M', 'R',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Q', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: BSZNXYSAFBUCZHHSFRBI  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Q', 'M', 'S',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'38 50 27 50 40 51 46 51 45 31 48 36 45 50 51 37 51 36 51 48\n'  
access denied received  
countarr: [12, 2, 1, 2, 12, 51, 6, 51, 7, 5, 4, 10, 45, 2, 51, 11, 51, 10, 51,
4]  
last_arr: [38, 50, 27, 50, 40, 51, 46, 51, 45, 31, 48, 36, 45, 50, 51, 37, 51,
36, 51, 48]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Q', 'M', 'S',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Q', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: XRUIMANZZROWXCAHUOYP  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Q', 'M', 'T',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'42 51 32 29 51 49 51 52 51 41 28 42 48 29 32 48 36 39 28 41\n'  
access denied received  
countarr: [10, 1, 6, 3, 1, 3, 1, 0, 1, 11, 2, 10, 48, 3, 6, 4, 10, 13, 2, 11]  
last_arr: [42, 51, 32, 29, 51, 49, 51, 52, 51, 41, 28, 42, 48, 29, 32, 48, 36,
39, 28, 41]  
last guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Q', 'M', 'T',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
new solved: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Q', 'M', '.',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
start: SFTXQXQEXCPHVACPJHVL  
next guess: ['N', 'Q', 'A', 'L', 'L', 'X', 'M', 'Z', 'Y', 'G', 'Q', 'M', 'U',
'F', 'G', 'D', 'E', 'B', 'A', 'E']  
Sending: b'47 37 33 40 47 52 48 47 27 30 27 31 51 31 30 40 47 46 31 45\n'

real    31m36.648s  
user    10m22.319s  
sys     0m2.599s  
~/aotw$ tail -n 15 challenge1.out

Contents:

AOTW{Should_have_us3d_the_bl0ckchain!}

Santa's Vault  
=============

Contents:

```

Original writeup
(https://github.com/nononovak/otwadvent2018-ctfwriteup/blob/master/day1.md).