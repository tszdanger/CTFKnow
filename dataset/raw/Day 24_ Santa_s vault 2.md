# Santa's vault 2 - Misc (200)

With Christmas only a day away, Santa must take security very seriously. You
broke all the other locks, can you break this one?

Service: nc 3.81.191.176 1224

## Triage

Connecting you're presented with some ASCII art and instructions:

```  
instructions:  
 Use '1' to '8' to alter the values on the locks or '0' to reset. When  
 the locks are lined up to the target value you will advance by 1 round.  
 Make it through 50 rounds to get a special present.

round 0/50:  
+-----------------------------------------------------------------------+  
| values:    601    551    591    548    636    460    641    464       |  
| target:    746    746    746    746    746    746    746    746       |  
+-----------------------------------------------------------------------+  
```

The 'values' and 'target' change each time you connect so this is going to
have to be some sort of automated script for a solution. There's no tricky
business here - its really just a dynamic programming problem interacting with
a web service. Entering 1-8 adds different amounts to each of the 'values'.

## Solution

My generic approach to solve this was:

* write a program to repeat once for each round  
* at the beginning of the round, write 1-8 to see how much each number adds to the 'values'  
* once i've collected all the value arrays, reset with 0  
* write a dynamic function to determine how many of each 1-8 value will be reqired to add up each of the values to the target

There isn't much else to say about how this problem works so I'll just give my
python code:

```python  
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
			if len(match.group(1)) == 0:  
				arr.append((0,0))  
			else:  
				arr.append(tuple(int(x) for x in match.group(1).split(';')))  
		last_end = end  
	if last_end != len(data):  
		arr.append(data[last_end:])  
	return arr

def text_from_ansi(arr):  
	return ''.join([x for x in arr if type(x) == str])

def get_values(buf):  
	pat_str = 'values:'+'\s+([-\d]+)'*8+'\s+\|\s\|\s+target:' + '\s+([-\d]+)'*8+'\s+\|'  
	pat = re.compile(pat_str,re.DOTALL)  
	match = re.search(pat,buf)  
	values = [int(match.group(i)) for i in range(1,9)]  
	target = [int(match.group(i)) for i in range(9,17)]  
	return values,target

global_values_target = {}  
def solve_values_target(diff_tuple,round_values,next_value=1):  
	global global_values_target

	if next_value >= 9:  
		return None

	if (diff_tuple,next_value) in global_values_target:  
		return global_values_target[diff_tuple,next_value]

	if min(diff_tuple) == 0 and max(diff_tuple) == 0:  
		return []

	for i in range(10):  
		if max(diff_tuple) == 0:  
			global_values_target[diff_tuple,next_value] = [i]  
			return global_values_target[diff_tuple,next_value]  
		ret = solve_values_target(diff_tuple,round_values,next_value+1)  
		if ret is not None:  
			global_values_target[diff_tuple,next_value] = [i]+ret  
			return global_values_target[diff_tuple,next_value]  
		diff_tuple = tuple((diff_tuple[j]-round_values[next_value][j]) for j in range(8))  
		if min(diff_tuple) < 0:  
			break  
	return None

def shell(s):

	full_outp = b''  
	awaiting_input = '\n+-----------------------------------------------------------------------+\n'

	start_round = True  
	round_values = [None] * 9  
	last_sent_round = 0  
	last_values = None  
	start_answer = False  
	answer = None

	while True:  
		outp = s.recv(1024)  
		if not outp:  
			# EOF  
			#return  
			print('recv error')  
			break  
		full_outp = full_outp + outp

		try:  
			arr = chunk_ansi(full_outp.decode('utf-8'))  
			buf = text_from_ansi(arr)  
		except:  
			continue

		if buf.endswith(awaiting_input) and type(answer) == list:

			if len(answer) == 0:  
				print(buf, flush=True)  
				print('next round ...')  
				print('send',0)  
				s.send(b'0\n')  
				full_outp = b''  
				start_round = True  
				round_values = [None] * 9  
				last_sent_round = 0  
				last_values = None  
				start_answer = False  
				answer = None  
				continue  
			else:  
				print('send', answer[0])  
				s.send(b'%d\n'%answer[0])  
				answer = answer[1:]  
				full_outp = b''  
				continue

		if buf.endswith(awaiting_input) and start_answer:

			values,target = get_values(buf)  
			print(values)  
			print(target)  
			print(round_values)  
			diff = [target[i]-values[i] for i in range(8)]  
			print(diff)

			global global_values_target  
			global_values_target = {}  
			ans = solve_values_target(tuple(diff),round_values)  
			ans = ans + [0]*(8-len(ans))  
			print(ans)  
			answer = []  
			for i in range(8):  
				answer = answer + [i+1] * ans[i]  
			print('answer:',answer)

			print('send',answer[0])  
			s.send(b'%d\n'%answer[0])  
			answer = answer[1:]  
			full_outp = b''  
			continue

		if buf.endswith(awaiting_input) and last_sent_round == 8:  
			next_values,target = get_values(buf)  
			values = [next_values[i]-last_values[i] for i in range(8)]  
			round_values[last_sent_round] = values  
			print(round_values)  
			print('send', 0)  
			s.send(b'0\n')  
			full_outp = b''  
			start_answer = True  
			continue

		if buf.endswith(awaiting_input) and last_sent_round > 0:  
			next_values,target = get_values(buf)  
			values = [next_values[i]-last_values[i] for i in range(8)]  
			last_values = next_values  
			round_values[last_sent_round] = values  
			last_sent_round += 1  
			print('send', last_sent_round)  
			s.send(b'%d\n'%last_sent_round)  
			full_outp = b''  
			continue

		if buf.endswith(awaiting_input) and start_round:  
			start_round = False  
			last_values,target = get_values(buf)  
			last_sent_round = 1  
			print('send', 1)  
			s.send(b'1\n')  
			full_outp = b''  
			continue

	print(full_outp)

if __name__ == '__main__':

	s = socket.socket()  
	s.settimeout(5)  
	s.connect(('3.81.191.176', 1224))  
	print(s)  
	shell(s)

```

For some reason this script fails out every so often. But running it a couple
times and waiting all 50 rounds yields the solution:

```  
Congratulations, here is your flag:  
AOTW{M3rRy_cHr1sTm4S_aNd_a_H4PpY_n3W_y34R}  
```  

Original writeup
(https://github.com/nononovak/otwadvent2018-ctfwriteup/blob/master/day24.md).