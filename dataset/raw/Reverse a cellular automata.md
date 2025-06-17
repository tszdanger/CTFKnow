> Cellular Automata  
>  
> 148  
>  
> It's hard to reverse a step in a cellular automata, but solvable if done
> right.  
>  
> https://cellularautomata.web.ctfcompetition.com/

As the [rules](https://cellularautomata.web.ctfcompetition.com/) state we are
dealing with a [Rule 126 automata](http://mathworld.wolfram.com/Rule126.html).
Patterns ```000``` and ```111``` produce a ```0``` bit while all others
produce ```1```.

The problem with reversing cellular automata is that a lot of different steps
correspond to the step you are trying to reverse. Straight bruteforcing will
take forever - 64-bit steps are just too bit. However, the bits in the reverse
step are not random, and are limited by 2 rules:

1. ```0``` has to reverse to patterns ```000``` or ```111```, and ```1``` to all others  
2. If a pattern is selected the patterns that follow it are limited to 2 possibilities (because they have to overlap by 2 bits). For example, pattern ```000``` can only be followed by patterns ```000``` and ```001```.

If we apply these 2 rules we can generate all possibilities very quickly with
the help of the following script:

```python  
import sys

if len(sys.argv) != 2:  
	print "Please supply a hex number on the command line"  
	quit()  
  
hexval = sys.argv[1]  
bit_size = len(hexval)*4

# convert hex value to bit string  
bitstr = (bin(int(hexval,16))[2:]).zfill(bit_size)

# map from bits to patterns that generate it  
patterns_generating_bit = {"0":[0,7], "1":[1,2,3,4,5,6]}

# valid patterns that can follow each pattern; for example, pattern 010 can be
followed  
#  only by 100 and 101 because they must overlap with its last 2 digits (10)  
valid_next_patterns = {0:[0,1], 1:[2,3], 2:[4,5], 3:[6,7], 4:[0,1], 5:[2,3],
6:[4,5], 7:[6,7]}

# mid bits in each pattern  
pattern_mid_bits = {0:"0", 1:"0", 2:"1", 3:"1", 4:"0", 5:"0", 6:"1", 7:"1"}

def reverse_rule126(bitstr, depth, valid_patterns, patterns_in_step):  
  
	# walk through all patterns that generate the current bit  
	for pattern in patterns_generating_bit[bitstr[depth]]:  
		# make sure the pattern is valid based on previously seen patterns  
		if pattern in valid_patterns:   
  
			# if we are not at the last bit - keep going recursively  
			if depth < (bit_size-1):  
				reverse_rule126(bitstr, depth+1, valid_next_patterns[pattern], patterns_in_step+[pattern])

			# if we are at the last bit...  
			if depth == (bit_size-1):  
				# ...and the last pattern wraps around properly to the beginning of the step string   
				if patterns_in_step[0] in valid_next_patterns[pattern]:  
  
					# generate the full bitstring for the step and print it out  
					found_step = ""  
					for x in patterns_in_step:  
						found_step += pattern_mid_bits[x]  
					found_step += pattern_mid_bits[pattern]  
  
					print hex(int(found_step,2))[2:]

reverse_rule126(bitstr, 0, [0,1,2,3,4,5,6,7], [])  
```

The script generates about 10K possibilities, which we can try to determine if
there is a flag in the output:

```bash  
#!/bin/sh

for i in $(python solve.py 66de3c1bf87fdfcf); do  
   echo "$i" > /tmp/plain.key; xxd -r -p /tmp/plain.key > /tmp/enc.key  
   echo
"U2FsdGVkX1/andRK+WVfKqJILMVdx/69xjAzW4KUqsjr98GqzFR793lfNHrw1Blc8UZHWOBrRhtLx3SM38R1MpRegLTHgHzf0EAa3oU  
eWcQ=" | openssl enc -d -aes-256-cbc -pbkdf2 -md sha1 -base64 --pass file:/tmp/enc.key 2>/dev/null | grep CTF  
done

```

When we run the script we quickly get the flag decoded:

```sh  
$ ./solve.sh  
CTF{reversing_cellular_automatas_can_be_done_bit_by_bit}  
```

The flag is ```CTF{reversing_cellular_automatas_can_be_done_bit_by_bit}```.

Original writeup (https://0xd13a.github.io/ctfs/gctf2019/cellular-automata/).