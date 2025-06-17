# The Most Worthy Distinction of Pain

###### writeup by [phishfood](https://ctftime.org/user/136455)

## Challenge

We intercepted a code (`encrypted.txt`).

Yeah, so, this is a lot of nonsense. It's mostly words that start with d, but
at least we know how it was created? (`encrypt.go`)

We also know where the dictionary file came from
([CROSSWD.TXT](https://www.gutenberg.org/files/3201/files/CROSSWD.TXT))

Note: The `CROSSWD.TXT` file can be verified with an md5 hash of
`e58eb7b851c2e78770b20c715d8f8d7b`. It starts with 1st word `aa`, and ends
with the 113809th word `zymurgy`.

[encrypted.txt](https://raw.githubusercontent.com/danieltaylor/ctf-
writeups/main/byuctf-22/themostworthydistinctionofpain/encrypted.txt)

[encrypt.go](https://raw.githubusercontent.com/danieltaylor/ctf-
writeups/main/byuctf-22/themostworthydistinctionofpain/encrypt.go)

## Solution

### Starting Out

The first step is of course to take a look at the provided encrypted text, as
well as the code that encrypted it.

`encrypted.txt` appears as follows:

```  
depaints dexterous dilution droseras dissecting driveways depaints droughtier
diluted demigods diluter beefing dogey dogfights diligently dusky beefing
dogey dogfights desand beefing dilution duenna ditto duenna dockworkers
departments dislocates drawbars beefing dogey dogfights diligently dusky
beefiest eloigned demigods deteriorations edge defecation deadpanned dits
diluted des detentes dementing desanded duelling demes deodorizing deafnesses
devotees combusting capitalists embruting beefing dogey dogfights diligently
dusky beefing dogey dogfights duskier beefing dogey dogfights desand doweling
derangements departments dislocates drawbars disprized depaints demigods
decrypted  
```

I won't include all of `encrypt.go` here, but I will point out two aspects
that are important to note:

1. The `readFlag` function reads in a file titled `flag.txt`, which can be presumed to be the plaintext of the ciphertext we are trying to decrypt:

	```go  
	func readFlag() (string, error) {  
		flag_file, err := os.Open("flag.txt")  
		if err != nil {  
			return "", err  
		}  
		defer flag_file.Close()  
		scanner := bufio.NewScanner(flag_file)  
		scanner.Scan()  
		flag := scanner.Text()  
		return flag, nil  
	}  
	```

2. The `encrypt` function requires a file titled `CROSSWD.TXT` in order to function:

	```go  
	func encrypt(flag string) string {  
		codex_file, err := os.Open("CROSSWD.TXT")  
		if err != nil {  
			return "!"  
		}  
		defer codex_file.Close()  
		all_words := []string{}  
		combined := combine([]uint8(flag))  
		for _, c := range combined {  
			all_words = append(all_words, encode_one(c, codex_file))  
		}  
		return strings.Join(all_words, " ")  
	}  
	```

We will therefore need to add the files `flag.txt` and `CROSSWD.TXT` to the
same directory as `encrypt.go`.

`CROSSWD.TXT` can be downloaded from the link provided in the problem
description with the following command:

```sh  
curl -O https://www.gutenberg.org/files/3201/files/CROSSWD.TXT  
```

`flag.txt` should be added manually.  Since we don't know what it contained
originally, I'll be trying some different inputs to get an idea of how the
encryption algorithm works.

### Testing Inputs

I began by running some different sample inputs through `encrypt.go` to get an
idea of the encryption scheme. This can be done by creating a file named
`flag.txt` containing plaintext and adding it to the working directory. Here
is an approximate outline of some inputs (plaintexts) I tried, along with
their outputs (ciphertexts) and what can be learned from them:

1. `a` > `decrypted`  
2. `a` > `decrypted` (again)  
	- The encryption algorithm is deterministic; repeating an input will always yield the same output.  
3. `ab` > `defat`  
	- Adding a second character results in an entirely different output than we might expect based on what we saw previously.  
	- *This doesn't bode well for a brute force solution, because it adds an element of unpredictability.*  
4. `abc` > `defat delineated`  
	- Adding a third character does not affect the expected result for `ab`.  
	- This suggests that each word in the ciphertext corresponds to two letters in the plaintext (or one if there are an odd number of characters).  
5. `abcdef` > `defat demeans des`  
	- Supports the previous assumption.  
6. `efabcd` > `des defat demeans`  
	- Changing the position of a two letter sequence does not affect its corresponding cipher word.  
7. `abdcef` > `defat deodorized des`  
	- Changing the position of a letter within its two letter sequence does affect the sequence's corresponding cipher word.  
8. `byuctf{` > `dei duros duendes emperor`  
	- The algorithm is capable of handling special characters.  
	- The the original contents of `flag.txt` did not begin with `byuctf{` as one may have expected.

#### TL;DR: Each word in the ciphertext corresponds to a pair of letters in
the plaintext.

Therefore, if we can determine which letter pairs get encoded to which cipher
words, we can decrypt the ciphertext.

### Cracking the Key

After determining the nature of the algorithm, I decided that I could probably
use an approach similar to how I solved [Copilot](https://github.com/BYU-CTF-
group/old-ctf-
challenges/blob/18c8f246756e79069c1cb1753c8bfea5e73e31f5/miscellaneous/copilot/README.md).
For Copilot, I built the plaintext one character at a time, trying each letter
in the alphabet until the resulting ciphertext matched the the provided
ciphertext up to that point.  The key difference for this challenge was that I
would need to build the plaintext two characters at a time rather than one.

While building the plaintext for Copilot, I had to try (up to) every possible
character for each corresponding number in the plaintext.  For Copilot, this
meant up to 100 tries for each number in the ciphertext that was decrypted.
(Python's `string.printable` includes 100 characters.) In this case, I will
want to be trying all possible *pairs* of letters for each word in the
ciphertext, which means up to 10,000 (100×100) tries for each word that is
decrypted.

Bruteforcing Copilot wasn't the speediest thing in the world, so doing
something that takes 100 times longer probably isn't a good option.  Luckily,
I can take advantage of a property in this challenge's encryption algorithm
that wasn't present in Copilot.  Since letter pairs always correspond to the
same word (see step 6 of [Testing Inputs](#Testing-Inputs)), regardless of
their position in the plaintext, it's possible to keep track of which words
correspond to which letters, and then just replace all occurrences of that
word with the corresponding letter pair. This takes us from generating up to
10,000 letter pairs per cipher word (up to 77,000 pairs in total) down to
exactly 10,000 letter pairs to crack the entire key!

Another advantage of letter pairs corresponding to the same word regardless of
position is that it means we can test multiple values at once.  In Copilot I
had to write one character to the input file, run `copilot.go`, and then see
how the change to the input affected the output.  This time, I can write a
bunch of letter pairs to the input file, run `encrypt.go`, and then match up
all the cipher words in the output file to their corresponding letter pairs.

I initially tried just writing every letter pair to the input file, but the
encryption script seemed to cut off the output after a certain length, so I
ended up doing it in parts.

Here is the portion of my code that builds the cipher key (with some
adjustments and added comments):

```python  
from string import printable  
import os

key = dict()

# a = first letter in the pair, b = second letter in the pair  
for a in printable:  
	# open the input (plaintext) file to write letter pairs to  
	input_file = open('flag.txt', 'w')

	# keep track of what letter pairs are written in a list so that they can be matched up with their corresponding cipher words later on  
	letter_pairs = []

	for b in printable:  
		input_file.write(a + b)  
		letter_pairs.append(a + b)

	input_file.close()

	# run the encryption script with the resulting ciphertext being written to ouptut.txt  
	os.system('go run encrypt.go > output.txt')

	# open output.txt and read the words into a list  
	output_file = open('output.txt', 'r')  
	words = output_file.read().split()  
	output_file.close()

	# match up each letter pair to the word it represents and store them in the key dictionary  
	for i in range(len(words)):  
		key[words[i]] = letter_pairs[i]

		# display progress—show which word corresponds to which pair of letters  
		print(words[i], '=', letter_pairs[i])  
```

Once the key is cracked, the ciphertext can be decrypted very quickly, as is
done in the following section of code:

```python  
from collections import deque

flag = ''  
ciphertext_words =  deque(['depaints', 'dexterous', 'dilution', 'droseras',
'dissecting', 'driveways', 'depaints', 'droughtier', 'diluted', 'demigods',
'diluter', 'beefing', 'dogey', 'dogfights', 'diligently', 'dusky', 'beefing',
'dogey', 'dogfights', 'desand', 'beefing', 'dilution', 'duenna', 'ditto',
'duenna', 'dockworkers', 'departments', 'dislocates', 'drawbars', 'beefing',
'dogey', 'dogfights', 'diligently', 'dusky', 'beefiest', 'eloigned',
'demigods', 'deteriorations', 'edge', 'defecation', 'deadpanned', 'dits',
'diluted', 'des', 'detentes', 'dementing', 'desanded', 'duelling', 'demes',
'deodorizing', 'deafnesses', 'devotees', 'combusting', 'capitalists',
'embruting', 'beefing', 'dogey', 'dogfights', 'diligently', 'dusky',
'beefing', 'dogey', 'dogfights', 'duskier', 'beefing', 'dogey', 'dogfights',
'desand', 'doweling', 'derangements', 'departments', 'dislocates', 'drawbars',
'disprized', 'depaints', 'demigods', 'decrypted'])

while len(ciphertext_words) != 0:  
	flag += key[ciphertext_words.popleft()]

print('!!! FLAG = ' + flag + ' !!!')  
```

In [my actual code](https://raw.githubusercontent.com/danieltaylor/ctf-
writeups/main/byuctf-22/themostworthydistinctionofpain/key_cracker.py), I
additionally printed the progress in decrypting the flag while the key was
being cracked, checking each time the key was updated to see if the next word
to appear in the ciphertext had been decoded.  That can be seen in the demo
below.

### Demo

![](https://raw.githubusercontent.com/danieltaylor/ctf-
writeups/main/byuctf-22/themostworthydistinctionofpain/key_cracker_demo.gif)  
*(While it would probably more exciting to watch this at 2x speed, I figured it would be more valuable to show it in realtime speed.)*