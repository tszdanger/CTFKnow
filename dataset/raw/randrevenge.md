### Overview

Both can be solved with this solution. The servers sends a timestamp and a few
random numbers. The goal is to send back the next number in the sequence.

### Idea

The sequence starts with the very first number after a random seed is set, so
we can narrow the search space to seeds that start with it. After getting a
few candidates, it is possible to check if the other numbers match by using
the provided algorithm. The server doesn't have rate limiting, so we can check
just a subset of random seeds and request another batch of numbers if none
fit.

### Solution

Step 1: Dump a few pairs of (seed, first_random_number) in a file

```  
"

d = {}

i = 0

with open('data.csv') as csvfile:

   spamreader = csv.reader(csvfile)

   for row in spamreader:  
       i+=1  
       # check if in dict  
       if i == 20796091:  
           break  
       if row[0] in d:  
           d[row[0]].append(row[1])  
       else:  
           d[row[0]] = [row[1]]  
           z = row[0]

print(f"Loaded {i} lines")

while True:  
   r = requests.post(url)  
   data = r.text.split("\\n")

   data[0] # time  
   leak = data[1]

   if leak in d:  
       number = os.popen(f"php a.php {len(d[leak])} {' '.join(d[leak])} {' '.join(data[:-2])}").read()

       print(f"Number: {number}")

       cookies = r.cookies

       r = requests.post(url+"submit", data={"next": number}, cookies=cookies)  
       print(r.text)  
       if "ENO" in r.text:  
           exit()

```

## Flags

`ENO{M4sT3r_0f_R4nd0n0m1c5}` - randrevenge  
`ENO{PHD_1N_TrU3_R4nd0n0m1c5_516189}` - randrevengerevenge