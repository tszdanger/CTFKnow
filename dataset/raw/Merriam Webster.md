# Merriam Webster Writeup  
### Writeup by nineluj

After connecting to the server you are asked to perform 500 tasks after which
you receive the flag. The first few tasks were in the same order but since
there so many to solve it was better to just use a while loop. The one trick
for this one was to realize that you should use `/usr/share/dict/words`
instead of downloading other word lists. Some people tried using the Merriam
Webster API but this approach is way too slow (1-2 seconds per request).

Code:  
```  
from pwn import remote, log

# Use a set for faster lookup  
dic_file = open('/usr/share/dict/words')  
dic_list = {s.lower()[:-1] for s in dic_file.readlines()}

def get_fake_list(wl):  
   return list(filter(lambda w: w not in dic_list, wl.split(" ")))

def get_real_list(wl):  
   return list(filter(lambda w: w in dic_list, wl.split(" ")))

funcs = {  
   ": Can you tell me how many words here are NOT real words?":  
       lambda wl: len(get_fake_list(wl)),  
   ": Can you tell me which words here are NOT real words IN CHRONOLOGICAL
ORDER? Separate each by a space.":  
       lambda wl: " ".join(get_fake_list(wl)),  
   ": Can you tell me which words here are NOT real words IN ALPHABETICAL
ORDER? Separate each by a space.":  
       lambda wl: " ".join(sorted(get_fake_list(wl))),  
   ": Can you tell me how many words here ARE real words?":  
       lambda wl: len(get_real_list(wl)),  
   ": Can you tell me which words here ARE real words IN CHRONOLOGICAL ORDER?
Separate each by a space.":  
       lambda wl: " ".join(get_real_list(wl)),  
   ": Can you tell me which words here ARE real words IN ALPHABETICAL ORDER?
Separate each by a space.":  
       lambda wl: " ".join(sorted(get_real_list(wl))),  
}

def main():  
   r = remote('jh2i.com', 50012)

   while True:  
       prompt = r.recvuntil("\n", drop=True).decode()  
       if prompt not in funcs:  
log.info(f"Got flag >>>>>>>> {prompt}")  
           exit()  
log.info(prompt)

       # Read the words  
       words = r.recvuntil("\n", drop=True).decode()

       # Compute and send the response  
       resp = funcs[prompt](words)  
       r.sendlineafter(">", str(resp).encode())

       # Get status  
       status = r.recvuntil("\n", drop=True).decode()

       if "fired" in status.lower():  
           log.error(f"Oops, failed task for prompt ({prompt})")  
       else:  
log.info(status)

if __name__ == "__main__":  
   main()  
```

The flag was `flag{you_know_the_dictionary_so_you_are_hired}`