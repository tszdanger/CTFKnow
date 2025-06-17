# TicTacToe

## Description:  
Hey, I made a tic tac toe game! If you can beat me enough times I’ll give you
a flag.  
  
[tictactoe](tictactoe.py) *openssl s_client -connect tamuctf.com:443
-servername tictactoe -quiet*

## Difficulty/Points:  
`Easy/150`

## FLAG:  
`gigem{d0esnt_looK_lik3_5t4rs_t0_M3}`  
#  
## Solution  
Having the [source code](tictactoe.py), after a first reading, it was easy to
identify the problem.

The part we have focused on are essentially two:  
1. `Save progress`: *thanks to which, after winning a game, you can "save"*;   
   ```python  
  elif selection == "3":  
        data = {"wins": wins, "security": get_hash(wins)}  
        print(f"Here you go!  Come back and try again! \"{base64.b64encode(pickle.dumps(data)).decode()}\"")  
        pass  
    ```  
2. `Load progress`: *thanks to which you can "load" a progress starting from the result obtained from the "save"*.  
   ```python  
   elif selection == "4":  
        save = input("What was the code I gave you last time? ")  
        data = pickle.loads(base64.b64decode(save))  
        if get_hash(data['wins']) != data['security']:  
          print("Hey, the secret code I left isn't correct.  You aren't trying to cheat are you :/")  
          continue  
        else:  
          wins = data['wins']  
          print(f"Okay, that all checks out!  I'll mark you down as {wins} wins")  
        pass  
   ```  
But what is the information that can be found from these two pieces of code?  
- how the *"data"* parameter is constructed which is what is encoded and returned as the value of the "save" operation.  
 ```python  
 data = {"wins": wins, "security": get_hash(wins)}  
 ```  
 In particular, note how the content of the *"security"* field is generated
using the *get_hash* method.  
 ```python  
 def get_hash(w):  
      m = sha256()  
      m.update((str(wins) + flag).encode())  
      return base64.b64encode(m.digest()).decode()  
    ```  
  It is particular because the parameter that the method receives is not used
to generate the hash which will depend only on the value of the *"wins"*
variable and the value of the *flag*;  
- how what is "loaded" is evaluated.  
 ```python  
 if get_hash(data['wins']) != data['security']  
 ```  
At this point we knew what to do because, after winning a game and generating
the hash, it was enough to reconstruct the *"data"* parameter by imposing that
the *"wins"* field was the number to be reached and the *"security"* field was
the one generated after "saving", "loading" a progress with the result
obtained and finally claiming the reward.

To do this, the following python script has been implemented:  
```python  
from pwn import *  
from base64 import *  
from pickle import *

p = process("openssl s_client -connect tamuctf.com:443 -servername tictactoe
-quiet", shell=True)

def play_game():  
   p.sendlineafter("> ", "1")  
   movs = ["0 0", "1 0", "2 0"]  
   for m in movs:  
       p.sendlineafter("> ", m)

def save_progress():  
   p.sendlineafter("> ", "3")  
   enc_data = p.recvline().strip().decode().split()[8]  
   return enc_data

def rebuild_data(enc_data):  
   data = loads(b64decode(enc_data))  
   new_data = {"wins": 133713371337, "security": data["security"]}  
   return base64.b64encode(pickle.dumps(new_data)).decode()

def load_progress(data):  
   p.sendlineafter("> ", "4")  
   p.sendlineafter("? ", data)

def print_flag():  
   p.sendlineafter("> ", "2")  
   print(p.recvline().strip().decode())

if __name__ == "__main__":  
   play_game()  
   enc = save_progress()  
   data = rebuild_data(enc)  
   load_progress(data)  
   print_flag()  
```  

Original writeup (https://github.com/hackalcubo/CTF-
Writeups/tree/main/TamuCTF-2021/TicTacToe).