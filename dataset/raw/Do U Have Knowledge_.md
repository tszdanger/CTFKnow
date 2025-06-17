# Do U Have Knowledge (crypto, 470p, 8 solved)

## Description

In the task we get the [server source
code](https://raw.githubusercontent.com/TFNS/writeups/master/2020-09-25-BalCCon/do_u_have_knowledge/server.py)  
We can also connect to remote server, where this code is running.

## Code analysis

Application has 2 stages.  
First one is a game of number guessing, second one is decrypting the flag.

### Stage 1

In this stage we have to play a game of number guessing with the server:

```python  
def play_lottery() -> bool:  
   random.seed(int(time.time()))  
   for _ in range(3):  
       number = random.randint(1,65535)  
       guess = input('Guess the next lottery number: ')  
       guess = int(guess)  
       if(number == guess):  
           print('Congratulations, you won the lottery.')  
           return True  
       else:  
           print('Wrong. The correct number was {}.'.format(number))  
   return False  
```

Server seeds the random with current server time and allows us to have 3
attempts at guessing the right number.

### Stage 2

If we manage to pass the lottery stage, the server will give us encrypted
flag.  
Encryption is using AESCCM with randomly generated `key`, `nonce` and some
additional `associated data`:

```python  
with open('flag.txt') as f: flag = f.read()  
# Use a cryptographically secure random number generator to secure the flag  
rng = AnsiRng(urandom(16)) # Use an unguessable seed value for the RNG  
key = rng.get_random(16)  
r = rng.get_random(32)  
nonce = r[:12]  
ad = r[12:]

cipher = AESCCM(key, tag_length=16)  
encrypted_flag = cipher.encrypt(nonce, flag.encode('utf-8'),
associated_data=ad)  
output = b64encode(nonce + ad + encrypted_flag).decode('utf-8')  
print("Here is your encrypted flag: {}".format(output))  
```

The key part is `AnsiRng` code which generates the randoms:

```python  
   def _get_random_block(self):  
       t = self._get_timestamp()  
       cipher = Cipher(algorithms.AES(b'1234567890123456'), modes.ECB(), backend = default_backend())  
       c1 = cipher.encryptor().update(t)  
       c2 = bytes([c1[i] ^ self._state[i] for i in range(16)])  
       o = cipher.encryptor().update(c2)  
       c3 = bytes([c1[i] ^ o[i] for i in range(16)])  
       self._state = cipher.encryptor().update(c3)  
       return o  
```

It's using current timestamp and also current generator `state` to create new
state and also random block.

## Vulnerabilities

### Timestamps

The initial vulnerability in both stages is actually the same -> when the
application starts it prints out the current server time!  
While the second stage is using much higher precision than what we have
(million times), but we can brute-force one million values to find the right
timestamp if necessary.

### Random generation

Notice that we know 2 output blocks from the RNG, because we know `nonce` and
`associated data`.  
Notice also what happens if we know the current timestamp:

1. By knowing `t` value we can reproduce `c1` directly by encryption  
2. By knowing `o` variable we can recover `c2` directly by encryption  
3. From `c1` and `c2` we can get `current state` by simple XOR  
4. By knowing `o` variable (output of RNG) and `c1` we can reproduce `c3` value  
5. `c3` value directly produces `state` for the next run of the RNG

This pretty much means we know everything there is to know.  
We can do steps 1-3 to get current state from some RNG output.  
Then we can use it to get `c3` from previous RNG run.  
Then we need to move back in time a bit and test some potential `t` values to
get `c1` and finally recover `o` for this previous round.

## Solver

### Stage 1

First stage is trivial, we just connect, read the timestamp, seed the random
and win the game:

```python  
def stage1():  
   host = "pwn.institute"  
   port = 36666  
   s = nc(host, port)  
   timestamp = receive_until(s, "\n")[:-1]  
   print('timestamp', timestamp, int(time.time() * 1000000))  
   t = time.mktime(time.strptime(timestamp))  
   random.seed(int(t) + 2 * 3600)  
   x = receive_until(s, ":")  
   number = random.randint(1, 65535)  
   print('number', number)  
   send(s, str(number))  
   print(receive_until(s, "="), int(time.time() * 1000000))

stage1()  
```

### Stage 2

Notice that our stage 2 attack works under the assumption that we know the `t`
in some round.  
Since we know 2 outputs of the RNG, we can use those to pinpoint the exact `t`
value by pure brute-force:

```python  
def worker(data):  
   cipher = Cipher(algorithms.AES(b'1234567890123456'), modes.ECB(),
backend=default_backend())  
   c2, ts, t1, target, c1s = data  
   c1 = c1s[t1]  
   state = bytes([c1[i] ^ c2[i] for i in range(16)])  
   c3 = cipher.decryptor().update(state)  
   for t2 in range(1000):  
       c1 = c1s[t1 - t2 if t1 - t2 >= 0 else 0]  
       o = bytes([c1[i] ^ c3[i] for i in range(16)])  
       if o == target:  
           print(ts * 1000000 + t1, ts * 1000000 + t1 - t2)  
           return ts * 1000000 + t1 - t2

def recover_previous(ts, value, target):  
   cipher = Cipher(algorithms.AES(b'1234567890123456'), modes.ECB(),
backend=default_backend())  
   c1s = [cipher.encryptor().update(int.to_bytes(int(ts * 1000000 + t1),
length=16, byteorder='little')) for t1 in range(1000000)]  
   c2 = cipher.decryptor().update(value)  
   print("Precomputed!")  
   brute(worker, [(c2, ts, t1, target, c1s) for t1 in range(1000000)],
processes=6)  
```

We pre-compute all possible timestamps from the one we know onwards for 1
second, and then we run our attack in parallel.  
The pre-computation is useful, because we need to "move in time" between RNG
generations, and we don't know by how much.  
This means for each test we need to encrypt two values `ts * 1000000 + X` and
`ts * 1000000 + Y`, so it makes sense to compute this once.  
We assume here that between the RNG generations there was no more than 1ms
delay.

Once we get the proper timestamp for the second RNG, we can use it, to recover
the output of the RNG in previous round (so the key):

```python  
def recover_flag(ts, value, ct):  
   cipher = Cipher(algorithms.AES(b'1234567890123456'), modes.ECB(),
backend=default_backend())  
   for t1 in range(1000):  
       t = int.to_bytes(ts - t1, length=16, byteorder='little')  
       o = value  
       c1 = cipher.encryptor().update(t)  
       c2 = cipher.decryptor().update(o)  
       state = bytes([c1[i] ^ c2[i] for i in range(16)])  
       c3 = cipher.decryptor().update(state)  
       for t2 in range(1000):  
           t = int.to_bytes(ts - t1 - t2, length=16, byteorder='little')  
           c1 = cipher.encryptor().update(t)  
           o = bytes([c1[i] ^ c3[i] for i in range(16)])  
           ciph = AESCCM(o, tag_length=16)  
           try:  
               return ciph.decrypt(ct[:12], ct[32:], ct[12:32])  
           except:  
               pass

```

The code is pretty much identical, but this time we decrypt the ciphertext and
look for flag prefix, and we get:
`BCTF{7he_DUHK_a77ack_1s_go1ng_t0_mak3_y0u_gr0use}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-09-25-BalCCon/do_u_have_knowledge/README.md).