## Description of the challenge

We are given a compiled binary of the [janet-lang](https://janet-lang.org/)
interpreter, along with a "compiled" script written in janet-lang.

## Solution

So I'll start off by saying that we work cooperatively on some challenges. For
example, [zenbassi](https://github.com/Stefan-Radu) also worked heavily on
this one. So the writeup author is usually not the only one to credit for the
challenge.

We run the challenge and it asks us to input some coordinates. We give it
``13.37,4.2`` five times and then it exits, showing us where the answer was in
memory:  
```  
$ ./janet -i program.jimage  
Welcome to geoguesser!  
Where am I? 13.37,4.2  
Nope. You have 4 guesses left.  
Where am I? 13.37,4.2  
Nope. You have 3 guesses left.  
Where am I? 13.37,4.2  
Nope. You have 2 guesses left.  
Where am I? 13.37,4.2  
Nope. You have 1 guesses left.  
Where am I? 13.37,4.2  
You lose!  
The answer was: <tuple 0x5608A2AF0BC0>  
```  
Our first thought was that we had to dump the memory and then just give it the
correct answer to decrypt some flag. But then we realized that there is a
remote instance, so surely the local instance had no flag.

By inspecting the ``program.jimage`` compiled image we were given, we can
observe several plaintext artifacts left over. A lot of the artifacts leak
information about the modules used in the program. For example, these lines
from the hexdump seem to suggest that there might be a random number generator
involved:  
```  
000002e0: d805 7072 696e 74d7 00cd 00dc 0000 0400  ..print.........  
000002f0: 0000 030b 0001 ce08 696e 6974 2d72 6e67  ........init-rng  
00000300: da05 d807 6f73 2f74 696d 65d8 086d 6174  ....os/time..mat  
00000310: 682f 726e 67da 2d00 0b00 cf08 696e 6974  h/rng.-.....init  
00000320: 2d72 6e67 2c00 0000 2a02 0000 3301 0200  -rng,...*...3...  
```  
Even more interesting is the appearance of ``os/time``. This could mean this
is a RNG seeded with the current time.

We found that janet has a [disasm](https://janet-
lang.org/api/index.html#disasm) functionality. So we can import the program
and disassemble any of the called functions.  
```  
$ ./janet      # --- ENTER JANET REPL ---

Janet 1.28.0-358f5a0 linux/x64/gcc - '(doc)' for help  
# --- IMPORT program.jimage ---  
repl:1:> (import ./program)  
@{_ @{:value <cycle 0>} program/compare-coord @{:private true}
program/compare-float @{:private true} program/coordinate-peg @{:private true}
program/get-guess @{:private true} program/guessing-game @{:private true}
program/init-rng @{:private true} program/main @{:private true} program/parse-
coord @{:private true} program/precision @{:private true} program/print-flag
@{:private true} program/random-float @{:private true} program/rng @{:private
true} :macro-lints @[]}  
# --- DISASSEMBLE program/main ---  
repl:2:> (disasm program/main)  
{:arity 0 :bytecode @[ (lds 0) (ldc 1 0) (push 1) (ldc 2 1) (call 1 2) (ldc 3
2) (call 2 3) (ldi 3 -90) (ldi 4 90) (push2 3 4) (ldc 4 3) (call 3 4) (ldi 4
-180) (ldi 5 180) (push2 4 5) (ldc 5 3) (call 4 5) (push2 3 4) (mktup 3) (movn
4 3) (push 4) (ldc 6 4) (call 5 6) (jmpno 5 3) (ldc 6 5) (tcall 6) (ldc 6 6)
(push 6) (ldc 7 1) (call 6 7) (ldc 6 7) (push2 6 4) (ldc 6 1) (tcall 6)]
:constants @["Welcome to geoguesser!" <cfunction print> <function init-rng>
<function random-float> <function guessing-game> <function print-flag> "You
lose!" "The answer was: "] :defs @[] :environments @[] :max-arity 2147483647
:min-arity 0 :name "main" :slotcount 8 :source "main.janet" :sourcemap @[ (54
1) (55 3) (55 3) (55 3) (55 3) (56 3) (56 3) (57 16) (57 16) (57 16) (57 16)
(57 16) (57 38) (57 38) (57 38) (57 38) (57 38) (57 15) (57 15) (57 3) (58 7)
(58 7) (58 7) (58 3) (59 5) (59 5) (61 7) (61 7) (61 7) (61 7) (62 7) (62 7)
(62 7) (62 7)] :structarg false :symbolmap @[(0 34 0 main) (19 34 4 answer)]
:vararg false}  
```  
Then we can manually inspect it and assign some meaning to the lines. We used
this [page as reference](https://janet-lang.org/docs/abstract_machine.html),
describing the instructions of the abstract machine.

First, we started with ``program/main``, ``program/init-rng`` and
``program/random-float``. Analysis listed below:  
```  
// random-float  
constants [  
0: @[nil]  
1: <cfunction math/rng-uniform>]

==================================

(lds 2) // $2 = current closure  
(ldc 3 0) // $3 = constants[0] // [nil]  
(geti 3 3 0) // $3 = $3[0]  // nil  
(push 3) // push $3 args // nil  
(ldc 4 1) // $4 = constants[1] // rng-uniform  
(call 3 4) // $3 = (call $4 args) // got random  
(sub 4 1 0) // $4 = $1 - $0 // arg1 - arg2  
(mul 5 3 4) // $5 = $3 * $4 // $3 * diff  
(add 3 0 5) // $3 = $0 + $5 // scaled_diff + arg1  
(ret 3) // ret $3 // random in [arg1, arg2]

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  
// init-rng -> returns random number generator  
constants = [  
0: <cfunction os/time>  
1: <cfunction math/rng>  
2: @[nil] ]

==================================

(lds 0)             $0 = current closure  
(ldc 2 0)           $2 = constants[0] // os/time  
(call 1 2)          $1 = call $2 args  
(push 1)            push args $1  
(ldc 3 1)           $3 = constants[1] // math/rng  
(call 2 3)          $2 = call $3 args  
(ldc 1 2)           $1 = constans[2] // nil?  
(puti 1 2 0)        $1[0] = $2  
(ldc 1 2)           $2 = $1  
(geti 1 1 0)        $1 = $1[0]  
(ret 1)             ret $1 // returns generator

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  
// main  
constants = [  
0: "Welcome to geoguesser!"  
1: <cfunction print>  
2: <function init-rng>  
3: <function random-float>  
4: <function guessing-game>  
5: <function print-flag>  
6: "You lose!"  
7: "The answer was: " ]

====================================

(lds 0)         $0 = current closure  
(ldc 1 0)       $1 = constants[0] // 0: "Welcome to geoguesser!"  
(push 1)        push $args $1  
(ldc 2 1)       $2 = constants[1] // 1: <cfunction print>  
(call 1 2)      $1 = call $2 args // print "welcome..."  
(ldc 3 2)       $3 = $2           // 2: <function init-rng>  
(call 2 3)      $2 = call $3 args // gets generator  
(ldi 3 -90)     $3 = -90  
(ldi 4 90)      $4 = 90  
(push2 3 4)     push args $3 $4  
(ldc 4 3)       $4 = constants[3] // random float  
(call 3 4)     *$3 = call $4 args // random float in [-90, 90]  
(ldi 4 -180)    $4 = -180  
(ldi 5 180)     $5 = 180  
(push2 4 5)     push args $4 $5  
(ldc 5 3)       $5 = constants[3] // random float  
(call 4 5)     *$4 = call $5 args // random float in [-180, 180]  
(push2 3 4)     push args $3 $4  
(mktup 3)       $3 = tuple ($3 $4)  
(movn 4 3)      $4 = $3 // tuple ($3 $4)  
(push 4)        push args $4  
(ldc 6 4)       $6 = constants[4] // guessing game (tuple ($3 $4))  
(call 5 6)      $5 = call $6 args //  
(jmpno 5 3)     if $5 pc++ else pc += 3  
(ldc 6 5)       $6 = constants[5] // print-flag  
(tcall 6)       return call $6 args // print flag  
(ldc 6 6)       $6 = constants[6] // "you lost"  
(push 6)        push args $6  
(ldc 7 1)       $7 = constants[1] // print  
(call 6 7)      $6 = call $7 args // print "you lost"  
(ldc 6 7)       $6 = constants[7] // the answer was  
(push2 6 4)     push args $6 $4  
(ldc 6 1)       $6 = constants[1] // print  
(tcall 6)       return call $6 // print the ans was (tuple ..)  
```  
Honestly, we analyzed a bit too much (in fact, we analyzed almost the whole
program, check appendix). Really what we needed to see is that ``random-
float`` generates a floating point number in a range and that the generator is
seeded with the current time. So all you have to do is rewrite the number
generation and then pass it to the remote instance. We wrote the following
janet script to generate the random numbers with the current time:  
```  
(let [t (math/rng (os/time))]  
(printf "%.4f,%.4f"  
   (+ -90 (* 180  
       (math/rng-uniform t)  
       ))  
   (+ -180 (* 360  
       (math/rng-uniform t)  
       ))))  
```  
Notice how we only assigned the seeded RNG to a variable at the **beginning**
of the script. This is very important, because otherwise the RNG will print
out different numbers in different instances of it. This was a problem we
initially had while solving. So then we write a small, simple pwntools script
and get the flag:  
```py  
#!/usr/bin/env python3

from pwn import *

def send_janet():  
   print(val)  
   target.sendline(val)  
   print(target.recvline())  
  
#target = process(["./janet", "-i", "program.jimage"])  
target = remote("geoguesser.chal.uiuc.tf", 1337)  
val = subprocess.check_output(['janet', 'main.janet'])  
print(target.recvline())  
send_janet()  
send_janet()  
#send_janet()  
#send_janet()  
#send_janet()

print(target.recv())  
```  
Not sure why, but I had to send the coordinates twice before getting the
correct reply. Maybe I'm sending them too fast or something.

Running:  
```  
$ ./solve.py  
[+] Opening connection to geoguesser.chal.uiuc.tf on port 1337: Done  
b'== proof-of-work: disabled ==\n'  
b'-52.8000,56.5566\n'  
b'Welcome to geoguesser!\n'  
b'-52.8000,56.5566\n'  
b'Where am I? You win!\n'  
b'The flag is: uiuctf{wow!_I_cant_believe_its_another_.hidden_flag!!!1}\n'  
[*] Closed connection to geoguesser.chal.uiuc.tf port 1337  
```

## Appendix

Here's our full analysis of the program image:  
```  
// random-float  
constants [  
0: @[nil]  
1: <cfunction math/rng-uniform>]

==================================

(lds 2) // $2 = current closure  
(ldc 3 0) // $3 = constants[0] // [nil]  
(geti 3 3 0) // $3 = $3[0]  // nil  
(push 3) // push $3 args // nil  
(ldc 4 1) // $4 = constants[1] // rng-uniform  
(call 3 4) // $3 = (call $4 args) // got random  
(sub 4 1 0) // $4 = $1 - $0 // arg1 - arg2  
(mul 5 3 4) // $5 = $3 * $4 // $3 * diff  
(add 3 0 5) // $3 = $0 + $5 // scaled_diff + arg1  
(ret 3) // ret $3 // random in [arg1, arg2]

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

// init-rng -> returns random number generator  
constants = [  
0: <cfunction os/time>  
1: <cfunction math/rng>  
2: @[nil] ]

==================================

(lds 0)             $0 = current closure  
(ldc 2 0)           $2 = constants[0] // os/time  
(call 1 2)          $1 = call $2 args  
(push 1)            push args $1  
(ldc 3 1)           $3 = constants[1] // math/rng  
(call 2 3)          $2 = call $3 args  
(ldc 1 2)           $1 = constans[2] // nil?  
(puti 1 2 0)        $1[0] = $2  
(ldc 1 2)           $2 = $1  
(geti 1 1 0)        $1 = $1[0]  
(ret 1)             ret $1 // returns generator

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  
// compare-float -> compares floats  
constants = [  
0: <cfunction math/abs>  
]  
args = [  
0: a  
1: b  
2: tolerance  
]  
======================================  
(lds 3)             $3 = current closure  
(sub 4 0 1)         $4 = $0 - $1 // arg0 - arg1 (a - b)  
(push 4)            push args $4  
(ldc 6 0)           $6 = constants[0] // math/abs  
(call 5 6)          $5 = call $6 args  
(lt 4 5 2)          $4 = $5 < $2 ? // true/false  
(ret 4)  
// so basically it does  
// return abs(a - b) < tolerance

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  
// compare-coords

constants = [  
0: <cfunction compare-float>  
]  
args = [  
0: a // guess  
1: b // correct  
2: tolerance  
]  
====================================  
(lds 3)             $3 = current closure  
(ldi 5 0)           $5 = 0  
(get 4 0 5)         $4 = $0[$5] // guess[0]  
(ldi 6 0)           $6 = 0  
(get 5 1 6)         $5 = $1[$6] // correct[0]  
(push3 4 5 2)       Push $4, $5, $2, on args // guess[0], correct[0],
tolerance  
(ldc 7 0)           $7 = compare-float  
(call 6 7)          $6 = call compare-float on args  
(movn 4 6)          $4 = $6  
(jmpno 6 8)         if $6 pc++ else pc += 8 // exit if not true  
(ldi 7 1)  
(get 5 0 7)         $5 = $0[1] // guess[1]  
(ldi 8 1)           $8 = 1  
(get 7 1 8)         $7 = $1[1] // correct[1]  
(push3 5 7 2)       Push $5, $7, $2, on args // guess[1], correct[1],
tolerance  
(ldc 8 0)  
(tcall 8)           return compare-float result  
(ret 4)

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  
// guessing-game  
constants = [  
0: <function get-guess>  
1: 0.0001  
2: <function compare-coord>  
3: <cfunction not>  
4: "Nope. You have "  
5: " guesses left."  
6: <cfunction print>  
]  
args = [  
0: answer  
1: guessing-game  
2: guess  
3: remaining  
]  
====================================

(lds 1)              $1 = closure  
(ldc 3 0)            $3 = get-guess  
(call 2 3)           $2 = get-guess()  
(movn 3 2)           $3 = $2  
(ldi 4 4)            $4 = 4  
(ldc 6 1)            $6 = 0.0001 // constants[1]  
(push3 3 0 6)        Push $3, $0, $6 // guess, answer, precision  
(ldc 7 2)            $7 = compare-coord  
(call 6 7)           $6 = compare-coord(stack_stuff)  
(push 6)             Push $6 // true/false  
(ldc 8 3)            $8 = func-not  
(call 7 8)           $7 = !compare-coord()  
(movn 6 7)           $6 = $7  
(jmpno 7 4)          if $7 pc++ else pc += 4 // if not correct else jump 4  
(gtim 8 4 0)         $8 = $4 > 0 // rem_guesses > 0 ?????  
(movn 5 8)           $5 = $8  
(jmp 2)              jump 2  
(movn 5 6)           $5 = $6 // !compare-coord()  
(jmpno 5 10)         if $5 pc++ else pc += 10 // if not correct or out of
guesses jump 10 BIG JUMP OUT OF LOOP -------->  
(ldc 6 4)            $6 = "Nope."  
(ldc 7 5)            $7 = "guesses left"  
(push3 6 4 7)        push $6, $4, $7 // "Nope you have " x " guesses left  
(ldc 7 6)            $7 = print  
(call 6 7)           $6 = print()  
(addim 4 4 -1)       $4 = $4 - 1 // decrease remaining  
(ldc 6 0)            $6 = get-guess  
(call 3 6)           $3 = get-guess()  
(jmp -22)            loop back  
(ldc 5 1)            5 = precision // JUMP HERE
<----------------------------------------------------------------------  
(push3 3 0 5)        push $3, $0, $5 // guess, answer, precision  
(ldc 5 2)            $5 = compare-coords  
(tcall 5)            ret compare-coords()

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

// main  
constants = [  
0: "Welcome to geoguesser!"  
1: <cfunction print>  
2: <function init-rng>  
3: <function random-float>  
4: <function guessing-game>  
5: <function print-flag>  
6: "You lose!"  
7: "The answer was: " ]

====================================

(lds 0)         $0 = current closure  
(ldc 1 0)       $1 = constants[0] // 0: "Welcome to geoguesser!"  
(push 1)        push $args $1  
(ldc 2 1)       $2 = constants[1] // 1: <cfunction print>  
(call 1 2)      $1 = call $2 args // print "welcome..."  
(ldc 3 2)       $3 = $2           // 2: <function init-rng>  
(call 2 3)      $2 = call $3 args // gets generator  
(ldi 3 -90)     $3 = -90  
(ldi 4 90)      $4 = 90  
(push2 3 4)     push args $3 $4  
(ldc 4 3)       $4 = constants[3] // random float  
(call 3 4)     *$3 = call $4 args // random float in [-90, 90]  
(ldi 4 -180)    $4 = -180  
(ldi 5 180)     $5 = 180  
(push2 4 5)     push args $4 $5  
(ldc 5 3)       $5 = constants[3] // random float  
(call 4 5)     *$4 = call $5 args // random float in [-180, 180]  
(push2 3 4)     push args $3 $4  
(mktup 3)       $3 = tuple ($3 $4)  
(movn 4 3)      $4 = $3 // tuple ($3 $4)  
(push 4)        push args $4  
(ldc 6 4)       $6 = constants[4] // guessing game (tuple ($3 $4))  
(call 5 6)      $5 = call $6 args //  
(jmpno 5 3)     if $5 pc++ else pc += 3  
(ldc 6 5)       $6 = constants[5] // print-flag  
(tcall 6)       return call $6 args // print flag  
(ldc 6 6)       $6 = constants[6] // "you lost"  
(push 6)        push args $6  
(ldc 7 1)       $7 = constants[1] // print  
(call 6 7)      $6 = call $7 args // print "you lost"  
(ldc 6 7)       $6 = constants[7] // the answer was  
(push2 6 4)     push args $6 $4  
(ldc 6 1)       $6 = constants[1] // print  
(tcall 6)       return call $6 // print the ans was (tuple ..)

Original writeup (https://dothidden.xyz/uiuctf_2023/geoguesser/).