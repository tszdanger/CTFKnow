Writeup for the hello world challenge:

Description for the challenge:

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/HelloWorld/Images/Screenshot_20201001_005713.jpeg)

I am gonna be honest I can't able to get any info from the description

Okk lets proceed to our always goto 3 steps to stage the arena to get the flag
for the challenge.

The first 3 steps is normal execution,ltrace and strings.Let's perform these
steps and find out any info

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/HelloWorld/Images/Screenshot_20201001_004210.jpeg)

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/HelloWorld/Images/Screenshot_20201001_004225.jpeg)

Okk from the normal execution step the info we can be able to get is the
program checks if 3 user arguements(program_name,2 other user arguements) and
after it checks whether the first arguement is correct then it proceeds to
check whether the next arguement is correct

And now the ltrace part ...Whattt  sort of black magic is this how come ltrace
does not produce any sort of output!!Pretty Strangeee!!!!!

Time for analyzing the binary using strings,the information we can able to
scratch from here is there are 2 user defined functions:-check and
print.According to name, the check function maybe used to check whether the
provided arguements are correct and then the print function maybe used to
print the flag if both arguements are correct.And the presence of strcmp gives
positive signs of string compare if program debugged in gdb we can set
breakpoint in the instruction that calls the strcmp function and analyze the
rsi and rdi registers and see the values that are compared which makes it
pretty easy..Then the  name of the source code of the challenge is chall.c

Though we know the presence of strcmp in binary..Still before using gdb let's
try ghidra's decompiler  and try to get more information about the binary or
the flag itself in this phase ...

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/HelloWorld/Images/Screenshot_20201001_004735.jpeg)

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/HelloWorld/Images/Screenshot_20201001_004757.jpeg)

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/HelloWorld/Images/Screenshot_20201001_004912.jpeg)

The main seems to be small and the information we can get from this decompiled
version of main is the program first check whether there are 3 user
arguements(1 file name arguement(which is default),2 user arguements) and if
it is succeded it moves it another if statement that checks whether the return
value from check function is equal to 0 when the first arguement for the
function is first user arguement and the int 1.And if the return value is zero
it checks the next if statement which proceeds the same way as the first if
statement but the difference is the arguements which is second arguement and
int 2.And if both the if statement succeeds the print function is executed
which generates and print the flag.And if the statement does not succeed it
gives which arguement is not correct.

Let's move to the check function where it looks little bit complex but can be
duplicated because of absence of undefined..But a strcmp is present which
gonna make it way easier than that of duplicating the program.. From the
decompiled version we can see that the first execution of check function
executes first part of check function with strcmp and returns 0 if both values
are same and proceeds to the second time execution of check function where the
next strcmp check where both values are same and return 0 and if not return
values other than zero.

Frankly I have no idea about what is going in the print function.

Armed with this knowledge let's move to gdb and set breakpoints on the call
strcmp instruction in check function and examine the values in rsi and rdi
register where one holds the value of our user input arguement where the other
holds the value by the binary..We have to execute the program three times to
get the flag.

First time to get first arguement and the second time to get the value of the
second arguement and third time with both correct arguements to get the flag.

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/HelloWorld/Images/Screenshot_20201001_040338.jpeg)

Okk we have set breakpoints at both the call strcmp instructions and ready to
start execution of the program by two sample flag format arguements.Now let's
wait and see the value of the first arguement.

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/HelloWorld/Images/Screenshot_20201001_040759.jpeg)

After hitting the breakpoint 1 we found that our first input arguement is
compared with the value "H3ll0" which we found out by examining the rdi
register and then we didn't hit on breakpoint 2 ..But it's no surprise as we
found from the decompiled version the execution passes to second part of check
function only if the first arguement is correct.So lets try again the second
time with first arguement as H3ll0.

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/HelloWorld/Images/Screenshot_20201001_041444.jpeg)

We can see that for first strcmp both value is same and this time we are able
to hit the second breakpoint where after examining the rsi and rdi registers
we can see that our second input arguement is compared with the value "W0rld"
and after continuing the execution the program throws the error that "invalid
argument: darkCTF{5678}" showing that  second arguement is wrong .Now this
time lets change the second arguement to "W0rld" and see what happens this
time ..Lets run this time with arguements "H3ll0" "W0rld".

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/HelloWorld/Images/Screenshot_20201001_042309.jpeg)

For the first breakpoint the values of rsi and rdi registers are same and for
the second breakpoint the same value occurs in both rsi and rdi
registers.Continuing the execution of the program ..And Voila!!  The flag of
the challenge appers.

The flag is darkCTF{4rgum3nts_are_v3ry_1mp0rt4nt!!!}

Original writeup (https://github.com/vital-information-resource-under-
siege/DarkCTF-Writeups/blob/master/HelloWorld/README.md).