Writeup for so_much reverse challenge:

Description:

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/so_much/Images/Screenshot_20200930_044942.jpeg)

The description says strcmp and printf okk if strcmp is present it is gonna
compare the user input with flag maybe

Let's proceed the 5 go to steps for debugging:-

The steps are present in the c_maths writeup

1.Let's run and see ..Okk it needs some arguements lets give a arguement with
the flag format and some strings command to find some juicy information

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/so_much/Images/Screenshot_20200930_044358.jpeg)

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/so_much/Images/Screenshot_20200930_044328.jpeg)

We found that there are functions that process the strings and checks for the
flag because of presence of number of user defined function names

So due to the high number of functions and get flag functions that calls many
function let's proceed to gdb straightly and see the arguements for the strcmp
functions chances are that maybe the flag.So lets pop our gdb set breakpoint
before the strcmp function and analyze the registers.

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/so_much/Images/Screenshot_20200930_054943.jpeg)

We can see that values are getting moved to rsi and rdi register before the
strcmp function so it is wise to check there

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/so_much/Images/Screenshot_20200930_054953.jpeg)

In rdi register our user input is present and in rsi register the other value
seems to be strange and it is curly braces tooo and saying
{w0w_s0_m4ny_funct10ns}.Let's try this as the input for our next round of
execution.

![alt_text](https://github.com/vital-information-resource-under-siege/DarkCTF-
Writeups/blob/master/so_much/Images/Screenshot_20200930_055738.jpeg)

The flag is darkCTF{w0w_s0_m4ny_funct10ns}

  

Original writeup (https://github.com/vital-information-resource-under-
siege/DarkCTF-Writeups/blob/master/so_much/README.md).