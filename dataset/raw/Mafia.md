# Mafia

>The CTF Mafia wants to remove the competition (i.e.you) to again have
monopoly over flags. Bribe the Mafia to get away unscathed and with the flag.  
>  
>nc chall.csivit.com 30721

# Problem from prob.pdf  
Problem Statement:

To bribe the Mafia, you need a lot of money. You can borrow only from one of
your 300 friends (numbered 1 to 300) who have 1 to 1000000(both inclusive)
bucks, so you want to borrow money from the friend with the most cash.

However, your friends are pretty annoying and only tell you whether they have
greater(G), lesser(L) or equal(E) money to a given value.

You can ask a maximum 1000 questions (even less are ok) of the form 1
(friend_number) (value). And finally input the maximum amount of money you can
borrow in the form 2 (max_money).

Examples:

• 1 15 3007 This question asks whether the 15th friend has more, less or equal
money to 3007 bucks.

• 2 2000 This indicates that the friend with the maximum money has 2000 bucks.

Note:

• Asking more than 1000 questions will end program instantly.

•  Entering invalid question or final input will end program instantly.

• Keep friend_number between 1 and 300(both inclusive) and keep value between
1 and 1000000(both inclusive).

# Solution

My solution was to ask every single one of the 300 people if they have
greater, less, or equal money than the average of the min and max possible
money. If there are some people that say greater, everyone else that said less
are forgotten and aren't interrogated again. The min is moved up to the guess,
and a new guess is created, which is the number between the min and the max.
If everyone said less (hopefully not, as that is highly unlikely in the first
iteration) the max is moved to the guess, and a new guess is generated. This
continues until there is one person left and that person says he has exactly
that amount of money. (E)

I made a proof script to see if this algorithm will actually work in practice.

```python  
f = 300 # friends  
q = 1000 # questions  
max = 1000000 # max cash  
i = 2  
cash = 0

while f > 0:  
   q -= f  
   f = f // 2  
   cash += max / i  
   i *= 2

print("Ratio of max to cash:", max/cash)  
print("Questions remaining after interogation:", q)  
```

```  
$ py proof.py  
Ratio of max to cash: 1.0019569471624266  
Questions remaining after interogation: 404  
```

Assuming that half of the friends still remaining are removed after each
interrogation, there should be an average of 404 questions remaining, which is
really good.

This solution doesn't work  100% of the time, it might have been better to
make random guess between the min and the max, instead of take the average.
This doesn't work when the max money is a very small number, because then this
algorithm runs out of questions very quickly. But it works if the max is
bigger than half the max, because the guesses are usually a lot better.

```  
Investigating friend 291... 491 questions remaining.  
b'E'  
b'E'  
Moving downward!  
Win!  
Friend #: 291, Max money: 712787  
[*] Switching to interactive mode  
Congratulations you guessed it right, here is the reward:
csictf{y0u_ar5_t8e_k!ng_0f_rAnd0mne55}  
[*] Got EOF while reading in interactive  
$  
```

Overall, very fun challenge! This probably was my favorite challenge for this
entire CTF!

I would like to thank the organizers for hosting an amazing CTF! All the
challenges were very good, and overall I learned a lot! Thank you for hosting
this ctf!

Flag: `csictf{y0u_ar5_t8e_k!ng_0f_rAnd0mne55}`  

Original writeup (https://github.com/Jord4563/CTF-
writeups/tree/master/csictf2020/mafia).