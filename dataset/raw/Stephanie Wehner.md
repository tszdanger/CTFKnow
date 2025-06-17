##  Description

Stephanie Dorothea Christine Wehner (born 8 May 1977 in Würzburg) is a German
physicist and computer scientist. She is the Roadmap Leader of the Quantum
Internet and Networked Computing initiative at QuTech, Delft University of
Technology.She is also known for introducing the noisy-storage model in
quantum cryptography. Wehner's research focuses mainly on quantum cryptography
and quantum communications. - Wikipedia Entry

Challenge: We had the flag in notepad but it crashed. Please return the flag
to this Quantum Cryptographer

Memory Dump:
https://drive.google.com/file/d/1wFihQD4zdespZx1Bjw5fV_zANoNrJg9k/view  
---

Because this is a memory dump challenge, my first assumption is that we need
to use volatility. I used the python script of volatility 3 for this challenge
but I know that a lot of people had issues running vol3, instead using vol2
which worked. Also some did not use the python version so it ran a lot slower
for them whereas for me it took no more than 2-3 minutes to completely dump
the memory for specific PIDs.

Moving on, the challenge mentioned the notepad program so that is what I want to dump. To start I ran `python3 vol.py -f memory_dump.vmem windows.pslist.PsList | Select-String notepad` which will list all the processes that were running and their id. The second part of the code is just the powershell equivalent to grep which I used to return only the line relating to the notepad application. 

{% highlight bash %}  
2452 1180 notepad.exe 0xe000021c3900 2 - 1 False 2023-08-03 21:20:36.000000
N/A Disabled  
{% endhighlight %}

The process id is the first value returned, in this case PID is 2452. Now onto
dumping the memory of that process using `python3 vol.py -f memory_dump.vmem
-o /path/to/desired/output/dir windows.memmap.Memmap --pid 1452 --dump`

This will take a little bit of time to run but after a couple minutes it was
done. To try and find the content I went with the strings approach. So trying
to dump all the strings first with `strings -e l pid2452.dmp` where the '-e l'
flag refers to the type of encoding it is processing, specifically 16-bit
littleendian which I found out about when trying to look through some
volatility notes. Now there were way too many strings for me to go through so
I tried using grep/select-string to find the flag.

Adding `Select-String "chctf"` and running resulted in another dead end as
there was a fake flag in the strings, *"chctf{this_is_not_the_flag}"*. The
fake flag made it clear that I am on the right track so I added '-B 10' to my
command so that it would display 10 lines before the grep match. Below is the
final command needed in both powershell and bash.

{% highlight bash %}  
strings -e l pid2452.dmp | grep "chctf" -B 10  
strings -e l pid2452.dmp | Select-String "chctf" -Context 10  
{% endhighlight %}

Now I could see a lot more data and there is a link to a github repository.

{% highlight bash %}  
Welcome to CyberHeroines CTF!  
No, No, chctf{this_is_not_the_flag} - not a leet format  
Try harder !!!  
Github: https://github.com/FITCF  
{% endhighlight %}

The user account has one repository which is called *secret* that holds a
single file that says *"well, there's nothing here!"*. If we look in the
history of that file we see a previous upload that contains the flag,
chctf{2023!@mu5f@!5y_1009}.

Original writeup
(https://jaedyno15.github.io/ctf_writeup/2023-09-09-stephanie-wehner/).