![Pasted image
20210718142935.png](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718142935.png?token=AL5Z374PFMXPXJ3OXAEIC2DA7UQFM)

## This is the problem from LIT CTF 2021. At the time i wrote this writeup, it
has only 6 solves (2 was mine lol xD)

### During the CTF, i was able to solve all 7 web challenges but i think this
challenge is the only one deserves a detail writeup

### Here is the front page of the website of the challenge

![Pasted image
20210718143143.png](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718143143.png?token=AL5Z372E5ZUQ7SQVGTHJC23A7UQLO)

#### We see one endpoint here */api*  and a template POST request to this
endpoint to query for information in database  
#### This request used xml so the first idea comes through me was a XXE, but
let see

#### After downloading the challenge's file, we have source code of the
challenge. I will focus on the main file *alexfanclubapi.py* where the
bussiness happen. Make sure to always to try run these challs locally

![[Pasted image
20210718143708.png]](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718143708.png?token=AL5Z377HKQ2V3OQHZEU6XG3A7UQNG)

#### The server try to prepend and append xml document to our query, a basic
query was like:

```
]><req><stime>&sendtime;</stime><ntime>&nowtime;</ntime><search>cool</search></req>```

![[Pasted image 20210718144143.png]](https://github.com/letronghoangminh/CTF-
Writeups/blob/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718144143.png?raw=true)

#### And this is the code for comparing the sendtime with the nowtime to
determine if we have tampered the sendtime or not  
#### The server also take the search text to put into a safe query which
prevent us from abusing error-based XXE or SQL Injection

![[Pasted image
20210718144351.png]](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718144351.png?token=AL5Z37YEWJ2RATSJ5HY2FRTA7UQUM)

## So now im pretty sure this is a XXE attack. But how??

#### After going around on Google i found this Github issue
https://github.com/tylere/pykml/issues/37 which tell me that the *fromstring*
was definitely a dangerous function cause it didn't parse the XML well

#### So i try to inject XXE into the template request  
![[Pasted image
20210718145140.png]](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718145140.png?token=AL5Z37264XP4XYKX27NSKQDA7UQWE)

### AND HEY, IT WORK (I tried dumping the xml document after parsing it at
local)  
![[Pasted image
20210718144919.png]](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718144919.png?token=AL5Z374ZJ5FKJLTPVSUF67LA7UQX6)

#### This is basically a blind XXE attack. So then i do what a normal person
would do: Try connecting to my server

![[Pasted image
20210718145215.png]](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718145215.png?token=AL5Z37377ZZNX7J5NVFLTSLA7UQZU)

#### Surely, that didn't work =))  
#### The lxml module automatically block all outbound connections by default
(:pain:)  
![[Pasted image
20210718150501.png]](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718150501.png?token=AL5Z3755NT3YULICIURU7N3A7UQ2Y)  
#### Then i came up with a new idea, the only thing we could abuse was the
feedback of the server  
## Pay attention to this code, the server try to turn the *sendtime* and
*nowtime* we sent to it into 2 integers and them compare them to return a
particular result. What if we can turn the flag into a integer and then
compare it with our number? Then it would be easy to develop a binary search
algorithm to find out the number  
![[Pasted image
20210718145830.png]](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718145830.png?token=AL5Z373UALZDTG4GS24TKDTA7UQ4C)

#### So, i inserted comments into the XML document to overwrite the nowtime
entity, the flag then will be convert into a integer.  
#### The *psycho* variable is a random number of my choice  
![[Pasted image
20210718145729.png]](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718145729.png?token=AL5Z37YHMGSFRVIDLFTLH6LA7UQ44)

#### Then the algorithm part was easy  
![[Pasted image
20210718150035.png]](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718150035.png?token=AL5Z377TNGZSTG5BQJ4WVX3A7UQ5Q)

#### Result:  
![[Pasted image
20210718150124.png]](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718150124.png?token=AL5Z37ZYD74DSUZ2PQKCDZLA7UQ6G)

### After a few minutes, here is what we got:  
![[Pasted image
20210718150521.png]](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718150521.png?token=AL5Z37526MP75CUBZKNEJCDA7UQ64)

### Then to decode it, you can replace the *req_time* with the result we've
found, here i sent it to my local server. After parsing the XML, the flag
appeared:  
![[Pasted image
20210718150731.png]](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718150731.png?token=AL5Z374E3IAKEMVWYVETJNDA7UQ7U)

![[Pasted image
20210718150806.png]](https://raw.githubusercontent.com/letronghoangminh/CTF-
Writeups/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)/Images/Pasted%20image%2020210718150806.png?token=AL5Z372GYNCZO3SNW6WKZQTA7URAQ)

### Because of some problems in timing, the flag's parsing was not completely
successed  
### So i guessed it =))  
## Here is the flag: `flag{xxe_1s_k1nd4_co0l_als0_ins3rt_m1s5ing_br4ck3ts}`

## Thanks for reading, sorry for my English =))  
## Cre: psycholog1st  

Original writeup (https://github.com/letronghoangminh/CTF-
Writeups/tree/master/Web/LITCTF%202021%20-%20Alex%20Fan%20Club%20API%20(500)).