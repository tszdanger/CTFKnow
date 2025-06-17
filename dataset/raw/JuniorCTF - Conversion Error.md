# 35C3 Junior CTF – Conversion Error

* **Category:** Misc  
* **Points:** 87 (variable)

## Challenge

> With assert_conversion(str: string), we assert that our VM properly handles
> conversions. So far we never triggered the assertion and are certain it's
> impossible.  
>  
> http://35.207.189.79/  
>  
> Difficulty estimate: Medium  
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

The *Wee* interpreter source code can be found here:
`http://35.207.189.79/weelang/weeterpreter.ts`.

The endpoint that can be used to run *Wee* code is the following.

```  
http://35.207.189.79/wee/run  
```

The assertion that must be exploited is the following.

```Typescript  
externals.addFunction(  
  "assert_conversion",  
  [{name: "str", type: compiler.StringType}], compiler.StringType,  
  false,  
  (str: string) => str.length === +str + "".length ||
!/^[1-9]+(\.[1-9]+)?$/.test(str)  
      ? "Convert to Pastafarianism" : flags.CONVERSION_ERROR  
)  
```

The second part of the condition contains an *or* operation. The regex refers
to floating point numbers, so it is sufficient to make it `true`.

The payload is the following.

```  
alert(assert_conversion("1.1"))  
```

The following Python script can be used to send the payload.

```Python  
import requests  
import json

url = "http://35.207.189.79/wee/run"  
data_structure = """{{ "code": {} }}"""  
data_content = """alert(assert_conversion("1.1"))"""

data_content_to_send = json.dumps(data_content)  
data_to_send = data_structure.format(data_content_to_send)  
print "[*] Payload: '{}'.".format(data_to_send)  
response = requests.post(url, data=data_to_send)  
print "[*] Response: '{}'.".format(response.text)  
```

The flag is the following.

```  
35C3_FLOATING_POINT_PROBLEMS_I_FEEL_B4D_FOR_YOU_SON  
```

Original writeup (https://github.com/m3ssap0/CTF-
Writeups/blob/master/35C3%20Junior%20CTF/Conversion%20Error/README.md).