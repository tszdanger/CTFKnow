After opening and exploring `server.go` script, you can find line 141 in main
func:  
`       http.HandleFunc("/login", loginHandler)`.

Now we understand, that url with `/login` at the end calls `loginHandler`
function.

Let's look inside:

```  
func loginHandler(w http.ResponseWriter, r *http.Request) {

	if err := r.ParseForm(); err != nil {  
		fmt.Fprintf(w, "500: %v", err)  
		return  
	}  
	username := r.FormValue("username")  
	password := r.FormValue("password")

	if strings.ToLower(username) != "admin" {  
		fmt.Fprintf(w, "User not found!\n")  
		return  
	}

	if MD5([]byte(password)) == "90829146b3603e2e7daf5031b2103e9e" {  
		fmt.Fprintf(w, "Login successful! Flag is %s\n", flag)  
	} else {  
		fmt.Fprintf(w, "Password is not correct!\nExpected %s, got %s\n", "90829146b3603e2e7daf5031b2103e9e", MD5([]byte(password)))  
	}  
}  
```  
So, there is 2 values which server checks: `username` and `password`.

It means, that correct url-request looks like this:
`http://tasks.kksctf.ru:30020/login?username=admin&password=qwerty`

(Of course, we want to log in as admin, and `admin` is common username for
it).  
***  
With `qwerty` password, server returns this:  
```  
Password is not correct!  
Expected 90829146b3603e2e7daf5031b2103e9e, got
67e129628458ce06fbc5bb76a58c5ca4  
```  
Because, as we have seen earlier, `MD5()` func result compares with
`90829146b3603e2e7daf5031b2103e9e`.

To understand, how we can hack it, let's dive into this function:  
```  
func MD5(data []byte) string {  
	b := digest(data)  
  
	return hex.EncodeToString(b[:])  
}  
```  
and further into `digest(data)`:  
```  
func digest(data []byte) [16]byte {  
	digest := md5.Sum(data)  
  
	s := len(data) / 4  
	if s > 4 {  
		s = 4  
	}  
  
	for ss := 0; ss < s; ss++ {  
		var F uint32

		F = ^F

		for i := 0; i < 4; i++ {  
			F = (F << 8) ^ table[(F>>24)^(uint32(data[ss*4+i])&0xff)]  
		}  
		F = ^F

		digest[ss*4+3] = byte((F >> 24) & 0xff)  
		digest[ss*4+2] = byte((F >> 16) & 0xff)  
		digest[ss*4+1] = byte((F >> 8) & 0xff)  
		digest[ss*4+0] = byte(F & 0xff)  
	}  
  
	return digest  
}  
```  
Let's look at:  
```  
s := len(data) / 4  
if s > 4 {  
   s = 4  
}  
```  
What is `s`? It represents, how many groups of 4 bytes are in our password

(If password length > 16, than 17, 18 and other characters simply ignores).

Further we iterate not through every byte, but every group of 4 bytes:  
```  
for ss := 0; ss < s; ss++ {  
   ...  
}  
```  
It's important. Algorithm processes the password in groups of 4 bytes
**separately**.

Notice, that if password is less than 4 characters, program never gets into
this loop, and the whole function return just password's md5 hash.

At the end of this loop there are such lines:  
```  
digest[ss*4+3] = byte((F >> 24) & 0xff)  
digest[ss*4+2] = byte((F >> 16) & 0xff)  
digest[ss*4+1] = byte((F >> 8) & 0xff)  
digest[ss*4+0] = byte(F & 0xff)  
```  
We can see, that 4 bytes of `F` variable (`F` is `uint32`, so it takes only 4
bytes) writes to the current group of 4 bytes.

First useful fact, is that bytes are written in reverse order (little-endian).

Second — is that every byte is rewritten, so nothing remains of md5 and we
don't need to reverse it!

Final hash - is simply some 4 numbers (`F`).

Now we can try to reverse this function deeper to find characters from `F`,
but let's notice, that we can simply bruteforce every such group of 4
characters!

Byte is 256 possible values, so 4 bytes is 256⁴ = 4294967296, which is not too
much.  
***  
But we need to gets this F's to compare with. Here is our admin's password
hash: `90829146b3603e2e7daf5031b2103e9e`.

Firstly, split it into 4 bytes groups: `90829146 b3603e2e 7daf5031 b2103e9e`.

Now remember, that it is little-endian, so reverse bytes for every number:
`46918290 2e3e60b3 3150af7d 9e3e10b2`.

Now we have F's to compare with!

So, here is dirty bruteforce code (from `F = ^F` to `F = ^F` is original
algorithm code):  
```  
	for a := byte(0); a < 255; a++ {  
		for b := byte(0); b < 255; b++ {  
			for c := byte(0); c < 255; c++ {  
				for d := byte(0); d < 255; d++ {  
					var F uint32  
					F = ^F  
					for i := 0; i < 4; i++ {  
						if i == 0 {  
							F = (F << 8) ^ table[(F>>24)^(uint32(a)&0xff)]  
						}  
						if i == 1 {  
							F = (F << 8) ^ table[(F>>24)^(uint32(b)&0xff)]  
						}  
						if i == 2 {  
							F = (F << 8) ^ table[(F>>24)^(uint32(c)&0xff)]  
						}  
						if i == 3 {  
							F = (F << 8) ^ table[(F>>24)^(uint32(d)&0xff)]  
						}  
					}  
					F = ^F  
  
					if F == 0x46918290 {  
						fmt.Println("=== 1 ===")  
						fmt.Println(a)  
						fmt.Println(b)  
						fmt.Println(c)  
						fmt.Println(d)  
					}  
					if F == 0x2e3e60b3 {  
						fmt.Println("=== 2 ===")  
						fmt.Println(a)  
						fmt.Println(b)  
						fmt.Println(c)  
						fmt.Println(d)  
					}  
					if F == 0x3150af7d {  
						fmt.Println("=== 3 ===")  
						fmt.Println(a)  
						fmt.Println(b)  
						fmt.Println(c)  
						fmt.Println(d)  
					}  
					if F == 0x9e3e10b2 {  
						fmt.Println("=== 4 ===")  
						fmt.Println(a)  
						fmt.Println(b)  
						fmt.Println(c)  
						fmt.Println(d)  
					}  
				}  
			}  
		}  
	}  
```  
After about 20 seconds we get this:  
```  
=== 1 ===  
41  
82  
41  
99  
=== 4 ===  
71  
74  
75  
45  
=== 3 ===  
75  
62  
65  
119  
=== 2 ===  
107  
52  
114  
94  
```  
Turn it to right order: `41 82 41 99 107 52 114 94 75 62 65 119 71 74 75 45`

And then to ASCII: `)R)ck4r^K>AwGJK-`  
***  
Input it as password:
`http://tasks.kksctf.ru:30020/login?username=admin&password=)R)ck4r^K%3EAwGJK-`
and server returns...  
```  
Login successful! Flag is kks{1f_s0meth1ng_called_md5_1t_d0esnt_have_t0_be}  
```  
Nice, we found the flag without deep reversing! :D  

Original writeup (https://github.com/RichardTry/kksctf-hashfunction).