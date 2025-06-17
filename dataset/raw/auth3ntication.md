## Web Auth3ntication challenge

**Category:** javascript **Points:** 200

### Description  
```  
Login if you can. It is protected by so called secure algorithm. Let's see how
secure it is...

http://35.200.218.73/  
```

### Solution  
This challenge is a XOR authentication system implemented with javascript :(.  
To understand the logic of the challenge we should first look at the provided
code:

```html  
<form action="#" method="post">  
		<label>Username</label>  
		<input class="form-control" type="text" name="username" id="cuser" placeholder="Username" />  
		<label>Password</label>  
		<input type="password" class="form-control" name="password" id="cpass" placeholder="Password" />  
		<input type="submit" style="margin-top: 12px;" value="Login" class="form-control btn btn-success c_submit" />  
	</form>  
<script type="text/javascript">  
		$(".c_submit").click(function(event) {  
			event.preventDefault();  
			var u = $("#cpass").val();  
			var k = $("#cuser").val();  
			var func = "\x0d\x13\x45\x17\x48\x09\x5e\x4b\x17\x3c\x1a\x1f\x2b\x1b\x7a\x0c\x1f\x66\x0b\x1a\x3e\x51\x0b\x41\x11\x58\x17\x4d\x55\x16\x42\x01\x52\x4b\x0f\x5a\x07\x00\x00\x07\x06\x40\x4d\x07\x5a\x07\x14\x19\x0b\x07\x5a\x4d\x03\x47\x01\x13\x43\x0b\x06\x50\x06\x13\x7a\x02\x5d\x4f\x5d\x18\x09\x41\x42\x15\x59\x48\x4d\x4f\x59\x1d\x43\x10\x15\x00\x1a\x0e\x17\x05\x51\x0d\x1f\x1b\x08\x1a\x0e\x03\x1c\x5d\x0c\x05\x15\x59\x55\x09\x0d\x0b\x41\x0e\x0e\x5b\x10\x5b\x01\x0d\x0b\x55\x17\x02\x5a\x0a\x5b\x05\x10\x0d\x52\x43\x40\x15\x46\x4a\x1d\x5f\x4a\x14\x48\x4b\x40\x5f\x55\x10\x42\x15\x14\x06\x07\x46\x01\x55\x16\x42\x48\x10\x4b\x49\x16\x07\x07\x08\x11\x18\x5b\x0d\x18\x50\x46\x5c\x43\x0a\x1c\x59\x0f\x43\x17\x58\x11\x04\x14\x48\x57\x0f\x0a\x46\x17\x48\x4a\x07\x1a\x46\x0c\x19\x12\x5a\x22\x1f\x0d\x06\x53\x43\x1b\x54\x17\x06\x1a\x0d\x1a\x50\x43\x18\x5a\x16\x07\x14\x4c\x4a\x1d\x1e";  
			buf = "";  
			if(k.length == 9) {  
				for(i = 0, j = 0; i < func.length; i++) {  
					c = parseInt(func.charCodeAt(i));  
					c = c ^ k.charCodeAt(j);  
					if(++j == k.length) {  
						j = 0;  
					}  
					buf += eval('"' + a(x(c)) + '"');  
				}  
				eval(buf);  
  
			} else {  
				$("#cresponse").html("<div class='alert alert-danger'>Invalid creds...</div>");  
			}  
		});  
  
		function a(h) {  
			if(h.length != 2) {  
				h = "\x30" + h;  
			}  
			return "\x5c\x78" + h;  
		}  
  
		function x(d) {  
			if(d < 0) {  
				d = 0xFFFFFFFF + d + 1;  
			}  
			return d.toString(16).toUpperCase();  
		}  
</script>  
```

As you can see, the provided username should be at least 9 characters. the pw
parameter (password) is not even used in any part of code. So we ignore it.

By looking at the code, we understand that the provided user value, will be
XORed with the ```func``` variable 9 characters 9 characters, chunk by chunk.  
So we know that username is actaully the key for xor encryption.

At first glance, Code look a little difficult to understand but after digging
deeper, u can see that it just does a simple xor as follow:

- Get ascii equivalent value for each character of func and provided user value, char by char. (if reached 9, then reset and start from first character of user)

- Xor parseInt(func.charCodeAt(i)) ^ k.charCodeAt(j) => for example 13 ^ 97 (chr("a") == 97) 

- Then return it back to ascii with x() and a(h) function. These functions just put \x before each xored value and x(h) add a 0 before hex value if len!=2.

- And finally all xored values are added together and stored in buff value which will be passed to ```eval``` function at end.

As you can see logic is simple. but we need to find the key. HOW!

I tried many different solutions, including looking char by char and check if
response is started with any of codes below to find key form it:

```  
- var flag  
- $("#cresponse  
- console.log  
flag =  
```  
and so on. but none of them worked.  
I used ```http://xor.pw/#``` for testing this values.

### Final solution

So after working on challenge manually, this solution came to mind

- First iterate over all characters of func. choose a text that u are sure is in the decrypted value. for example "flag"

- create a temp user value with same size of func. then move this text one by one to right and each time do the same functionality xor to it. (I mean the exact functionallity that authencation system is using, by xoring a user input value with a func variable.) 

- Each time you're doing this, store the key. which is 9 characters at the position of that key. (you should fix offsets. for example if it's in the second iteration, key should be like this ```x<key>xxxx``` and so on.)

- Now again provide this key to the provided code at challenge and print output

- You will have 214 different results, you should look through them and see if any is readable?

Here is the code:

```javascript

var u = $("#cpass").val();  
var k = $("#cuser").val();  
var func =
"\x0d\x13\x45\x17\x48\x09\x5e\x4b\x17\x3c\x1a\x1f\x2b\x1b\x7a\x0c\x1f\x66\x0b\x1a\x3e\x51\x0b\x41\x11\x58\x17\x4d\x55\x16\x42\x01\x52\x4b\x0f\x5a\x07\x00\x00\x07\x06\x40\x4d\x07\x5a\x07\x14\x19\x0b\x07\x5a\x4d\x03\x47\x01\x13\x43\x0b\x06\x50\x06\x13\x7a\x02\x5d\x4f\x5d\x18\x09\x41\x42\x15\x59\x48\x4d\x4f\x59\x1d\x43\x10\x15\x00\x1a\x0e\x17\x05\x51\x0d\x1f\x1b\x08\x1a\x0e\x03\x1c\x5d\x0c\x05\x15\x59\x55\x09\x0d\x0b\x41\x0e\x0e\x5b\x10\x5b\x01\x0d\x0b\x55\x17\x02\x5a\x0a\x5b\x05\x10\x0d\x52\x43\x40\x15\x46\x4a\x1d\x5f\x4a\x14\x48\x4b\x40\x5f\x55\x10\x42\x15\x14\x06\x07\x46\x01\x55\x16\x42\x48\x10\x4b\x49\x16\x07\x07\x08\x11\x18\x5b\x0d\x18\x50\x46\x5c\x43\x0a\x1c\x59\x0f\x43\x17\x58\x11\x04\x14\x48\x57\x0f\x0a\x46\x17\x48\x4a\x07\x1a\x46\x0c\x19\x12\x5a\x22\x1f\x0d\x06\x53\x43\x1b\x54\x17\x06\x1a\x0d\x1a\x50\x43\x18\x5a\x16\x07\x14\x4c\x4a\x1d\x1e";  
buf = "";

// create a temp key (we should fill it later)  
tmp = ""  
for (z=0; z<func.length; z++) {  
	tmp += "a";  
}

// a simple function to shift key based on position on tmp  
String.prototype.replaceAt=function(index, replacement) {  
   return this.substr(0, index) + replacement+ this.substr(index +
replacement.length);  
}

// this is the known text that we know will be in the decrypted response.  
var knownText = "\").html(\"";

// main functionallity  
for(w=0; w<func.length;w++) {  
	buf = ""

	//   
	var g = tmp;  
	var arr = g.split("");  
	arr.splice(w, knownText.length, knownText);  
	var result = arr.join("");

	k = result.substring(0, func.length);

	for(i = 0, j = 0; i < func.length; i++) {  
		c = parseInt(func.charCodeAt(i));  
		c = c ^ k.charCodeAt(j);  
		if(++j == k.length) {  
			j = 0;  
		}  
		buf += eval('"' + a(x(c)) + '"');  
	}

	var temp = buf.substring(w, w+knownText.length);  
	console.log(temp);  
	// now temp is the key if the response contains knownText value.

	// Now fix position of temp in key, if len<9, add a -> but in the right position.  
	tt = 'aaaaaaaaa';  
	for (gg=0; gg<knownText.length; gg++) {  
		var position = ((w%9)+gg)%9;  
		tt = tt.replaceAt(position, temp[gg])  
	}

	console.log(tt);

	buf = "";

	// Now we imagine that we have the key. so decrypt it with this flag for func.length times.  
	k = tt;  
	for(i = 0, j = 0; i < func.length; i++) {  
		c = parseInt(func.charCodeAt(i));  
		c = c ^ k.charCodeAt(j);  
		if(++j == k.length) {  
			j = 0;  
		}  
		buf += eval('"' + a(x(c)) + '"');  
	}  
	console.log(buf);  
	console.log(buf.length);  
	// eval(buf);

	console.log("============");  
}

function a(h) {  
	if(h.length != 2) {  
		// \x30 == 0  
		h = "\x30" + h;  
	}  
	// \x5c\x78 == \x  
	return "\x5c\x78" + h;  
}

function x(d) {  
	if(d < 0) {  
		d = 0xFFFFFFFF + d + 1;  
	}  
	return d.toString(16).toUpperCase();  
}  
```

I tried different values for ```knownText``` variable. non of them worked
including

```  
flag{  
$("#cresponse  
var  
```

finally this came up to mind:  
```javascript  
var knownText = "\").html(\"";  
```

running code, shows that for key ```dumbh4ck5```, decrypted value is readable.

response will be:  
```  
if(u == "XorIsNotSooS3cur3") { if(document.location.href.indexOf("?p=") == -1)
{ document.location = document.location.href + "?p=" + u; } } else {
$("#cresponse").html("<div class='error'>Wrong password sorry.")}  
```

So visiting ```http://35.200.218.73/?p=XorIsNotSooS3cur3``` will give us the
flag.

peace:)  

Original writeup (https://github.com/Execut3/Participated-
CTF/tree/master/2018/BSides%20Delhi%20CTF/Web200).