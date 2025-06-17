## Web

### Paster

flag: flag{x55_i5Nt_7hA7_bAD_R1Gh7?}

Simple XSS attack, call alert on the screen to get flag

#### payload

```  
$ <svg/onload=alert(1)>  
```

### Super Secret Flag Vault

flag: flag{!5_Ph9_5TronGly_7yPed?}

php hash issue(weak type comparsion)

```lang=php  
$hash = "0e770334890835629000008642775106";  
if(md5($_REQUEST["combination"]) == $hash){  
 echo "  
The Flag is flag{...}  
";  
}  
```

Since hash is all digits, and "==", it simply means $hash = 0  
set Combination to 240610708 to solve the problem  
md5(240610708) == 0e46... == 0

### CookieForge

**Failed**

Got the cookie, seems to be in jwt token  
But can't forge(because of the last to dot, can't know what it means)

session:
eyJmbGFnc2hpcCI6ZmFsc2UsInVzZXJuYW1lIjoiYWRtaW4ifQ.XqHKwQ.VzPUBGzCO5kAFQ-k1DkzKY7hA80

First one is

> {"flagship":false,"username":"admin"}

simpley change flagship to true won't work because of the latest two
terms(kind of signature)

### Custom UI

**Failed**

Seems to be XXE attack

### Online BirthDay Party

**Failed**

SQL-Injection

Original writeup (https://github.com/jimmychang851129/CTF-
writeup/tree/master/hackpack-2020/web).