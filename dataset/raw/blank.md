Firstly, let's take a look at the source code. We can see that it initializes
an empty database with a users table:  
```js  
const db = new sqlite3.Database(':memory:');

db.serialize(() => {  
 db.run('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username
TEXT, password TEXT)');  
});  
```  
  
Next let's look at the login endpoint:  
```js  
app.post('/login', (req, res) => {  
 const username = req.body.username;  
 const password = req.body.password;

 db.get('SELECT * FROM users WHERE username = "' + username + '" and password
= "' + password+ '"', (err, row) => {  
   if (err) {  
     console.error(err);  
     res.status(500).send('Error retrieving user');  
   } else {  
     if (row) {  
       req.session.loggedIn = true;  
       req.session.username = username;  
       res.send('Login successful!');  
     } else {  
       res.status(401).send('Invalid username or password');  
     }  
   }  
 });  
});  
```  
So we have a pretty straightforward SQL injection here. The only problem we
have is that the database is completely empty, so we don't have any users that
can be selected. Therefore, we'll have to find some other way to introduce
additional records into the query result.

Since the code is only checking if at least one row exists, and it doesn't
care what the contents of the row are, we can simply set the username to
admin, and the password to an injection that will insert additional rows. We
can do this using a union injection. Even though the database is empty, there
are still some builtin tables like `sqlite_master` that are still there, so we
can select from that table.

This is the payload I used:

Username: `admin`

Password: `" union select rootpage, type, name from sqlite_master --`

Then, we can go to `/flag`, and we get the flag:
`ictf{sqli_too_powerful_9b36140a}`