## HXP CTF 2022 - Required (RE 385)  
### 10-12/03/2023 (48hr)  
___

## Description  
  
**Difficulty estimate:** easy - easy

**Points:** round(1000 · min(1, 10 / (9 + [17 solves]))) = 385 points

**Description:**

*I have written a super safe flag encryptor. I’m sure nobody can figure out what my original flag was:*

```  
0xd19ee193b461fd8d1452e7659acb1f47dc3ed445c8eb4ff191b1abfa7969  
```

*Dockerfile for your convenience / to ensure correct environment.*

**Download:**  
```  
required-27edfc0c02c5f748.tar.xz (11.4 KiB)  
```  
___

## Solution

Let's start with the `Dockerfile`:  
```bash  
# see docker-compose.yml

FROM node:19

RUN useradd --create-home --shell /bin/bash ctf  
WORKDIR /home/ctf

COPY flag files/* /home/ctf/

USER ctf

CMD sh run.sh  
```

This challenge contains **250** JavaScript files under `files/` directory:  
```  
ispo@ispo-glaptop2:~/ctf/hxp_2022/required$ ls files/*.js | wc  
   250     250    3226  
```

Everything starts from `files/run.sh`:  
```bash  
#!/bin/bash

if [ "$(node required.js)" =
"0xd19ee193b461fd8d1452e7659acb1f47dc3ed445c8eb4ff191b1abfa7969" ]; then  
   echo ":)"  
else  
   echo ":("  
fi  
```

`files/required.js` contains a long sequence of `require` calls:  
```javascript  
f=[...require('fs').readFileSync('./flag')]  // load flag  
require('./28')(753,434,790)  
require('./157')(227,950,740)  
/* ... ~1228 more `require` calls ... */  
require('./725')(9,30,288)  
require('./37')(f)  // print encrypted flag  
````

Let's start looking into some of these files:  
```  
ispo@ispo-glaptop2:~/ctf/hxp_2022/required$ cat files/103.js  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[i]*=f[25],f[i]&=0xff)

ispo@ispo-glaptop2:~/ctf/hxp_2022/required$ cat files/118.js  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[i]*=f[8],f[i]&=0xff)

ispo@ispo-glaptop2:~/ctf/hxp_2022/required$ cat files/1.js  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[i]*=-1,f[i]&=0xff)  
```

These files look very similar and they are probably automatically generated.
We quickly dump  
all these files to see how they differ from each other:  
```bash  
for i in files/*.js; do echo -e "\n-------------------------- $i"; cat $i; done | less  
```

All files have the same format (with very few exceptions that we will see in a
moment):  
```javascript  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],/*f
operation */)  
```

Each time, only one of the `i`, `j` and `t` variables is used to access a
single character from  
`f` -which contains the flag- and do some transformations to it. Some
operations (such as addition)  
have an extra statement `f[i]&=0xff` to ensure that the result is only **1**
byte. Let's now look  
at some examples of all different operations:  
```js  
// add, sub, mul, div  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[j]+=f[i],f[j]&=0xff)  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[j]-=f[t],f[j]&=0xff)  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[i]*=f[25],f[i]&=0xff)  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[i]/=f[9],f[i]&=0xff)

// xor  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[t]^=f[i])

// not  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[i]=~f[i]&0xff)

// rol (operates on the same f element)  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[j]=f[j]<<1&0xff|f[j]>>7)

// neg (operates on the same f element)  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[i]*=-1,f[i]&=0xff)

// left and right shift (operates on the same f element)  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[i]<<=f[j],f[i]&=0xff)  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[i]>>=f[j],f[i]&=0xff)

// xor with shifted by 1 (operates on the same f element)  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[j]=f[j]^(f[j]>>1))

// weirdo calculation (operates on the same f element)  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],  
                        f[i]=(((f[i]*0x0802&0x22110)|(f[i]*0x8020&0x88440))*0x10101>>>16)&0xff)  
```

There are also some files which are different:  
```js  
// 37.js    ~> print flag  
module.exports=(i,j,t)=>(i+=[],j+"",t=(t+{}).split("[")[0],console.log(require('./314')(i)))

// 314.js  ~> flag to hex  
module.exports=(i,j,t)=>(i+=[],j+"",t=(t+{}).split("[")[0],s='0x',  
                        i.split(',').forEach(b=>(s+=('0'+(b-0).toString(16)).slice(-2))),s)

// 556.js   ~> dtor  
module.exports=(i,j,t)=>(i+=[],j+"",t=(t+{}).split("[")[0],  
                        Object.keys(require.cache).forEach(i=>{delete require.cache[i]}))

// 289.js  ~> build json obj  
//      > i = 123; j = 998  
//          ['__proto__']: { data: { name: './123', exports: [Object] }, path:
'./' }  
//      > json['__proto__']['data']['exports']  
//          { '.': './998.js' }  
module.exports=(i,j,t)=>(  
   i+=[],  // if this none, add the empty array to give it a type  
   j+"",   // same for this  
   t=(t+{}).split("[")[0], // same for this  
   JSON.parse(`{"__proto__":{"data":{"name":"./${i}","exports":{".":
"./${j}.js"}},"path": "./"}}`))

/* all these are the same but different combination of i,j,t is used. */

// 28.js  
module.exports=(i,j,t)=>(i+=[],j+"",t=(t+{}).split("[")[0],o={},  
   Object.entries(require('./289')(i,j)).forEach(  
       ([K,V])=>Object.entries(V).forEach(([k,v])=>(o[K]=o[K]||{},o[K][k]=v))),require(`./${i}`))

// 157.js  
module.exports=(i,j,t)=>(i+=[],j+"",t=(t+{}).split("[")[0],o={},  
   Object.entries(require('./289')(i,t)).forEach(  
       ([K,V])=>Object.entries(V).forEach(([k,v])=>(o[K]=o[K]||{},o[K][k]=v))),require(`./${i}`))

// 299.js  
module.exports=(i,j,t)=>(i+=[],j+"",t=(t+{}).split("[")[0],o={},  
   Object.entries(require('./289')(t,j)).forEach(  
       ([K,V])=>Object.entries(V).forEach(([k,v])=>(o[K]=o[K]||{},o[K][k]=v))),require(`./${t}`))

// 394.js  
module.exports=(i,j,t)=>(i+=[],j+"",t=(t+{}).split("[")[0],o={},  
   Object.entries(require('./289')(t,i)).forEach(  
       ([K,V])=>Object.entries(V).forEach(([k,v])=>(o[K]=o[K]||{},o[K][k]=v))),require(`./${t}`))

// 555.js  
module.exports=(i,j,t)=>(i+=[],j+"",t=(t+{}).split("[")[0],o={},  
   Object.entries(require('./289')(j,t)).forEach(  
       ([K,V])=>Object.entries(V).forEach(([k,v])=>(o[K]=o[K]||{},o[K][k]=v))),require(`./${j}`))

// 736.js  
module.exports=(i,j,t)=>(i+=[],j+"",t=(t+{}).split("[")[0],o={},  
   Object.entries(require('./289')(j,i)).forEach(  
       ([K,V])=>Object.entries(V).forEach(([k,v])=>(o[K]=o[K]||{},o[K][k]=v))),require(`./${j}`))  
```

To understand what the last **6** files do, we run them in `node`:  
```js  
> i=1111,j=2222,t=3333  
3333

>  i+=[],j+"",t=(t+{}).split("[")[0],o={},  
...     Object.entries(require('./289')(i,j)).forEach(  
...
([K,V])=>Object.entries(V).forEach(([k,v])=>(o[K]=o[K]||{},o[K][k]=v))),  
...         require(`./${i}`)  
Uncaught Error: Cannot find module
'/home/ispo/ctf/hxp_2022/required/files/2222.js'

???  
```

Even though we require `i`, program actually tries to load
`required/files/2222.js` (which  
corresponds to `j`) and fails. This has to do with the modification of
`__proto__` (for more  
details about it, please take a look  
[here](https://levelup.gitconnected.com/the-mysterious-javascript-objects-
proto-property-67b7c6b3140c)).  
First, we invoke `require('./289')(i,j)`, so `exports` takes the value of the
**2nd** parameter (`j`).  
If we replace it with `require('./289')(i,tj)`, we will get a different error:  
```js  
> i+=[],j+"",t=(t+{}).split("[")[0],o={},  
...     Object.entries(require('./289')(i,t)).forEach(  
...
([K,V])=>Object.entries(V).forEach(([k,v])=>(o[K]=o[K]||{},o[K][k]=v))),  
...         require(`./${i}`)  
Uncaught Error: Cannot find module
'/home/ispo/ctf/hxp_2022/required/files/3333.js'  
   at createEsmNotFoundErr (node:internal/modules/cjs/loader:1016:15)  
   at finalizeEsmResolution (node:internal/modules/cjs/loader:1009:15)  
   at trySelf (node:internal/modules/cjs/loader:505:12)  
   at Module._resolveFilename (node:internal/modules/cjs/loader:972:24)  
   at Module._load (node:internal/modules/cjs/loader:841:27)  
   at Module.require (node:internal/modules/cjs/loader:1061:19)  
   at require (node:internal/modules/cjs/helpers:103:18) {  
 code: 'MODULE_NOT_FOUND',  
 path: '/home/ispo/ctf/hxp_2022/required/files/package.json'  
}  
```

## Extracting Actual Computations

Program takes a flag as input, it invokes many many `require` functions to
make various operations  
in `f` and then prints the result. Our goal is to crack the flag from the
encrypted version:  
```  
   0xd19ee193b461fd8d1452e7659acb1f47dc3ed445c8eb4ff191b1abfa7969  
```

The first task is to find out exactly which computations take place. I first
tried to parse the  
`required.js` file and get the order of the JavaScript files. But it didn't
work as they were  
many files that seem to be missing, so I tried another approach:  
**I appended a console.log() statement to every .js files and I run it through
the flag.**.  
This approach works because there are no if-conditions; no matter the flag
input, the exact same  
computations are being applied. Function `patch_js_files` does the patching:  
```python  
def patch_js_files(root_dir):  
   """Patches all js files to append a console.log() statement."""  
   for root, dirs, files in os.walk(root_dir):  
       for file in files:  
           if not file.endswith(".js"):  
               continue

           # Blacklisted files.  
           if file in ['289.js', '37.js', '314.js', '556.js', '28.js', '157.js',  
                       '299.js', '394.js', '555.js', '736.js', 'required.js']:  
               continue

           # Read file  
           with open(os.path.join(root_dir, file)) as fp:  
               content = fp.read().strip()

           # Verify that all files start the same.          
           prolog = 'module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],'  
           if not content.startswith(prolog):  
               raise Exception(f'Invalid file content: {content}')

           line = content[len(prolog):]        # Drop the prolog              
           line = line[:-1]                    # Drop the last ')'  
           stmt = line.split(',')[0]           # Get the 1st operation on f  
                                               # (we can have an extra f[i]&=0xff too)  
           stmt = stmt.replace('i', '${i}')    # Substitute parameters with formatted strings  
           stmt = stmt.replace('j', '${j}')  
           stmt = stmt.replace('t', '${t}')

           # Put operation into a console.log() statement with i,j,t being substituted  
           line = prolog + line + f",console.log(`{stmt}`))"  
  
           print(f'[+] Patching {file}: {line}')

           # Write patched file back.  
           with open(os.path.join(root_dir, file), 'w') as fp:  
               fp.write(line)  
```

This is how the new files look like:  
```javascript  
// 1.js  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[i]*=-1,f[i]&=0xff,  
   console.log(`f[${i}]*=-1`))

// 506.js  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[t]=f[t]^(f[t]>>1),  
   console.log(`f[${t}]=f[${t}]^(f[${t}]>>1)`))

// 743.js  
module.exports=(i,j,t)=>(i%=30,j%=30,t%=30,i+=[],j+"",t=(t+{}).split("[")[0],f[i]*=f[2],f[i]&=0xff,  
   console.log(`f[${i}]*=f[2]`))  
```

Then we simply run `node required.js` and we dump all the equations:  
```  
f[17]+=f[5]  
f[29]=~f[29]&0xff  
f[3]^=f[11]  
f[6]=f[6]<<7&0xff|f[6]>>1  
f[2]=~f[2]&0xff  
f[20]=f[20]<<7&0xff|f[20]>>1  
f[23]=f[23]^(f[23]>>1)  
f[15]=f[15]^(f[15]>>1)  
f[9]^=f[1]  
f[9]^=f[4]  
f[16]=f[16]^(f[16]>>1)  
f[11]=f[11]<<1&0xff|f[11]>>7  
f[28]=~f[28]&0xff  
f[0]=~f[0]&0xff  
f[16]+=f[13]  
f[14]+=f[29]  
f[13]=~f[13]&0xff  
f[26]-=f[7]  
f[26]-=f[0]  
f[18]-=f[29]  
f[8]=f[8]<<1&0xff|f[8]>>7  
f[4]=f[4]^(f[4]>>1)  
f[5]-=f[7]  
f[10]^=f[29]  
f[15]^=f[20]  
f[22]=f[22]<<7&0xff|f[22]>>1  
f[4]^=f[15]  
f[13]-=f[3]  
f[5]=f[5]<<1&0xff|f[5]>>7  
f[26]=f[26]<<7&0xff|f[26]>>1  
f[14]^=f[21]  
f[29]=f[29]<<7&0xff|f[29]>>1  
f[1]-=f[4]  
f[4]=~f[4]&0xff  
f[13]-=f[18]  
f[16]=f[16]<<1&0xff|f[16]>>7  
f[11]=f[11]<<7&0xff|f[11]>>1  
f[7]-=f[6]  
f[11]-=f[20]  
f[23]=~f[23]&0xff  
f[4]+=f[3]  
f[26]+=f[22]  
f[16]=f[16]<<1&0xff|f[16]>>7  
f[11]+=f[8]  
f[8]^=f[9]  
f[24]+=f[14]  
f[29]-=f[24]  
f[4]-=f[18]  
f[1]=f[1]<<7&0xff|f[1]>>1  
f[20]=f[20]<<7&0xff|f[20]>>1  
f[20]=f[20]<<7&0xff|f[20]>>1  
f[20]=~f[20]&0xff  
f[11]^=f[2]  
f[20]-=f[24]  
f[2]+=f[6]  
f[10]+=f[24]  
f[25]=f[25]^(f[25]>>1)  
f[12]^=f[14]  
f[25]=f[25]<<7&0xff|f[25]>>1  
f[15]=f[15]<<1&0xff|f[15]>>7  
f[25]+=f[12]  
f[2]+=f[5]  
f[0]-=f[11]  
f[6]-=f[1]  
f[6]+=f[17]  
f[29]-=f[9]  
f[7]=~f[7]&0xff  
f[2]+=f[5]  
f[22]-=f[2]  
f[24]=f[24]<<1&0xff|f[24]>>7  
f[20]=f[20]^(f[20]>>1)  
f[28]=f[28]^(f[28]>>1)  
f[15]^=f[20]  
f[3]=f[3]<<1&0xff|f[3]>>7  
f[17]=f[17]<<7&0xff|f[17]>>1  
f[11]=f[11]<<7&0xff|f[11]>>1  
f[18]=~f[18]&0xff  
f[13]=f[13]^(f[13]>>1)  
f[15]-=f[2]  
f[9]+=f[20]  
f[6]^=f[1]  
f[1]-=f[13]  
f[0]-=f[4]  
f[14]=~f[14]&0xff  
f[17]=f[17]<<1&0xff|f[17]>>7  
f[17]=f[17]<<7&0xff|f[17]>>1  
f[14]=f[14]^(f[14]>>1)  
f[24]-=f[7]  
f[16]^=f[6]  
f[13]+=f[9]  
f[1]-=f[10]  
f[28]=f[28]<<1&0xff|f[28]>>7  
f[25]-=f[22]  
f[14]=f[14]^(f[14]>>1)  
f[2]=f[2]<<7&0xff|f[2]>>1  
f[2]^=f[15]  
f[17]=f[17]<<7&0xff|f[17]>>1  
f[3]-=f[22]  
f[23]=f[23]<<7&0xff|f[23]>>1  
f[11]=f[11]<<7&0xff|f[11]>>1  
f[9]+=f[16]  
f[7]=f[7]<<7&0xff|f[7]>>1  
f[6]=~f[6]&0xff  
f[5]+=f[15]  
f[6]-=f[17]  
f[7]-=f[6]  
f[3]+=f[28]  
f[1]^=f[18]  
f[22]-=f[5]  
f[14]-=f[2]  
f[21]^=f[22]  
f[4]-=f[29]  
f[26]=(((f[26]*0x0802&0x22110)|(f[26]*0x8020&0x88440))*0x10101>>>16)&0xff  
f[17]-=f[18]  
f[17]=f[17]<<1&0xff|f[17]>>7  
f[16]-=f[3]  
f[25]^=f[21]  
f[14]+=f[9]  
f[1]+=f[13]  
f[0]^=f[1]  
f[1]^=f[28]  
f[14]=~f[14]&0xff  
f[27]=(((f[27]*0x0802&0x22110)|(f[27]*0x8020&0x88440))*0x10101>>>16)&0xff  
f[9]^=f[2]  
f[17]=f[17]<<7&0xff|f[17]>>1  
f[13]^=f[1]  
f[5]^=f[13]  
f[10]^=f[0]  
f[12]^=f[1]  
f[2]=~f[2]&0xff  
f[1]=f[1]<<7&0xff|f[1]>>1  
f[11]=f[11]<<1&0xff|f[11]>>7  
f[9]^=f[28]  
f[3]=(((f[3]*0x0802&0x22110)|(f[3]*0x8020&0x88440))*0x10101>>>16)&0xff  
f[19]=f[19]<<1&0xff|f[19]>>7  
f[16]-=f[9]  
f[8]=f[8]<<1&0xff|f[8]>>7  
f[28]=f[28]<<1&0xff|f[28]>>7  
f[12]-=f[3]  
f[25]=(((f[25]*0x0802&0x22110)|(f[25]*0x8020&0x88440))*0x10101>>>16)&0xff  
f[14]=(((f[14]*0x0802&0x22110)|(f[14]*0x8020&0x88440))*0x10101>>>16)&0xff  
f[11]=f[11]<<7&0xff|f[11]>>1  
f[6]+=f[28]  
f[6]^=f[5]  
f[28]^=f[0]  
f[10]-=f[22]  
f[8]=f[8]^(f[8]>>1)  
f[19]=f[19]<<7&0xff|f[19]>>1  
f[26]-=f[14]  
f[25]^=f[28]  
f[15]-=f[17]  
f[12]^=f[4]  
f[25]+=f[4]  
f[11]=~f[11]&0xff  
f[1]=f[1]<<7&0xff|f[1]>>1  
f[9]+=f[28]  
f[4]^=f[18]  
f[15]=~f[15]&0xff  
f[12]=f[12]<<1&0xff|f[12]>>7  
f[12]=f[12]<<7&0xff|f[12]>>1  
f[2]=f[2]^(f[2]>>1)  
f[6]=~f[6]&0xff  
f[10]=f[10]<<7&0xff|f[10]>>1  
f[20]=f[20]^(f[20]>>1)  
f[20]+=f[24]  
f[4]=f[4]<<1&0xff|f[4]>>7  
f[16]^=f[11]  
f[8]=~f[8]&0xff  
f[1]=(((f[1]*0x0802&0x22110)|(f[1]*0x8020&0x88440))*0x10101>>>16)&0xff  
f[4]+=f[18]  
f[5]=f[5]^(f[5]>>1)  
f[25]-=f[4]  
f[9]^=f[26]  
f[5]^=f[3]  
f[4]^=f[2]  
f[29]-=f[21]  
f[20]=f[20]<<1&0xff|f[20]>>7  
f[24]^=f[27]  
f[8]+=f[16]  
f[22]=f[22]<<7&0xff|f[22]>>1  
f[3]=f[3]<<7&0xff|f[3]>>1  
f[10]-=f[9]  
f[9]=f[9]^(f[9]>>1)  
f[24]^=f[25]  
f[9]=~f[9]&0xff  
f[1]=f[1]^(f[1]>>1)  
f[19]=f[19]<<1&0xff|f[19]>>7  
f[7]=f[7]<<7&0xff|f[7]>>1  
f[21]+=f[25]  
f[28]-=f[0]  
f[18]=f[18]<<7&0xff|f[18]>>1  
f[20]^=f[5]  
f[17]^=f[12]  
f[22]-=f[23]  
f[18]+=f[25]  
f[4]=f[4]<<1&0xff|f[4]>>7  
f[0]=f[0]<<1&0xff|f[0]>>7  
f[29]=f[29]<<1&0xff|f[29]>>7  
f[17]=f[17]<<1&0xff|f[17]>>7  
f[7]^=f[21]  
f[8]-=f[17]  
f[10]+=f[22]  
f[8]-=f[18]  
f[21]+=f[0]  
f[15]^=f[20]  
f[1]=f[1]<<1&0xff|f[1]>>7  
f[14]=f[14]<<7&0xff|f[14]>>1  
f[13]^=f[2]  
f[9]^=f[6]  
f[15]-=f[8]  
f[8]^=f[1]  
f[6]=f[6]^(f[6]>>1)  
f[21]^=f[5]  
f[17]^=f[13]  
f[12]-=f[8]  
f[19]^=f[12]  
f[2]^=f[1]  
f[25]=f[25]<<1&0xff|f[25]>>7  
f[19]=f[19]^(f[19]>>1)  
f[0]=f[0]^(f[0]>>1)  
f[17]+=f[27]  
f[20]=f[20]<<7&0xff|f[20]>>1  
f[28]-=f[13]  
f[22]=~f[22]&0xff  
f[26]^=f[17]  
f[10]=f[10]<<1&0xff|f[10]>>7  
f[24]=~f[24]&0xff  
f[4]-=f[22]  
f[4]-=f[20]  
f[24]+=f[12]  
f[13]=f[13]<<1&0xff|f[13]>>7  
f[2]=f[2]<<7&0xff|f[2]>>1  
f[1]-=f[24]  
f[11]^=f[27]  
f[14]=f[14]^(f[14]>>1)  
f[17]=f[17]^(f[17]>>1)  
f[21]=f[21]^(f[21]>>1)  
f[24]=(((f[24]*0x0802&0x22110)|(f[24]*0x8020&0x88440))*0x10101>>>16)&0xff  
f[12]=f[12]^(f[12]>>1)  
f[3]=f[3]<<1&0xff|f[3]>>7  
f[8]+=f[1]  
f[21]+=f[18]  
f[0]+=f[22]  
f[4]=f[4]<<7&0xff|f[4]>>1  
f[25]=f[25]<<1&0xff|f[25]>>7  
f[10]=f[10]<<7&0xff|f[10]>>1  
f[13]=f[13]^(f[13]>>1)  
f[1]-=f[27]  
f[13]=(((f[13]*0x0802&0x22110)|(f[13]*0x8020&0x88440))*0x10101>>>16)&0xff  
f[11]=(((f[11]*0x0802&0x22110)|(f[11]*0x8020&0x88440))*0x10101>>>16)&0xff  
f[2]+=f[17]  
f[6]=f[6]<<7&0xff|f[6]>>1  
f[10]=f[10]^(f[10]>>1)  
f[4]-=f[8]  
f[1]-=f[2]  
f[0]-=f[14]  
f[11]=f[11]^(f[11]>>1)  
f[7]-=f[17]  
f[18]=~f[18]&0xff  
f[0]^=f[16]  
f[12]+=f[13]  
f[23]=~f[23]&0xff  
f[10]-=f[7]  
f[29]=f[29]^(f[29]>>1)  
f[3]=f[3]<<7&0xff|f[3]>>1  
f[20]^=f[3]  
f[8]=f[8]<<1&0xff|f[8]>>7  
f[25]-=f[24]  
f[26]=f[26]<<1&0xff|f[26]>>7  
f[10]=f[10]^(f[10]>>1)  
f[26]=f[26]^(f[26]>>1)  
f[16]-=f[7]  
f[8]=~f[8]&0xff  
f[14]^=f[13]  
f[3]+=f[24]  
f[15]=(((f[15]*0x0802&0x22110)|(f[15]*0x8020&0x88440))*0x10101>>>16)&0xff  
f[15]-=f[28]  
f[10]=f[10]^(f[10]>>1)  
f[17]+=f[15]  
f[22]-=f[2]  
f[27]=~f[27]&0xff  
f[5]=f[5]^(f[5]>>1)  
f[20]=~f[20]&0xff  
f[13]^=f[24]  
f[23]^=f[21]  
f[2]-=f[23]  
f[5]+=f[20]  
f[24]^=f[12]  
f[9]-=f[8]  
f[11]=f[11]^(f[11]>>1)  
f[27]-=f[14]  
f[18]+=f[25]  
f[6]+=f[26]  
f[7]=f[7]^(f[7]>>1)  
f[28]=f[28]^(f[28]>>1)  
f[10]-=f[1]  
f[18]-=f[14]  
f[20]+=f[14]  
f[15]-=f[17]  
f[0]=~f[0]&0xff  
0x2a8c594b90bc4be941624cac7493f521772b475b27209734942302ded9f30a  
```

We can verify that the computations are correct by initializing a `f` and
checking the final  
result (we also need to replace `>>>` with `>>`).

## Reversing the Computations

Now that we have the computations, the next step is to find the initial value
of `f` that gives  
the desired flag
`d19ee193b461fd8d1452e7659acb1f47dc3ed445c8eb4ff191b1abfa7969`. Once approach  
would be to use `z3` but it's going to be a mess because the same variables
are being updated  
(e.g., `f[1] += f[2]`, so we need to have multiple instances for each symbolic
variable:  
`s.add(f1_1 = f1_0 + f2_0`). However, we can do better: **all operations are
invertible**, so  
we can execute them in the reverse order and get the flag. That is, we need to
write a script  
that generates a python script with the inverted operations. We do this and we
run the generated  
script to get the flag.

For more details, please take a look at the
[required_crack.py](./required_crack.py) file.

So the flag is: `hxp{Cann0t_f1nd_m0dule_'fl4g'}`

We verify that the flag is correct:  
```  
ispo@ispo-glaptop2:~/ctf/hxp_2022/required/files$ cat flag  
hxp{1234567890123456789012345}

ispo@ispo-glaptop2:~/ctf/hxp_2022/required/files$ ./run.sh  
:(

ispo@ispo-glaptop2:~/ctf/hxp_2022/required/files$ echo -n
"hxp{Cann0t_f1nd_m0dule_'fl4g'}" > flag

ispo@ispo-glaptop2:~/ctf/hxp_2022/required/files$ ./run.sh  
:)  
```  
___  

Original writeup (https://github.com/ispoleet/ctf-
writeups/tree/master/hxp_ctf_2022/required).