# Chasing a lock writeup  
# Our problem in short:

Bypass need of 20k clicks  
**We will use Frida and Jadx in this challange**

# Frida framework installation  
Let's setup Frida on our Android device like in this link:  
https://frida.re/docs/android/

And then install Frida tools on our pc:  
`pip3 install frida-tools`  
Let's now verify our installation:  
`frida-ps -U`  
If output is:  
` PID NAME  
12345 com.example.app  
`  
...you installed Frida correctly!

# Jadx decompiler installation  
Let's visit Jadx releases page on Github  
https://github.com/skylot/jadx/releases/

Download latest binary and open it!

# Now let's begin!  
First, let's locate apk's Main activity class  
Do it by writing  
`frida-ps -U`  
You'll see  
`  
 PID NAME  
12345 com.example.xyz.Main  
XXXXX com.example.razictf.MainActivity  
67890 com.modern.app.App  
`  
Now open apk in Jadx and go to  
`com.example.razictf.MainActivity`

We notice onClick method and inside of it  
code changing our clicks left number **and this line**  
`String run = new switcher().run(i);` *which btw isn't best solution to call
.run method*  
Now lets see for what `run` string is being used  
it shows us something when its not null, hmmm  
Maybe visiting switcher.run will tell us more?  
Aha! This looks like code containing our flag parts

Now lets make frida script  
So we know what is giving us flag, lets try calling it  
I wrote this code to print flag for us:  
`  
const switcher = Java.use("com.example.razictf.switcher").$new();  
console.log(switcher.run(18)+switcher.run(15)+switcher.run(12)+switcher.run(10)+switcher.run(5));  
`

It doesn't tell you anything? Let me explain this simple code  
`Java.use("com.example.razictf.switcher")` gives us access to this class from
frida api  
`.$new()` makes an instance of this class, now we have access to object from
frida api  
`const switcher = Java.use("com.example.razictf.switcher").$new();` saves our
object for later use

`switcher.run(xx)` calls .run method of this object with xx as argument  
`console.log(switcher.run(18)+switcher.run(15)+switcher.run(12)+switcher.run(10)+switcher.run(5));`
prints whole flag for us

Lets launch Frida now!  
Go to terminal/cmd and write this command:  
`frida -U -f com.example.razictf --no-pause`  
Paste our code, and get the flag!