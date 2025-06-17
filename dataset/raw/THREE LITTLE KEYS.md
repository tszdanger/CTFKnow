# THREE LITTLE KEYS

This challenge gives us an apk file. After opening it, it showed us 3 keys.
The first one instantly turns green after clicking it, the second one wants us
to enter something and the third one throws an error.

## First Key

I decompiled the .dex file and got many folders to search through. I opened
the most important main class for the app in
`de/cybersecurityrumble/threelittlekeys` and took a closer look at how the app
actually works.  
After clicking a button, the corresponding method in another class gets run. I
found that class in `c/a/a/c` and quickly saw the method for the first key.

```Java  
public boolean checkFirstKey() {  
       String num = Integer.toString(new Random(3762).nextInt(8000));  
       this.f1665a = num;  
       Log.i("Key Created", num);  
       return !this.f1665a.isEmpty();  
   }  
```

As we can see, the method simply generates a random number and then prints it
to the console... It seems to use the same seed every time so I tried to run
that piece of code myself and got the first key which is `7765`. I confirmed
that by taking a look at the log while running the app in the android studio
emulator.

## Second Key

The next step was to find the second key. Somehow I was not able to decompile
this method using the usual decompiler tool websites. I then tried jadx-gui
which somehow managed to decompile the method as good as possible, I guess it
was corrupted on purpose.

The method gave us a few clues to build our second key:

The second character is a "c", the 1., 3., 6. and 7. character are the same
and there is another method that converts the string into a byte array, after
testing I figured out that it converts a string with hex values to the
corresponding byte values.  
  
That byte array also had the requirement, that the last character is an e and
that it is 4 characters long. If we reverse that, we can find out that the key
is 8 characters long and that it ends with 65, as the hex value for e is 65.  
The last thing needed to make that key valid is that its byte array characters
have equal 100 when bitwise and'ed together. Doing this I got around 20
possible combinations and after decoding it to ascii I got `love` in one of
the results which had to be the key, or at least the hex version which is
`6c6f7665`

## Third Key

This time I had no problems decompiling the method. It uses a regex and a few
comparisons to validate the key. The regex `\d{2}[*!=()%?$#]\p{Upper}\d+!`
matches a string that starts with two digits, followed by any of the
characters *!=()%?$#, followed by an uppercase letter, followed by one or more
digits, and finally an exclamation mark. Also, the 1. and 7. character have to
be equal and the 2. and 5. have to do the same.

But how am I going to give the key to the app?

I had to take a closer look at how the app gets the flag in the first place.

In the check method it says:  
```java  
String string = d.a().f1669a.getString("ThirdKey", "");  
```

I went to class d and looked at the right method and I now know how the app
gets the key. It is stored in the SharedPreferences!

But how do I get access on it?

I extracted the app using apktool, then I added `android:debuggable="true"` to
the AndroidManifest.xml and after that I built the app again and also had to
sign it to make it installable. Now I am able to not only read the file in the
file explorer of android studio, but also to edit it using the adb shell.

I correctly put a guess `12*A221!` into the file and was able to successfully
make the last key green. Still, something has to be wrong as clicking the
unlock button throws an error... what if I actually had to find the correct
third key?

After putting the openLock() method into a java project I wrote a small
bruteforcer that tries all of the combinations.

```java  
public static void openLock() {  
   String str = "7765";  
   String str2 = "6c6f7665";  
   String str3 = "12*A221!"; // Bruteforce  
   String string = "2a";  
   for (int i = 0; i < 10; i++) {  
       for (int ii = 0; ii < 10; ii++) {  
           for (String e : "*!=()%?$#".split("")) {  
               for (String f : "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("")) {  
                   for (int iii = 0; iii < 10; iii++) {  
                       str3 = "" + i + "" + ii + e + f + "" + ii + "" + iii + "" + i+"!";  
                       byte[] a2 = a(str + string + str2 + string);  
                       byte[] bytes = str3.getBytes();  
                       byte[] bArr = new byte[(a2.length + bytes.length)];  
                       System.arraycopy(a2, 0, bArr, 0, a2.length);  
                       System.arraycopy(bytes, 0, bArr, a2.length, bytes.length);  
                       SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES");  
                       try {  
                           byte[] bArr2 = FLAG;  
                           Cipher instance = Cipher.getInstance("AES/ECB/PKCS5Padding");  
                           instance.init(2, secretKeySpec);  
                           if(new String(instance.doFinal(bArr2), StandardCharsets.UTF_8).startsWith("CSR")){  
                               System.out.println(new String(instance.doFinal(bArr2), StandardCharsets.UTF_8) + " with keys: \n1. "+str+"\n2. "+str2+"\n3. "+str3);  
                           }  
                       } catch (Exception ex) {  
                       }  
                   }  
               }  
           }  
       }  
   }  
}  
```

The encrypted `FLAG` was at the top of that class and I got the variable
"string" from the config.

And one of the combinations gave me the correct flag!

Original writeup
(https://github.com/xXLeoXxOne/writeups/blob/main/CyberSecurityRumble%202022/THREE%20LITTLE%20KEYS.md).