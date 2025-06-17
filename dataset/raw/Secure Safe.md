# Mobile

## Candroid  
```  
I think I can, I think I can!

Download the file below.  
Files: candroid.apk  
```  
We extract apk in a directory and we check if the flag is writed in plain
text:  
```  
$ grep -R flag  
META-INF/CERT.SF:Name: res/layout/activity_flag.xml  
META-INF/MANIFEST.MF:Name: res/layout/activity_flag.xml  
Binary file resources.arsc matches  
Binary file classes.dex matches

$ strings resources.arsc | grep flag  
flag{4ndr0id_1s_3asy}  
res/layout/activity_flag.xml  
flagTV  
activity_flag  
flag  
```

The flag is: `flag{4ndr0id_1s_3asy}`

## Simple App  
```  
Here's a simple Android app. Can you get the flag?

Download the file below.  
Files:simple-app.apk  
```

Same method than **Candroid**

We extract apk in a directory and we check if the flag is writed in plain
text:  
```  
$ grep -R flag  
Binary file resources.arsc matches  
Binary file classes.dex matches

$ strings classes.dex | grep flag  
[...]  
flag{3asY_4ndr0id_r3vers1ng}  
[...]  
```

The flag is: `flag{3asY_4ndr0id_r3vers1ng}`

## Secure Safe  
```  
This app says it secures my stuff! It's so cool!

Download the file below.  
Files: secure_safe.apk  
```

The application asks a 4-digit pin and seems use it to decrypt a cipher after
that a `submit` was pressed, the result seems to be the flag

We use http://www.decompiler.com to decompile the APK

In `sources/com/congon4tor/nahamcon2/MainActivity.java`, there is the
`onCreate` main function:  
``` java  
public void onCreate(Bundle bundle) {  
   super.onCreate(bundle);  
   setContentView((int) R.layout.activity_main);  
   String string = getString(R.string.encrypted_flag);  
   this.p = (TextView) findViewById(R.id.flagTV);  
   ((Button) findViewById(R.id.submit)).setOnClickListener(new a(string,
(EditText) findViewById(R.id.pin)));  
}  
```

The class `MainActivity.a` is set as click listener of the submit button with
`string` var and the `pin` input element

`string` is equal to `getString(R.string.encrypted_flag)`, so we search its
value:  
```  
$ grep -R encrypted_flag  
resources/res/values/public.xml:    <public type="string"
name="encrypted_flag" id="2131492892" />  
resources/res/values/strings.xml:    <string
name="encrypted_flag">UFhYVUt2VmdqEFALbiNXRkZvVQtTQxwSTVABe0U=</string>  
sources/com/congon4tor/nahamcon2/MainActivity.java:        String string =
getString(R.string.encrypted_flag);  
sources/com/congon4tor/nahamcon2/R.java:        public static final int
encrypted_flag = 2131492892;  
```

`string` is equal to `UFhYVUt2VmdqEFALbiNXRkZvVQtTQxwSTVABe0U=` because it's
the variable `encrypted_flag` in `R.strings`

The class `MainActivity.a` is:  
``` java  
public class a implements View.OnClickListener {

   public final /* synthetic */ String f532b;  
   public final /* synthetic */ EditText c;

   public a(String str, EditText editText) {  
       this.f532b = str;  
       this.c = editText;  
   }

   public void onClick(View view) {  
       String[] strArr = {this.f532b, this.c.getText().toString()};  
       new b.b.a.a.a(MainActivity.this).execute(new String[][]{strArr});  
   }  
}  
```

At create, there is `UFhYVUt2VmdqEFALbiNXRkZvVQtTQxwSTVABe0U=` in `this.f532b`

When the user press the ` submit` button, the function `onClick` is called and
there are `UFhYVUt2VmdqEFALbiNXRkZvVQtTQxwSTVABe0U=` and the pin in `strArr`

Then, the class `b.b.a.a.a` is created and executed, the argument look like
`{{"UFhYVUt2VmdqEFALbiNXRkZvVQtTQxwSTVABe0U=", **pin**}}`

we search where the class is located: in the directory `source/b/b/a/a` there
is a file named `a` and in it, a class `a` from package `b.b.a.a`, it's it !

In `source/b/b/a/a/a` there is two methods of `AsyncTask class` called by
`execute`:  
``` java  
public Object doInBackground(Object[] objArr) {  
   String[][] strArr = (String[][]) objArr;  
   String str = strArr[0][0];  
   String str2 = strArr[0][1];  
   try {  
       MessageDigest instance = MessageDigest.getInstance("SHA-1");  
       instance.update("5up3r_53cur3_53cr37".getBytes("UTF-8"));  
       instance.update(str2.getBytes("UTF-8"));  
       return new String(a(Base64.decode(str, 0), new BigInteger(1, instance.digest()).toString(16).getBytes()));  
   } catch (UnsupportedEncodingException | NoSuchAlgorithmException e) {  
       e.printStackTrace();  
       return "Error decrypting";  
   }  
}

public void onPostExecute(Object obj) {  
   String str = (String) obj;  
   super.onPostExecute(str);  
   this.f531a.p.setText(str);  
}  
```

The `execute` function call `doInBackground` function with argument passed to
`execute` and `onPostExecute` is called automaticly after `doInBackground`
finishes with the value returned by `doInBackground` as argument

`doInBackground` seems decrypt the flag and `onPostExecute` display it

Now, we can write a script to test all pin and crack it:  
``` java  
import java.io.UnsupportedEncodingException;  
import java.math.BigInteger;  
import java.security.MessageDigest;  
import java.security.NoSuchAlgorithmException;  
import java.util.Base64;

public class Crack {

   // xor function  
   public static final byte[] a(byte[] bArr, byte[] bArr2) {  
       byte[] bArr3 = new byte[bArr.length];  
       for (int i = 0; i < bArr.length; i++) {  
           bArr3[i] = (byte) (bArr[i] ^ bArr2[i % bArr2.length]);  
       }  
       return bArr3;  
   }

   public static Object doInBackground(Object[] objArr) {  
       String[][] strArr = (String[][]) objArr;  
       String str = strArr[0][0];  
       String str2 = strArr[0][1];  
       try {  
           MessageDigest instance = MessageDigest.getInstance("SHA-1");  
           instance.update("5up3r_53cur3_53cr37".getBytes("UTF-8"));  
           instance.update(str2.getBytes("UTF-8"));  
           // change way to decode in Base64  
           return new String(a(Base64.getDecoder().decode(str), new BigInteger(1, instance.digest()).toString(16).getBytes()));  
       } catch (UnsupportedEncodingException | NoSuchAlgorithmException e) {  
           e.printStackTrace();  
           return "Error decrypting";  
       }  
   }

   public static void main(String[] args) {  
       String encrypted_flag = "UFhYVUt2VmdqEFALbiNXRkZvVQtTQxwSTVABe0U=";  
       for (int id = 0; id <= 9999; id++) {  
           String pin = String.format("%04d", id);  
           String flag = (String)doInBackground(new String [][]{{encrypted_flag, pin}});  
           if (flag.startsWith("flag{"))  
               System.out.println("pin:" + pin + " -> " + flag);  
       }  
   }

}  
```

And finaly execute it:  
```  
$ java Crack.java  
pint:3952 -> flag{N0T_th3_B3st_3ncrypt10N}  
```

The flag is: `flag{N0T_th3_B3st_3ncrypt10N}`  

Original writeup
(https://github.com/skyf0l/CTF/blob/master/NahamCon_2020/Mobile.md#secure-
safe).