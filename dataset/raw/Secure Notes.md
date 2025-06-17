# Secure Notes - NahamCon CTF 2022 -
[https://www.nahamcon.com/](https://www.nahamcon.com/)  
Mobile, 485 Points

## Description

![‏‏info.JPG](images/info.JPG)  
  
## Secure Notes Solution

Let's install the [secure_notes.apk](./secure_notes.apk) on [Genymotion
Android emulator](https://www.genymotion.com/):

![emulator.JPG](images/emulator.JPG)

If we are trying to insert an invalid OTP we get the message "Invalid OTP":

![invalid.JPG](images/invalid.JPG)

By decompiling the application using [jadx](https://github.com/skylot/jadx))
we can see the following methods on ```LoginActivity``` class:  
```java  
@Override // b.c, androidx.fragment.app.e,
androidx.activity.ComponentActivity, s.d, android.app.Activity  
   public void onCreate(Bundle bundle) {  
       super.onCreate(bundle);  
       setContentView(R.layout.activity_login);  
       Button button = (Button) findViewById(R.id.button);  
       TextView textView = (TextView) findViewById(R.id.password);  
       Intent intent = new Intent(this, MainActivity.class);  
       File file = new File(getCacheDir() + "/db.encrypted");  
       if (!file.exists()) {  
           try {  
               InputStream open = getAssets().open("databases/db.encrypted");  
               byte[] bArr = new byte[open.available()];  
               open.read(bArr);  
               open.close();  
               FileOutputStream fileOutputStream = new FileOutputStream(file);  
               fileOutputStream.write(bArr);  
               fileOutputStream.close();  
           } catch (Exception e2) {  
               throw new RuntimeException(e2);  
           }  
       }  
       button.setOnClickListener(new a(textView, file, intent));  
   }

@Override // android.view.View.OnClickListener  
      public void onClick(View view) {  
          try {  
              d.k(this.f1583b.getText().toString() + this.f1583b.getText().toString() + this.f1583b.getText().toString() + this.f1583b.getText().toString(), new File(this.f1584c.getPath()), new File(LoginActivity.this.getCacheDir(), "notes.db"));  
              LoginActivity.this.startActivity(this.f1585d);  
          } catch (p0.a unused) {  
              Toast.makeText(LoginActivity.this.getApplicationContext(), "Wrong password", 0).show();  
          }  
      }  
```

We can see the application creates file ```db.encrypted``` (on ```onCreate```
methods).  
Next, ```onClick```method calls to ```d.k``` method with the following
arguments:  
1. Concat the PIN code four times  
2. Path to ```db.encrypted```  
3. Path to decrypted file

Let's observe on ```d.k``` method:  
```java  
public static void k(String str, File file, File file2) {  
       try {  
           SecretKeySpec secretKeySpec = new SecretKeySpec(str.getBytes(), "AES");  
           Cipher instance = Cipher.getInstance("AES");  
           instance.init(2, secretKeySpec);  
           FileInputStream fileInputStream = new FileInputStream(file);  
           byte[] bArr = new byte[(int) file.length()];  
           fileInputStream.read(bArr);  
           byte[] doFinal = instance.doFinal(bArr);  
           FileOutputStream fileOutputStream = new FileOutputStream(file2);  
           fileOutputStream.write(doFinal);  
           fileInputStream.close();  
           fileOutputStream.close();  
       } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e2) {  
           throw new a("Error encrypting/decrypting file", e2);  
       }  
   }  
```

As we can see, ```db.encrypted``` file encrypted using AES and we know the PIN
code is 4 digits.

By observing ```onCreate``` on ```MainActivity``` class we can see:  
```java  
public void onCreate(Bundle bundle) {  
       int i2;  
       LinearLayoutManager linearLayoutManager;  
       super.onCreate(bundle);  
       setContentView(R.layout.activity_main);  
       String path = new File(getCacheDir(), "notes.db").getPath();  
       ArrayList arrayList = new ArrayList();  
       try {  
           BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(path)));  
           StringBuffer stringBuffer = new StringBuffer();  
           while (true) {  
               String readLine = bufferedReader.readLine();  
               if (readLine == null) {  
                   break;  
               }  
               stringBuffer.append(readLine);  
           }  
           try {  
               JSONArray jSONArray = new JSONObject(stringBuffer.toString()).getJSONArray("notes");  
               for (int i3 = 0; i3 < jSONArray.length(); i3++) {  
                   JSONObject jSONObject = jSONArray.getJSONObject(i3);  
                   arrayList.add(new q0.b(jSONObject.getInt("id"), jSONObject.getString("name"), jSONObject.getString("content")));  
               }  
           } catch (JSONException e2) {  
               e2.printStackTrace();  
           }  
       } catch (IOException e3) {  
           e3.printStackTrace();  
       }  
       this.f1587o = (RecyclerView) findViewById(R.id.recyclerView);  
       this.p = new LinearLayoutManager(1, false);  
       a aVar = a.LINEAR_LAYOUT_MANAGER;  
       this.r = aVar;  
       if (bundle != null) {  
           this.r = (a) bundle.getSerializable("layoutManager");  
       }  
       a aVar2 = this.r;  
       if (this.f1587o.getLayoutManager() != null) {  
           LinearLayoutManager linearLayoutManager2 = (LinearLayoutManager) this.f1587o.getLayoutManager();  
           View Y0 = linearLayoutManager2.Y0(0, linearLayoutManager2.x(), true, false);  
           i2 = Y0 == null ? -1 : linearLayoutManager2.Q(Y0);  
       } else {  
           i2 = 0;  
       }  
       int ordinal = aVar2.ordinal();  
       if (ordinal != 0) {  
           if (ordinal != 1) {  
               linearLayoutManager = new LinearLayoutManager(1, false);  
           } else {  
               linearLayoutManager = new LinearLayoutManager(1, false);  
           }  
           this.p = linearLayoutManager;  
           this.r = aVar;  
       } else {  
           this.p = new GridLayoutManager(this, 2);  
           this.r = a.GRID_LAYOUT_MANAGER;  
       }  
       this.f1587o.setLayoutManager(this.p);  
       this.f1587o.e0(i2);  
       new b(this, arrayList).start();  
   }  
```

According to this code, we know we expect to decrypt a file called
```notes.db``` with JSON content.

Let's pull the ```encrypted.db``` file from the emulator:  
```console  
┌─[evyatar@parrot]─[/mobile/secure_notes]  
└──╼ $ adb pull /data/data/com.congon4tor.securenotes/cache/db.encrypted  
/data/data/com.congon4tor.securenotes/cache/db.encrypted: 1 file pulled. 0.1
MB/s (224 bytes in 0.002s)  
```

Now, We can decrypt the file using the following Brute Force [java
code](./brute_force.java):  
```java  
public class Main {

	public static void main(String[] args) throws IOException {  
  
		for(int i = 1000 ; i<10000 ; i++)  
		{  
  
			String iStr = String.valueOf(i);  
			String currentPin = iStr + iStr + iStr + iStr;  
  
			 try {  
				File file = new File("/mobile/secure_notes/db.encrypted");  
				File file2= new File("/mobile/secure_notes/notes.db");  
  
		            SecretKeySpec secretKeySpec = new SecretKeySpec(currentPin.getBytes(), "AES");  
		            Cipher instance = Cipher.getInstance("AES");  
		            instance.init(2, secretKeySpec);  
		            FileInputStream fileInputStream = new FileInputStream(file);  
		            byte[] bArr = new byte[(int) file.length()];  
		            fileInputStream.read(bArr);  
		            byte[] doFinal = instance.doFinal(bArr);  
		            FileOutputStream fileOutputStream = new FileOutputStream(file2);  
		            fileOutputStream.write(doFinal);  
		            fileInputStream.close();  
		            fileOutputStream.close();

		            String content = Files.readString(Paths.get("/mobile/secure_notes/notes.db"), StandardCharsets.US_ASCII);  
		            if(content.contains("notes"))  
		            {  
		            	System.out.println("The PIN code is: " + i);  
		            	break;  
		            }  
		            break;  
		        } catch (Exception e2) {  
  
		        }  
		}  
	}  
}  
```

And by running this we get the following output:  
```console  
The PIN code is: 5732  
```

By observing the decrypted file ```notes.db``` we get:  
```console  
┌─[evyatar@parrot]─[/mobile/secure_notes]  
└──╼ $ cat notes.db  
{  
 "notes": [  
   {  
     "id": 0,  
     "name": "Note 1",  
     "content": "My first secure note!"  
   },  
   {  
     "id": 1337,  
     "name": "flag",  
     "content": "flag{a5f6f2f861cb52b98ebedcc7c7094354}"  
   }  
 ]  
}  
```

And we get the flag ```flag{a5f6f2f861cb52b98ebedcc7c7094354}```.

Original writeup
(https://github.com/evyatar9/Writeups/tree/master/CTFs/2022-NahamCon_CTF/Mobile/Secure_Notes).