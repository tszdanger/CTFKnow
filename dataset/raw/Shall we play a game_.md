## General problem description

```  
Win the game 1,000,000 times to get the flag.  
```

For this challenge we got an .apk file, which we should apperently run and win
1,000,000 times. We let the online Java-decompiler at
`http://www.javadecompilers.com/apk`. Running the apk on an Android-Phone or
emulator shows us the game: Tic Tac Toe. We also get a counter `0/1000000` on
the bottom of the screen. Each win increases the counter by one.

## Naive approach by recompiling the app

We used the decompiled code from `http://www.javadecompilers.com/apk` and
analyzed the generated code. The code consists of 4 Java classes and one
native library. Let us first look at the Java-classes:

* C0644N.java: The class is just a wrapper that loads the native library and holds a few float-arrays  
```java  
class C0644N {  
   static final int[] f2334a = new int[]{0, 1, 0};  
   static final int[] f2335b = new int[]{1, 0, 2};  
   static final int[] f2336c = new int[]{2, 0, 1};  
   static final int[] f2337d = new int[]{3, 0, 0};  
   static final int[] f2338e = new int[]{4, 1, 0};  
   static final int[] f2339f = new int[]{5, 0, 1};  
   static final int[] f2340g = new int[]{6, 0, 0};  
   static final int[] f2341h = new int[]{7, 0, 2};  
   static final int[] f2342i = new int[]{8, 0, 1};

   static {  
       System.loadLibrary("rary");  
   }

   static native Object m3217_(Object... objArr);  
}  
```  
* C0649a.java: This class is responsible for displaying the cells in the Tic Tac Toe field  
```java  
public class C0649a extends RelativeLayout {  
   ...  
}  
```  
* C0652b.java: This class is responisble for the fade in and out of the symbols in the Tic Tac Toe cells  
```java  
public class C0652b {  
   ...  
}  
```  
* GameActivity.java: This is the main activity of the App and holds most of the App logic. Here are important passages of the class file together with comments as to what we assumed they do:  
```java  
public class GameActivity extends C0433c implements OnClickListener {  
   C0649a[][] f2327l = ((C0649a[][]) Array.newInstance(C0649a.class, new
int[]{3, 3}));// initialises the Cells  
   ...  
   Object f2329n = C0644N.m3217_(3, C0644N.f2341h,
Long.valueOf((((((((1416127776 + 1869507705) + 544696686) + 1852403303) +
544042870) + 1696622963) + 544108404) + 544501536) + 1886151033));  
   ...  
   byte[] f2332q = new byte[32];// empty byte array  
   byte[] f2333r = new byte[]{(byte) -61, (byte) 15, (byte) 25, (byte) -115,
(byte) -46, (byte) -11, (byte) 65, (byte) -3, (byte) 34, (byte) 93, (byte)
-39, (byte) 98, (byte) 123, (byte) 17, (byte) 42, (byte) -121, (byte) 60,
(byte) 40, (byte) -60, (byte) -112, (byte) 77, (byte) 111, (byte) 34, (byte)
14, (byte) -31, (byte) -4, (byte) -7, (byte) 66, (byte) 116, (byte) 108,
(byte) 114, (byte) -122};// pre-filled byte array  
   public GameActivity() {  
       C0644N.m3217_(3, C0644N.f2342i, this.f2329n, this.f2332q);// calls the native function  
       ...  
   }  
   C0649a m3210a(List<C0649a> list) {  
       return (C0649a) list.get(((Random) this.f2329n).nextInt(list.size()));// casts the object got from the native funktion to random and uses it to choose the next cell for the app  
   }  
   ...  
   //this function is called after 1,000,000 wins  
   void m3214m() {  
       Object _ = C0644N.m3217_(0, C0644N.f2334a, 0);//native call  
       Object _2 = C0644N.m3217_(1, C0644N.f2335b, this.f2332q, 1);//native call  
       C0644N.m3217_(0, C0644N.f2336c, _, 2, _2);//native call  
       ((TextView) findViewById(R.id.score)).setText(new String((byte[]) C0644N.m3217_(0, C0644N.f2337d, _, this.f2333r)));//print result of native call  
       ...  
   }  
   //this function is called if the player wins  
   void m3215n() {  
       ...  
       this.f2330o++;//increase counter  
       Object _ = C0644N.m3217_(2, C0644N.f2338e, 2);//native call  
       C0644N.m3217_(2, C0644N.f2339f, _, this.f2332q);//native call  
       this.f2332q = (byte[]) C0644N.m3217_(2, C0644N.f2340g, _);//native call  
       if (this.f2330o == 1000000) {// wuhuuu 1,000,000 wins  
           m3214m();  
           return;  
       }  
       ((TextView) findViewById(R.id.score)).setText(String.format("%d / %d", new Object[]{Integer.valueOf(this.f2330o), Integer.valueOf(1000000)}));  
   }  
   ...  
}  
```  
We took this class and simply called the win-method 1,000,000 times and then
the win method. To get the result we changed `((TextView)
findViewById(R.id.score)).setText(...)` with `System.out.println(...)` calls,
so we get the flag in the console. Finally we wrapped all that into a simple
Aktivity and tried it out.  
```java  
GameActivity gameActivity = new GameActivity();  
for(int i = 0; i < 1000000; i++)  
   gameActivity.m3215n();  
```  
We tried it on 2 different Android devices(ARM based) and the x86_64 emulator
of Android Studios. Each run took some time(~20 minutes). All of those
resulted in garbage being printed.

## Hey don't forget `Random`

After our first tries failed we looked over the GameActivity-class and noticed
we forgot the `nextInt`-calls. The `Random`-object is fetched from the native-
library so it is theoretically possible, that either the state of the
`Random`-object is important for the native library or the `nextInt` is
overloaded inside of the native-library and does something special.

Looking through the code we found that the `nextInt`-method has to be called
twice before we can theoretically win, so we add the 2 calls at the start of
every "win"-method.

The result was exactly the same as before. There was no change in the output.

## Diving deep into the native library

We started by loading the native library into IDA and decompiling it.  
It is important to note, that we created the first argument to a `JNI**`-type,
which we modeled after the `jni.h`. We did not model the whole struct, as
there are multiple hundred of function-pointers defined in there and we only
defined the ones actually needed.  
```c  
void* __fastcall Java_com_google_ctf_shallweplayagame_N__1(JNI **env, void*
arg1, void* arg2){  
...  
 if ( !initialized ) {  
   init_data();  
   initialized = 1;  
 }  
 v4 = 0LL;  
 LODWORD(third_arg_array_ele0) = ((int (__fastcall *)(JNI **, void*,
_QWORD))(*env)->GetObjectArrayElement)(env, arg2_1, 0LL);  
 third_arg_array_ele0_1 = third_arg_array_ele0;  
 LODWORD(Integer_class) = ((int (__fastcall *)(JNI **, const char
*))(*env)->FindClass)(env, "java/lang/Integer");  
 if ( Integer_class ) {  
   LODWORD(Integer_intValue) = ((int (__fastcall *)(JNI **, void*, const char
*, const char *))(*env)->GetMethodID)(env, Integer_class, "intValue", "()I");  
   if ( Integer_intValue )  
     v4 = call_method(env, third_arg_array_ele0_1, Integer_intValue, Integer_intValue, v9, v10, v36);  
   else  
     v4 = 0LL;  
 }  
 LODWORD(class_def) = ((int (__fastcall *)(JNI **,
void*))(*env)->FindClass)(env, class_table[v4]);  
 LODWORD(parameter2) = ((int (__fastcall *)(JNI **, void*, signed
__int64))(*env)->GetObjectArrayElement)(env, arg2_1, 1LL);  
 v14 = 0;  
 LODWORD(parameter2_int_arr) = ((int (__fastcall *)(JNI **, void*,
_QWORD))(*env)->GetIntArrayElements)( env, parameter2, 0LL);  
 array2_0 = *parameter2_int_arr;  
 LODWORD(parameter2_int_arr_2) = ((int (__fastcall *)(JNI **, void*,
_QWORD))(*env)->GetIntArrayElements)(env, parameter2, 0LL);  
 array2_1 = *(_DWORD *)(parameter2_int_arr_2 + 4);  
 LODWORD(parameter2_int_arr_3) = ((int (__fastcall *)(_QWORD, _QWORD,
_QWORD))(*env)->GetIntArrayElements)( env, parameter2, 0LL);  
 array2_2 = *(_DWORD *)(parameter2_int_arr_3 + 8);  
 LODWORD(object_class_) = ((int (__fastcall *)(JNI **, const char
*))(*env)->FindClass)(env, "java/lang/Object");  
 arg2_1_length = ((int (__fastcall *)(JNI **,
void*))(*env)->GetArrayLength)(env, arg2_1);  
 v24 = 3 - (array2_1 != 0 || array2_2 == 2);  
 LODWORD(object_array) = ((int (__fastcall *)(JNI **, _QWORD, void*,
_QWORD))(*env)->NewObjectArray)( env, (unsigned int)(arg2_1_length - v24),
object_class_, 0LL);  
 v26 = object_array;  
 v27 = __OFSUB__(arg2_1_length, v24);  
 v28 = arg2_1_length - v24;  
 v40 = object_array;  
 if ( !((unsigned __int8)((v28 < 0) ^ v27) | (v28 == 0)) ) {  
   do {  
     LODWORD(v29) = ((int (__fastcall *)(JNI **, void*, _QWORD))(*env)->GetObjectArrayElement)(env, arg2_1, v24 + v14);  
     ((void (__fastcall *)(JNI **, void*, _QWORD, void*))(*env)->SetObjectArrayElement)(env, v26, v14++, v29);  
   } while ( v28 != v14 );  
 }  
 if ( array2_1 ) {  
   if ( array2_1 == 1 ) {  
     LODWORD(v30) = ((int (__fastcall *)(JNI **, void*, void*, void*))(*env)->CallStaticObjectMethod)( env, class_def, method_table[array2_0], string_table[array2_0 + 2]);  
     result = sub_1CA0(class_def, &v40, v30, array2_0, array2_2);  
   } else {  
     result = 0LL;  
   }  
 } else {  
   LODWORD(method) = ((int (__fastcall *)(JNI **, void*, void*,
void*))(*env)->GetMethodID)(env, class_def, method_table[array2_0],
string_table[array2_0 + 2]);  
   LODWORD(arg2_1_2) = ((int (__fastcall *)(JNI **, void*, signed
void*))(*env)->GetObjectArrayElement)( env, arg2_1, 2LL);  
   result = sub_1480(&v40, class_def, arg2_1_2, method, array2_0, array2_2);  
 }  
 v35 = *MK_FP(__FS__, 40LL);  
 return result;  
}  
```

The `init_data`-method looks like this:  
```  
void* init_data(){  
 ...  
 v2 = 1;  
 do  
 {  
   byte_4010[v2] += byte_4010[v2 - 1];  
   ++v2;  
 }  
 while ( v2 < 20 );  
 class_table[0] = (__int64)byte_4010;  
 v3 = 1;  
 do  
 {  
   byte_4030[v3] += byte_4030[v3 - 1];  
   ++v3;  
 }  
 while ( v3 < 32 );  
 class_table[1] = (__int64)byte_4030;  
 ...  
```

For the init-data, we can see, that for a certain block every byte is summed
up with the previous byte. We duplicated this with a simple script and got the
following strings:  
```  
Random  
MessageDigest  
Cipher  
SecretKeySpec  
<init>  
getInstance  
update  
digest  
getInstance  
<init>  
init  
doFinal  
SHA-256  
AES/ECB/NoPadding  
AES  
```  
From the `Java_com_google_ctf_shallweplayagame_N__1`we could figure out that
the first parameter is used as a decider what class to take. The second
parameter is an array where the first element is what method to call. The rest
of the parameters are the parameters for the method. We actually do not really
care about the second or third array-elements of the second parameter, because
we deduced their meaning later on through common sense.

The indices of the classes start at the decoded strings at index 0. The
methods at index 4 and some other strings at index 12. Looking back at the
Java code we can simplify the code to:  
```java  
byte[] arr = new byte[32];  
byte[] f2333r = new byte[]{(byte) -61, (byte) 15, (byte) 25, (byte) -115,
(byte) -46, (byte) -11, (byte) 65, (byte) -3, (byte) 34, (byte) 93, (byte)
-39, (byte) 98, (byte) 123, (byte) 17, (byte) 42, (byte) -121, (byte) 60,
(byte) 40, (byte) -60, (byte) -112, (byte) 77, (byte) 111, (byte) 34, (byte)
14, (byte) -31, (byte) -4, (byte) -7, (byte) 66, (byte) 116, (byte) 108,
(byte) 114, (byte) -122};  
new Random((((((((1416127776L + 1869507705L) + 544696686L) + 1852403303L) +
544042870L) + 1696622963L) + 544108404L) + 544501536L) +
1886151033L).nextBytes(arr);

for(int i = 0; i < 1000000; i++){  
   System.out.println(i);  
   try {  
       MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");  
       messageDigest.update(arr);  
       arr = messageDigest.digest();  
   } catch (NoSuchAlgorithmException e) {  
       e.printStackTrace();  
   }  
}  
try {  
   Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");  
   SecretKeySpec spec = new SecretKeySpec(arr, "AES");  
   cipher.init(2, spec);  
   System.out.println(new String(cipher.doFinal(f2333r)));  
} catch (NoSuchAlgorithmException | BadPaddingException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException e) {  
   e.printStackTrace();  
}  
```  
The `SHA-256`, `AES/ECB/NoPadding` and `AES` parameters we guessed as they are
common parameters for these functions.

We started this on a normal computer and got the output
`CTF{ThLssOfInncncIsThPrcOfAppls}` within a few seconds.

## Rant: Non-Portability of `Random`

This challenge should normally have ended after we let the program run on our
Android devices or the emulator, but due to different behaviours of
`java.util.Random` the algorithm behaved differently on every single device we
tried. The bytes that were saved in the initial byte-array always were
different values even though the java-api states differently:  
```  
If two instances of Random are created with the same seed, and the same
sequence of method calls is made for each, they will generate and return
identical sequences of numbers. In order to guarantee this property,
particular algorithms are specified for the class Random. Java implementations
must use all the algorithms shown here for the class Random, for the sake of
absolute portability of Java code. However, subclasses of class Random are
permitted to use other algorithms, so long as they adhere to the general
contracts for all the methods.  
```  
The class that was created was the `Random`-class and not something different.
We checked with the debugger. The results were still different, which was
infuriating. Note, that Random always behaved the same for each run on the
same hardware/emulator, but on different devices it produced different values.
This should not happen, but apparently it does.

Original writeup (https://w0y.at/writeup/2018/07/02/google-ctf-
quals-2018-shall-we-play-a-game.html).