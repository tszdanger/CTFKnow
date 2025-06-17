# Toast clicker 3 (96p, 21 solved)

The last part of the challenge comes from:

```java  
   public void loadClass() {  
       String methodToInvoke = "printThirdFlag";  
       try {  
           Class loadedClass = new DexClassLoader(Uri.fromFile(new File(getExternalFilesDir(null), "bacon-final.dex")).toString(), null, null, ClassLoader.getSystemClassLoader().getParent()).loadClass("bacon.ToastDynamicFlag");  
           Object obj = loadedClass.newInstance();  
           String str = (String) loadedClass.getMethod(methodToInvoke, new Class[]{String.class, String.class}).invoke(obj, new Object[]{"ijiijiiijjjjjijijijiiijjijjjji", "jjjiiiiijjjijijijjijiijji"});  
       } catch (ClassNotFoundException e) {  
           e.printStackTrace();  
       } catch (InstantiationException e2) {  
           e2.printStackTrace();  
       } catch (IllegalAccessException e3) {  
           e3.printStackTrace();  
       } catch (NoSuchMethodException e4) {  
           e4.printStackTrace();  
       } catch (IllegalArgumentException e5) {  
           e5.printStackTrace();  
       } catch (InvocationTargetException e6) {  
           e6.printStackTrace();  
       }  
   }  
```

It looks weird, but in reality this is simply loading a new class
`bacon.ToastDynamicFlag` at runtime from `bacon-final.dex` and calls method
`printThirdFlag` on object of this class with arguments
`"ijiijiiijjjjjijijijiiijjijjjji", "jjjiiiiijjjijijijjijiijji"`.

This dex file comes from:

```java  
   public void downloadFile() {  
       File file = new File(getExternalFilesDir(null), "bacon-final.dex");  
       DownloadManager downloadmanager = (DownloadManager) getSystemService("download");  
       Request request = new Request(Uri.parse("https://storage.googleapis.com/bsides-sf-ctf-2020-attachments/bacon-final.dex"));  
       request.setTitle("Dex File");  
       request.setDescription("Downloading update");  
       request.setNotificationVisibility(1);  
       request.setVisibleInDownloadsUi(false);  
       request.setDestinationUri(Uri.fromFile(file));  
       request.setAllowedOverRoaming(false);  
       request.setAllowedOverMetered(false);  
       Log.d("File path", Uri.fromFile(file).toString());  
       this.downloadID = downloadmanager.enqueue(request);  
   }  
```

We can just grab the
[dex](https://raw.githubusercontent.com/TFNS/writeups/master/2020-02-23-BSidesSF/toast/bacon-
final.dex) from the URL and decompile it just as we did with the apk.  
There is only [one
class](https://raw.githubusercontent.com/TFNS/writeups/master/2020-02-23-BSidesSF/toast/ToastDynamicFlag.java)
there.

As mentioned, we only need to call the function there to get the flag, so we
do just that, add a main method with:

```java  
   public static void main(String[] args) {  
       ToastDynamicFlag toastDynamicFlag = new ToastDynamicFlag();  
       System.out.println(toastDynamicFlag.printThirdFlag("ijiijiiijjjjjijijijiiijjijjjji", "jjjiiiiijjjijijijjijiijji"));  
   }  
```

And run this to get `CTF{makingbaconpancakes}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-02-23-BSidesSF/toast/README.md).