# There is a bug

## Point Value  
150

## Challenge Description  
Bob is reckless when developing apps. He just created an app that can show the
flag with the correct password. However, he just couldn't get the flag even
with the right password, could you help him to fix the bug?

## Description  
There is a missing function call in the code. In particular, `result =
getFlag(..);` should be called before showing the result in `TextView`. The
player needs to decompile the app into `smali` code and manually add the
function call. The function has several parameters which are all prepared
inside the function. Players should order them in the correct way. Here is the
`smali` code that need to be added:  
```smali  
invoke-virtual {p0, v0, v1, p0, v3},
Lcom/example/authenticator/MainActivity;->getFlag(Landroid/widget/TextView;Landroid/widget/EditText;Landroid/content/Context;Landroid/content/SharedPreferences;)Ljava/lang/String;  
move-result-object v5 # move the result to register v5 since v5 will be
presented in `TextView` in the following code  
```  
Once added, the player needs to repackage and re-sign the app. Run it on the
phone or emulator with the correct password, the flag will be presented.

There are other ways like using `frida` to directly call the `getFlag`. But
the parameters need to be constructed properly.  
## Deployment  
players just need access to Authenticator.apk