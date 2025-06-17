# CSAW CTF 2018: whyOS

## Description

Forensics, 300 points.

> Have fun digging through that one. No device needed.  
>  
> Note: the flag is not in flag{} format

We are given a huge `console.log` log file (185087 lines), as well as the
package for an iPhone app.

## Solution

Quickly searching for `flag` or so in the log file doesn't wield immediate
results, so we'll return to it later.

Digging into the package, we see various interesting files:

- Two small binaries, `control` and `debian-binary`, which I assume are part of this packaging format, and can be ignored.  
- Various `.plist` files that do not give the flag, but contain references to a "flag" UI element (probably a text input).  
- `whyOSsettings.bundle`, which finally contains the `whyOSsettings` binary.

Opening the binary in Hopper (or another disassembler), we see that it uses
standard Objective-C methods. This confirms we are looking at an iOS app, or
something similar.  
There's a promising method called `setFlag`, which decompiles to something
like this, using Hopper:

```  
void -[CSAWRootListController setflag](void * self, void * _cmd) {  
   sp = sp - 0x30;  
   r0 = *self;  
   r0 = [r0 alloc];  
   r0 = [r0
initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.yourcompany.whyos.plist"];  
   var_10 = r0;  
   if ([var_10 objectForKey:@"flag", @"flag"] != 0x0) {  
           var_2C = [var_10 objectForKey:@"flag", r1];  
   }  
   else {  
           var_2C = @"";  
   }  
   NSLog(@"%@", var_2C);  
   return;  
}  
```

It seems that `var_2C`, which is what the flag was "set" to, will be printed
just before this function exits. Importantly, the string is printed alone,
without any knwon prefix or suffix that we could search for in the log file.

Returning to the log file, and searching for "whyos", we get a hint:

```  
default 19:10:40.537634 -0400   Preferences Injecting
/Library/TweakInject/Activator.dylib into com.apple.Preferences  
default 19:10:53.647765 -0400   amfid   We got called!
/Library/PreferenceBundles/whyOSsettings.bundle/whyOSsettings with {  
   RespectUppTrustAndAuthorization = 1;  
   UniversalFileOffset = 81920;  
   ValidateSignatureOnly = 1;  
} (info: (null))  
default 19:10:53.651675 -0400   amfid   MacOS error: -67062  
default 19:10:53.656042 -0400   amfid   MacOS error: -67062  
default 19:10:53.659202 -0400   amfid   We got called! AFTER ACTUAL
/Library/PreferenceBundles/whyOSsettings.bundle/whyOSsettings with {  
   RespectUppTrustAndAuthorization = 1;  
   UniversalFileOffset = 81920;  
   ValidateSignatureOnly = 1;  
} (info: (null))  
default 19:10:53.659578 -0400   amfid   ours: {  
   CdHash = <610dc945 cd145933 7f552fe5 528afdc7 4bdd0559>;  
```

Hm... injecting libraries into Preferences? This tells us two things:

1. This is supposed to run on a jailbroken iPhone (which the many logs from Cydia confirm)  
2. The app is not an app, but a sort of extension that gets added to the built-in Preferences app. One big consequence is that when calling `NSLog`, the corresponding log line will not get a prefix identifying the binary (`whyOSsettings`), but the Preferences app.

And so we go back to the search, this time looking for log lines for the
Preferences app that are fairly short. Even though we don't know the format of
the flag, we know that it is logged on its own, not too long, and unlikely to
contain spaces.

```  
+Preferences +[^ ]{5,50}$  
```

This regular expression wields only 8 matches... we got the flag!

```  
default 19:12:18.884704 -0400   Preferences ca3412b55940568c5b10a616fa7b855e  
```

## Later updates

After solving this task, the following hints were added to the task
description:

> HINT: the flag is literally a hex string. Put the hex string in the flag
> submission box  
>  
> Update (09/15 11:45 AM EST) - Point of the challenge has been raised to 300  
> Update Sun 9:09 AM: its a hex string guys

This makes the task quite a bit easier, since it should only be a matter of
writing a regular expression to parse hex strings of a few lengths.  

Original writeup (https://github.com/ctf-
epfl/writeups/tree/master/csaw18/whyOS).