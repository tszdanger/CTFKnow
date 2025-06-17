# config-me - BSidesSF 2020 CTF (reverse, 472p, 4 solved)  
## Introduction

config-me is a reversing task. It is also in the `101` category, hinting that
it  
should be quite easy.

This task contains two files: `config-me` an ELF binary written in Rust, and  
`config-me.conf` that contains a name, a password, a comment, a conference
title  
and the flag.

The password and flag fields are encrypted:

```  
password: E$0d6b731d24127ad34e76a78133c91e59f13ab12eaa8dc0ad99e10c71  
flag: E$af7ac775b3716f6d6ae96fdb6080ef41f4918e0b9f2837b82105b5da39  
```

## Reverse engineering

The best way to reverse a Rust binary is: you don't.

## Dynamic analysis

The `config-me` binary reads the configuration from `config-me.conf`. It then  
displays `Welcome back, Ron [...]`, with Ron being the content of the `name`  
field from the configuration.

The binary can be used to add/delete a key and save/load a configuration file.
A  
key can be encrypted, and look like the encrypted field seen above.

By changing the configuration file and setting the `name` field to an
encrypted  
value, it will be decrypted and printed. Setting the `name` field to the  
encrypted flag will reveal the flag:

```  
Welcome back, CTF{my_rust_is_rusty}! Your config file currently has 5 entries.
What would you like to do?  
```

**Flag**: `CTF{my_rust_is_rusty}`

Original writeup
(https://github.com/TFNS/writeups/tree/master/2020-02-23-BSidesSF/config-
me/README.md).