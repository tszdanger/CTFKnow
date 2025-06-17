Hackover CTF 2018: military-crypto  
==================================

## Description

We take security seriously so instead of shipping our own crypto we simply use  
proven military grade technology for our firmware updates.

`nc military-crypto.ctf.hackover.de 1337`

## Solution

When connecting to the interface we're presented with a menu:

```  
====================================================  
   == secure update service

   we didn't roll our own, powered by the  
   best crypto known to humanity  
====================================================  
1) Update firmware    3) Current firmware  
2) Download firmware  4) Quit  
```

* **Update firmware** asks us to upload a new firmware and a detached PGP  
signature.

* **Download firmware** sends back the source code of the server encoded with  
base64.

* **Current firmware** sends back a PGP signed message with some information  
about the current firmware.

Clearly the goal here is to provide a new firmware and a signature to trick
the  
server into running it. So let's inspect the code of the server and see how
the  
verification is done.

```sh  
update_firmware() {  
  cat <<EOF  
====================================================  
   1) send update binary as base64  
   2) finish with an empty line  
   3) send detached signature as base64  
   4) finish with an empty line  
====================================================  
EOF  
  echo 'Reading firmware...'  
  touch update.bin.b64  
  while IFS='' read -r firmware; do  
      if [ -z "$firmware" ]; then break; fi  
      echo "$firmware" >> update.bin.b64  
  done  
  base64 -d update.bin.b64 > update.bin  
  rm update.bin.b64

  echo 'Reading detatched signaure...'  
  touch update.bin.sig  
  while IFS='' read -r signature; do  
      if [ -z "$signature" ]; then break; fi  
      echo "$signature" >> update.bin.sig.b64  
  done  
  base64 -d update.bin.sig.b64 > update.bin.sig  
  rm update.bin.sig.b64

  if ! gpg --verify update.bin.sig; then  
      set +x  
      echo '!!!!!!!!!!!!!!!!!!!!!!!'  
      echo '!! INVALID SIGNATURE !!'  
      echo '!!!!!!!!!!!!!!!!!!!!!!!'  
      exit 1  
  else  
      chmod +x update.bin  
      echo 'Updating....'  
      ./update.bin  
      echo 'Rebooting....'  
      exit 0  
  fi  
}  
```

The firmware is verified with `gpg --verify update.bin.sig`.

From `man gpg`:

```  
--verify  
             Assume that the first argument is a signed file and verify it  
             without generating any output.

             ...

             gpg may assume that a single argument is a file with a detached  
             signature, and it will try to find a matching data file by  
             stripping certain suffixes. Using this historical feature to  
             verify a detached signature is strongly discouraged; you should  
             always specify the data file explicitly.  
```

It seems that when `--verify` can both be used to verify signed files (where
the  
contents and the signature are in the same file) and files with a detached  
signature (where the signature is in a separate file).

The server expects a detached signature for `update.bin` but if we instead
send  
a self-contained signed message, gpg will think that we're trying to verify
the  
contents of that file and ignore `update.bin`. The `Current firmware` command  
conveniently sends back exactly that.

For the final exploit we can simply send a shell script that launches  
`/bin/bash` as the new firmware and the output of `Current firmware` as the  
signature.

Flag: `hackover18{r0ll_y0_0wn_crypt0_w1th_pgp}`  

Original writeup (https://github.com/ctf-
epfl/writeups/tree/master/hackover18/military-crypto).