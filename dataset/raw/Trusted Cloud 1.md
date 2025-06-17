The provided disk image contains two partitions, the first partition is EFI
loader  
with keywords "systemd" and "Arch Linux", the second partition is LUKS-
encrypted.

The task also provides network capture with a log of TPM requests and
responses.  
Wireshark has a dissector for TPM2 protocol; the dissector doesn't handle  
input and output parameters, leaving all of them as one combined blob,  
but it is sufficient for this task.

"Measured boot" process sends hashes of everything that is about to execute  
to the TPM, and then asks for decryption keys. TPM compares those hashes  
with those that were previously sealed, and returns requested keys only if  
everything matches and the system was not tampered with. The capture contains  
several TPM2_CC_PCR_Extend requests, eventually followed by TPM2_CC_Unseal  
(along with some other, irrelevant commands), the key should be in the
response  
to TPM2_CC_Unseal. Wireshark shows  
`RESPONSE PARAMS:
0020d57256b7127609a08607f99d6a0b9ff12af45c1c01f7b14322248bfc8072a3d5`  
when dissecting the response. First two bytes are obviously length in big-
endian  
of the one and only output parameter, and the rest must be a decryption key.  
(As Part 3 will show, TPM2 protocol has a possibility to encrypt data on-the-
wire,  
but this is not used here.)

Searching for TPM2/unseal/LUKS in systemd sources reveals that the TPM key  
is base64-encoded when opening LUKS volume:
[https://github.com/systemd/systemd/blob/26b283299254fd0b3a50bb635ac81da1d986d905/src/cryptsetup/cryptsetup-
tokens/cryptsetup-token-systemd-
tpm2.c#L109](https://github.com/systemd/systemd/blob/26b283299254fd0b3a50bb635ac81da1d986d905/src/cryptsetup/cryptsetup-
tokens/cryptsetup-token-systemd-tpm2.c#L109).

Base64 of the key above is `1XJWtxJ2CaCGB/mdaguf8Sr0XBwB97FDIiSL/IByo9U=`;  
mounting the volume with this as a passphrase succeeds (assuming you don't try  
to do it inside
[WSL](https://github.com/microsoft/WSL/issues/6584#issuecomment-786652601))  
and reveals the flag `CTF{The_S3cr3t_could_have_been_encrypted}` in `/flag`  
plus files for Part 2 and Part 3.