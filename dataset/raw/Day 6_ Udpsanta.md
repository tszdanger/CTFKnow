# Udpsanta - Crypto/pwn/reversing (250)

Little known fact about Santa is that he runs an encrypted messaging service
over UDP. We managed to capture some traffic...

Service: UDP 18.205.93.120:1206

Download: [mMZfQMAdYKHBUwFDJR8XCr4yd2DS5anm-
udpsanta.tar.xz](https://s3.amazonaws.com/advent2018/mMZfQMAdYKHBUwFDJR8XCr4yd2DS5anm-
udpsanta.tar.xz) [(mirror)](./static/mMZfQMAdYKHBUwFDJR8XCr4yd2DS5anm-
udpsanta.tar.xz)

## Setup

This challenge proved challenging for a number of reasons as I'll describe
below, but I had the right idea for a solution basically from the beginning.
The description below is out-of-order in terms of how I solved the problem,
but I think that this describes the solution to the problem in an easier-to-
understand way. Since a lot of the implementation of this attack centered
around getting the byte structure, offset, payload, etc setup exactly right, I
found it easier to set this challenge up on my own virtual machine and
experiment with.

First off, the challenge provided only a pcap file. From this there were three
HTTP connetions over TCP/8000. Two connections contained a `client` and
`server` binary which I extracted. The third contained a protobuf
specification which proved helpful in understanding the messages. There was
also a good deal of UDP/1206 traffic which seemed to give a feel for what kind
of traffic was sent with this protocol.

The `client` and `server` binaries seemed to work just fine with an Ubuntu
18.04 OS. Below is some terminal output to give a feel for the setup. The
`key` and `iv` I used for testing were just random bytes, and the `priv` and
`pub` were RSA keys created with openssl.

```sh  
# apt update && apt install -y libprotobuf-c1 libssl1.1  
john@john-virtual-machine:~$ ldd /opt/udpsanta/client  
	linux-vdso.so.1 (0x00007fff5cff0000)  
	libprotobuf-c.so.1 => /usr/lib/x86_64-linux-gnu/libprotobuf-c.so.1 (0x00007f14d5d51000)  
	libcrypto.so.1.1 => /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 (0x00007f14d58d9000)  
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f14d54e8000)  
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f14d52e4000)  
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f14d50c5000)  
	/lib64/ld-linux-x86-64.so.2 (0x00007f14d619c000)  
john@john-virtual-machine:~$ ldd /opt/udpsanta/server  
	linux-vdso.so.1 (0x00007fffb6196000)  
	libprotobuf-c.so.1 => /usr/lib/x86_64-linux-gnu/libprotobuf-c.so.1 (0x00007f3611f23000)  
	libcrypto.so.1.1 => /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 (0x00007f3611aab000)  
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f36116ba000)  
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f36114b6000)  
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f3611297000)  
	/lib64/ld-linux-x86-64.so.2 (0x00007f361236d000)  
john@john-virtual-machine:~$ find /opt/udpsanta/  
/opt/udpsanta/  
/opt/udpsanta/client  
/opt/udpsanta/userdata  
/opt/udpsanta/userdata/keys  
/opt/udpsanta/userdata/keys/Timmy.key  
/opt/udpsanta/userdata/keys/Timmy.iv  
/opt/udpsanta/userdata/keys/Timmy.priv  
/opt/udpsanta/userdata/keys/Timmy.pub  
/opt/udpsanta/userdata/userlist.txt  
/opt/udpsanta/server  
john@john-virtual-machine:~$ ll /opt/udpsanta/userdata/keys/  
total 24  
drwxr-xr-x 2 john john 4096 Dec 14 22:09 ./  
drwxr-xr-x 3 john root 4096 Dec 14 21:59 ../  
-rw-r--r-- 1 john john   32 Dec 14 22:16 Timmy.iv  
-rw-r--r-- 1 john john   32 Dec 14 22:16 Timmy.key  
-rw------- 1 john john  891 Dec 14 22:04 Timmy.priv  
-rw-r--r-- 1 john john  272 Dec 14 22:05 Timmy.pub  
john@john-virtual-machine:~$ ll ~/.udpsanta/  
total 16  
drwxr-xr-x  2 john john 4096 Dec 14 22:29 ./  
drwxr-xr-x 31 john john 4096 Dec 31 11:15 ../  
lrwxrwxrwx  1 john john   38 Dec 14 22:12 private.key ->
/opt/udpsanta/userdata/keys/Timmy.priv  
lrwxrwxrwx  1 john john   37 Dec 14 22:12 public.key ->
/opt/udpsanta/userdata/keys/Timmy.pub  
-rw-r--r--  1 root root 3024 Dec 14 22:29 test_tcpdump.pcapng  
-rw-r--r--  1 john john    6 Dec 14 22:11 user.name  
```

I chose to experiment with the user `Timmy` as this name was found in the pcap
file and contained the most messages to and from the server.  
With all of this setup, I connected `client` to `server` over localhost and
captured some traffic. I then wrote a python script to decrypt and parse out
the commands captured. The script and output are shown below:

```python  
# protoc -I=. --python_out=. ./udpsanta.proto  
# pip3 install protobuf  
import udpsanta_pb2  
import binascii  
import Crypto.Hash.SHA256 as SHA256  
import Crypto.Cipher.AES as AES

def timmy_decrypt(cipher):  
	TIMMY_KEY = b'\x9f\xa2(\xe6\x88hDb\x9f.\x1fq\xf9\xc7\x91mW\x86\xc8\xb1\xa4\x9fK\xf0\xfa=Y\xe3%$\xc5\x04'  
	TIMMY_IV = b'\x92\xc4\xc8\xfet\xf4\x11\xe5\x88u\x9a\x14\xab\x96\xbe\x1e'  
	a = AES.new(TIMMY_KEY,AES.MODE_CBC,iv=TIMMY_IV)  
	print('cipher',len(cipher),cipher)  
	plain = a.decrypt(cipher)  
	print('plain',len(plain),plain)  
	return plain

def parse_request(hex_str):

	print('='*80)  
	print(' REQUEST'*10)

	packet = binascii.unhexlify(hex_str)

	req = udpsanta_pb2.Request()  
	req.ParseFromString(packet)  
	print(req)  
	if req.encrypted:  
		dec = timmy_decrypt(req.innerRequest)  
		reqi = udpsanta_pb2.RequestInner()  
		reqi.ParseFromString(dec[:-dec[-1]])  
		print(reqi)  
	else:  
		reqi = udpsanta_pb2.RequestInner()  
		reqi.ParseFromString(req.innerRequest)  
		print(reqi)

	return req.innerRequest

def parse_response(hex_str):

	print('='*80)  
	print(' RESPONSE'*9)

	packet = binascii.unhexlify(hex_str)

	res = udpsanta_pb2.Response()  
	res.ParseFromString(packet)  
	print(res)

	if not res.pki_encrypted:  
		dec = timmy_decrypt(res.innerResponse)  
		resi = udpsanta_pb2.ResponseInner()  
		resi.ParseFromString(dec[:-dec[-1]])  
		print(resi)

	return res.innerResponse

def parse_captures():

	# the following are my own test setups  
	parse_request('0a0554696d6d7910001ab0020800128f022d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d4947664d413047435371475349623344514542415155414134474e4144434269514b4267514453767a4f6633595a476b364d6b684834544d3570576d77646f0a584e32583734495164744835304e78536b716f6e45584b426f487756584e4a7176597479674c43373539474e37796443384a4275336357664c6a5633716f656f0a426d6d64334f756a7a515752386e424c76306c73446269434a76796849647147464e325350506e697375504a31626e655963464139342b6f573033535633712b0a787a4872354c4c3839655a4e4f68483141774944415141420a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d28e4e9d1e00532144879744f696956627866716b6d76654e71735100')  
	parse_response('0a403132303631383336303561323734303130323333633933366231616135323834383738373865303661616333313862633430323262626536336664386663663510011af4010000008066d957ef5d0ee86c6b94bdd1f6838a8c42d1760a5b83c65c713453b11575de49f1a078618e474d22b2e144f66afae9b9eb1ff4164394688030a6770568081be8840922c777d02a6a7f2d187857463c7fc72eeebf71497e09d026415577cf000265192cdb013075c00fd0167a0b50a819a5d03949361a14b5949aca74cb0dc958c73d5507ba77db253ff119417f78ad8935962f35168f496d0aa597c23da908428ba76a3cb88f88409b80bdf5615229b09b3bf3587d74a6fb0f9bf9565dde6670d1ffe8f6ebe32eae73a8b3e2e7e836921094c4b638ac07ce499b58ac08445be12abbc8477f621af573d127cdf4cce6a2')  
	parse_request('0a0554696d6d7910011a30306f24a968ec230bd387bdc6e9d751c3b525ffb2f0e14232af4e14e36149239c6f502202ae0480fc1f35f4c45000c4a6')  
	parse_response('0a403132303637613563663630363637373436353731376130623765656632653133313132653130393261363063323664666237636438353537613636633538383010001a80013cd9c89d9676ad41a85049b22766b52e59b132a6a7a56e06c5803280141eddd1675ba2e79e7a43fc57cfa9641f771c94f25acd22c78a40fc02ee5c6bb818cb5ac61ed9fae23ad19dd544b9a2dc6a474f718309bb4b3098e732048f0ca763d7a07052e34b80cbce29861f032054ef26ac23000adf0610b53a832d193268e0eb99')  
	parse_request('0a0554696d6d7910011a30405b0d3ceba5ad2d1e02bbc4332053bdfb9870897fb23595668e0eaaf5db1848098d51d21a7d68f37a6ac369c57a2fb0')  
	parse_response('0a403132303633643634653838306432356237373334623134643864653734373032376635666465616331326536326162623332653538326362656136356162373110001a9001fc286d03e6baf94da36ec2db1fbc1d7ffa30da9f91371564965839204d528845f4a98fc599cc596368893f2d83c8f13757d2b5598e7ea8d67c7038b438084c37711f37c459738682f3cb061bdf6cfe793cd280df95cb753f5a2af198965edd733f41ebc30a505f1df8ece4739c0026d6a572e22615794571dc07d5cb01c8796722888a345f0701d5f71e0667874ff1ad')  
	parse_request('0a0554696d6d7910011a301d34e5df868b2cbf957f7416cf056f03d0157c53b6466acbb414aef2e31637feb74c7f77bd33e6d6718e9a723ae38564')  
	parse_response('0a403132303661663038316434376165613630356231633166393635336630343562343434653935303163313337383039666233326664653537346166303336323710001a800157f13a0bbf363f4392e7348c27b9d14f79a8df75f20a0865c7521568e11157b652373e826998198cbb72f789115f59f31bb1ec9d2faa85711f1afa2bbf5f62adc2589c160027084f09d924d7e1b4b180c4790a20e6c609930a27aa0a12879ba7d2ef374c49d323b37e2ad948bebc96d2543d78563892c433e575f6e552af5d3a')

if __name__ == '__main__':

	parse_captures()  
```

And the output:

```  
================================================================================  
REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST
REQUEST  
_from: "Timmy"  
innerRequest: "\010\000\022\217\002-----BEGIN PUBLIC
KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSvzOf3YZGk6MkhH4TM5pWmwdo\nXN2X74IQdtH50NxSkqonEXKBoHwVXNJqvYtygLC759GN7ydC8JBu3cWfLjV3qoeo\nBmmd3OujzQWR8nBLv0lsDbiCJvyhIdqGFN2SPPnisuPJ1bneYcFA94+oW03SV3q+\nxzHr5LL89eZNOhH1AwIDAQAB\n
-----END PUBLIC KEY-----(\344\351\321\340\0052\024HytOiiVbxfqkmveNqsQ\000"

arg1: "-----BEGIN PUBLIC
KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSvzOf3YZGk6MkhH4TM5pWmwdo\nXN2X74IQdtH50NxSkqonEXKBoHwVXNJqvYtygLC759GN7ydC8JBu3cWfLjV3qoeo\nBmmd3OujzQWR8nBLv0lsDbiCJvyhIdqGFN2SPPnisuPJ1bneYcFA94+oW03SV3q+\nxzHr5LL89eZNOhH1AwIDAQAB\n
-----END PUBLIC KEY-----"  
timestamp: 1544844516  
padding: "HytOiiVbxfqkmveNqsQ\000"

================================================================================  
RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE
RESPONSE  
replyTo: "1206183605a274010233c936b1aa528487878e06aac318bc4022bbe63fd8fcf5"  
pki_encrypted: true  
innerResponse:
"\000\000\000\200f\331W\357]\016\350lk\224\275\321\366\203\212\214B\321v\n[\203\306\\q4S\261\025u\336I\361\240xa\216GM\"\262\341D\366j\372\351\271\353\037\364\026C\224h\2000\246w\005h\010\033\350\204\t\"\307w\320*j\177-\030xWF<\177\307.\356\277qI~\t\320&AUw\317\000\002e\031,\333\0010u\300\017\320\026z\013P\250\031\245\3209I6\032\024\265\224\232\312t\313\r\311X\307=U\007\272w\333%?\361\031A\177x\255\2115\226/5\026\217Im\n\245\227\302=\251\010B\213\247j<\270\217\210@\233\200\275\365aR)\260\233;\363X}t\246\373\017\233\371V]\336fp\321\377\350\366\353\343.\256s\250\263\342\347\3506\222\020\224\304\2668\254\007\316I\233X\254\010D[\341*\273\310G\177b\032\365s\321\'\315\364\314\346\242"

================================================================================  
REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST
REQUEST  
_from: "Timmy"  
encrypted: true  
innerRequest:
"0o$\251h\354#\013\323\207\275\306\351\327Q\303\265%\377\262\360\341B2\257N\024\343aI#\234oP\"\002\256\004\200\374\0375\364\304P\000\304\246"

cipher 48
b'0o$\xa9h\xec#\x0b\xd3\x87\xbd\xc6\xe9\xd7Q\xc3\xb5%\xff\xb2\xf0\xe1B2\xafN\x14\xe3aI#\x9coP"\x02\xae\x04\x80\xfc\x1f5\xf4\xc4P\x00\xc4\xa6'  
plain 48 b'\x08\x02
\x14(\xe4\xe9\xd1\xe0\x052\x14YQ3FcV0m4jjNZHBfR1r\x00\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'  
cmd: LISTMSGS  
arg2num: 20  
timestamp: 1544844516  
padding: "YQ3FcV0m4jjNZHBfR1r\000"

================================================================================  
RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE
RESPONSE  
replyTo: "12067a5cf606677465717a0b7eef2e13112e1092a60c26dfb7cd8557a66c5880"  
innerResponse:
"<\331\310\235\226v\255A\250PI\262\'f\265.Y\2612\246\247\245n\006\305\2002\200\024\036\335\321g[\242\347\236zC\374W\317\251d\037w\034\224\362Z\315\"\307\212@\374\002\356\\k\270\030\313Z\306\036\331\372\342:\321\235\325D\271\242\334jGOq\203\t\273K0\230\3472\004\217\014\247c\327\240pR\343K\200\313\316)\206\037\003
T\357&\254#\000\n\337\006\020\265:\203-\0312h\340\353\231"

cipher 128
b'<\xd9\xc8\x9d\x96v\xadA\xa8PI\xb2\'f\xb5.Y\xb12\xa6\xa7\xa5n\x06\xc5\x802\x80\x14\x1e\xdd\xd1g[\xa2\xe7\x9ezC\xfcW\xcf\xa9d\x1fw\x1c\x94\xf2Z\xcd"\xc7\x8a@\xfc\x02\xee\\k\xb8\x18\xcbZ\xc6\x1e\xd9\xfa\xe2:\xd1\x9d\xd5D\xb9\xa2\xdcjGOq\x83\t\xbbK0\x98\xe72\x04\x8f\x0c\xa7c\xd7\xa0pR\xe3K\x80\xcb\xce)\x86\x1f\x03
T\xef&\xac#\x00\n\xdf\x06\x10\xb5:\x83-\x192h\xe0\xeb\x99'  
plain 128
b'\x08\x02\x10\xe4\xe9\xd1\xe0\x05(\x002P\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff:\x14hW3uvrsqRsRft4GMp61\x00\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'  
cmd: LISTMSGS  
timestamp: 1544844516  
resultbytes:
"\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377"  
padding: "hW3uvrsqRsRft4GMp61\000"

================================================================================  
REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST
REQUEST  
_from: "Timmy"  
encrypted: true  
innerRequest: "@[\r<\353\245\255-\036\002\273\3043
S\275\373\230p\211\177\2625\225f\216\016\252\365\333\030H\t\215Q\322\032}h\363zj\303i\305z/\260"

cipher 48 b'@[\r<\xeb\xa5\xad-\x1e\x02\xbb\xc43
S\xbd\xfb\x98p\x89\x7f\xb25\x95f\x8e\x0e\xaa\xf5\xdb\x18H\t\x8dQ\xd2\x1a}h\xf3zj\xc3i\xc5z/\xb0'  
plain 48
b'\x08\x01\x12\x04test\x1a\x0811223344(\xf0\xe9\xd1\xe0\x052\x14r5yFE5SlaGtfswbif50\x00\x02\x02'  
cmd: SENDMSG  
arg1: "test"  
arg2: "11223344"  
timestamp: 1544844528  
padding: "r5yFE5SlaGtfswbif50\000"

================================================================================  
RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE
RESPONSE  
replyTo: "12063d64e880d25b7734b14d8de747027f5fdeac12e62abb32e582cbea65ab71"  
innerResponse:
"\374(m\003\346\272\371M\243n\302\333\037\274\035\177\3720\332\237\2217\025d\226X9
MR\210E\364\251\217\305\231\314Ych\211?-\203\310\3617W\322\265Y\216~\250\326|p8\2648\010L7q\0377\304Ys\206\202\363\313\006\033\337l\376y<\322\200\337\225\313u?Z*\361\230\226^\335s?A\353\303\nP_\035\370\354\344s\234\000&\326\245r\342&\025yEq\334\007\325\313\001\310yg\"\210\2124_\007\001\325\367\036\006g\207O\361\255"

cipher 144
b'\xfc(m\x03\xe6\xba\xf9M\xa3n\xc2\xdb\x1f\xbc\x1d\x7f\xfa0\xda\x9f\x917\x15d\x96X9
MR\x88E\xf4\xa9\x8f\xc5\x99\xccYch\x89?-\x83\xc8\xf17W\xd2\xb5Y\x8e~\xa8\xd6|p8\xb48\x08L7q\x1f7\xc4Ys\x86\x82\xf3\xcb\x06\x1b\xdfl\xfey<\xd2\x80\xdf\x95\xcbu?Z*\xf1\x98\x96^\xdds?A\xeb\xc3\nP_\x1d\xf8\xec\xe4s\x9c\x00&\xd6\xa5r\xe2&\x15yEq\xdc\x07\xd5\xcb\x01\xc8yg"\x88\x8a4_\x07\x01\xd5\xf7\x1e\x06g\x87O\xf1\xad'  
plain 144 b"\x08\x04\x10\xf0\xe9\xd1\xe0\x05\x1a^Due to an unprecedented
amount of requests, Santa's messaging server has run out of
diskspace.(\x00:\x14QtuNod3fLomkv8dOus6\x00\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"  
cmd: ERROR  
timestamp: 1544844528  
result1: "Due to an unprecedented amount of requests, Santa\'s messaging
server has run out of diskspace."  
padding: "QtuNod3fLomkv8dOus6\000"

================================================================================  
REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST REQUEST
REQUEST  
_from: "Timmy"  
encrypted: true  
innerRequest:
"\0354\345\337\206\213,\277\225\177t\026\317\005o\003\320\025|S\266Fj\313\264\024\256\362\343\0267\376\267L\177w\2753\346\326q\216\232r:\343\205d"

cipher 48
b'\x1d4\xe5\xdf\x86\x8b,\xbf\x95\x7ft\x16\xcf\x05o\x03\xd0\x15|S\xb6Fj\xcb\xb4\x14\xae\xf2\xe3\x167\xfe\xb7L\x7fw\xbd3\xe6\xd6q\x8e\x9ar:\xe3\x85d'  
plain 48 b'\x08\x02
\x14(\xf2\xe9\xd1\xe0\x052\x14jQXC5Hf9NgHsT6jMH80\x00\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'  
cmd: LISTMSGS  
arg2num: 20  
timestamp: 1544844530  
padding: "jQXC5Hf9NgHsT6jMH80\000"

================================================================================  
RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE
RESPONSE  
replyTo: "1206af081d47aea605b1c1f9653f045b444e9501c137809fb32fde574af03627"  
innerResponse:
"W\361:\013\2776?C\222\3474\214\'\271\321Oy\250\337u\362\n\010e\307R\025h\341\021W\266R7>\202i\230\031\214\273r\367\211\021_Y\363\033\261\354\235/\252\205q\037\032\372+\277_b\255\302X\234\026\000\'\010O\t\331$\327\341\264\261\200\304y\n
\346\306\t\223\n\'\252\n\022\207\233\247\322\3577LI\323#\263~*\331H\276\274\226\322T=xV8\222\3043\345u\366\345R\257]:"

cipher 128
b"W\xf1:\x0b\xbf6?C\x92\xe74\x8c'\xb9\xd1Oy\xa8\xdfu\xf2\n\x08e\xc7R\x15h\xe1\x11W\xb6R7>\x82i\x98\x19\x8c\xbbr\xf7\x89\x11_Y\xf3\x1b\xb1\xec\x9d/\xaa\x85q\x1f\x1a\xfa+\xbf_b\xad\xc2X\x9c\x16\x00'\x08O\t\xd9$\xd7\xe1\xb4\xb1\x80\xc4y\n
\xe6\xc6\t\x93\n'\xaa\n\x12\x87\x9b\xa7\xd2\xef7LI\xd3#\xb3~*\xd9H\xbe\xbc\x96\xd2T=xV8\x92\xc43\xe5u\xf6\xe5R\xaf]:"  
plain 128
b'\x08\x02\x10\xf2\xe9\xd1\xe0\x05(\x002P\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff:\x14I7opdFhJiuD7aXpObsH\x00\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'  
cmd: LISTMSGS  
timestamp: 1544844530  
resultbytes:
"\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377"  
padding: "I7opdFhJiuD7aXpObsH\000"

```

## Protobuf Details

At this point, a little explanation on how the protobufs were constructed for
this challenge is needed. First, the protobuf spec from the challenge packet
capture was given as below. Note: I added a couple comments to help my own
understanding.

```  
syntax = "proto3";

enum Command {  
 GETKEY = 0;    // <pubkey>  
 SENDMSG = 1;   // <username> <message>  
 LISTMSGS = 2;  // <count>  
 GETMSG = 3;    // <msgid>  
 ERROR = 4;    // only response, <error message>  
}

/*  
* Inner part of a request message.   
* command and parameters determine the nature of the request.  
* timestamp ensures freshness.  
* Padding is used to make the checksum in the Request message fit its requirements.  
* The serialized form of this may be encrypted using symmetric encryption  
* before use in the following Request message.  
*/  
message RequestInner {  
 Command cmd = 1;  
 string arg1 = 2;  
 string arg2 = 3;  
 uint32 arg2num = 4;  
 uint32 timestamp = 5;  
 bytes padding = 6;  
}

/*  
* A full request.   
*     from: the username of the user sending the request. This determines the encryption keys used.  
*     encrypted: is the message encrypted with symmetric encryption?  
*     innerRequest: serialized RequestInner message,   
*                   optionally encrypted with symmetric key, depending on command  
*/  
message Request {  
 string _from = 1;  
 bool encrypted = 2;  
 bytes innerRequest = 3;  
}

/*  
* a response contains the server's timestamp for synchronization,  
* and whatever data the server wants to send back.  
* Padding is used to make the checksum in the Response message fit its requirements.  
*/  
message ResponseInner {  
 Command cmd = 1;  
 uint32 timestamp = 2;  
 string result1 = 3;  
 string result2 = 4;  
 bool resultbool = 5;  
 bytes resultbytes = 6;  
 bytes padding = 7;  
}

/*  
* A full response.  
*     replyTo: the sha256 of the request being replied to  
*     innerResponse: serialized ResponseInner message,   
*                    encrypted with public or symmetric key,  depending on command  
*     padding: some unused space that can be filled with garbage  
*/  
message Response {  
 string replyTo = 1;  
 bool pki_encrypted = 2;  
 bytes innerResponse = 3;  
}  
```

For this challenge, most of the elements in each protobuf are not marked as
required which makes things easier for constructing a new buffer. Again, I
wrote a python function and reviewed the output to figure out how a protobuf
was constructed:

```python  
def test_protobuf():

	print('RequestInner Testing:')  
	reqi = udpsanta_pb2.RequestInner()  
	reqi.cmd = 1  
	print(reqi.SerializeToString())  
	reqi.arg1 = 'aa'  
	print(reqi.SerializeToString())  
	reqi.arg2 = 'bbb'  
	print(reqi.SerializeToString())  
	reqi.arg2num = 20  
	print(reqi.SerializeToString())  
	reqi.timestamp = 1  
	print(reqi.SerializeToString())  
	reqi.timestamp = 0x1234567  
	print(reqi.SerializeToString())  
	reqi.padding = b'cccc'  
	print(reqi.SerializeToString())

	print('Request Testing:')  
	req = udpsanta_pb2.Request()  
	req._from = 'Timmy'  
	print(req.SerializeToString())  
	req.encrypted = True  
	print(req.SerializeToString())  
	req.innerRequest = b'innerRequest'  
	print(req.SerializeToString())

	print('ResponseInner Testing:')  
	resi = udpsanta_pb2.ResponseInner()  
	resi.cmd = 2  
	print(resi.SerializeToString())  
	resi.timestamp = 0x7654321  
	print(resi.SerializeToString())  
	resi.result1 = 'dddd'  
	print(resi.SerializeToString())  
	resi.result2 = 'eee'  
	print(resi.SerializeToString())  
	resi.resultbool = True  
	print(resi.SerializeToString())  
	resi.resultbytes = b'ff'  
	print(resi.SerializeToString())  
	resi.padding = b'g'  
	print(resi.SerializeToString())

	print('Response Testing:')  
	res = udpsanta_pb2.Response()  
	res.replyTo = 'aabbccdd';  
	print(res.SerializeToString())  
	res.pki_encrypted = True  
	print(res.SerializeToString())  
	res.innerResponse = b'innerResponse'  
	print(res.SerializeToString())  
```

And the output:

```  
$ ./challenge6.py  
RequestInner Testing:  
b'\x08\x01'  
b'\x08\x01\x12\x02aa'  
b'\x08\x01\x12\x02aa\x1a\x03bbb'  
b'\x08\x01\x12\x02aa\x1a\x03bbb \x14'  
b'\x08\x01\x12\x02aa\x1a\x03bbb \x14(\x01'  
b'\x08\x01\x12\x02aa\x1a\x03bbb \x14(\xe7\x8a\x8d\t'  
b'\x08\x01\x12\x02aa\x1a\x03bbb \x14(\xe7\x8a\x8d\t2\x04cccc'  
Request Testing:  
b'\n\x05Timmy'  
b'\n\x05Timmy\x10\x01'  
b'\n\x05Timmy\x10\x01\x1a\x0cinnerRequest'  
ResponseInner Testing:  
b'\x08\x02'  
b'\x08\x02\x10\xa1\x86\x95;'  
b'\x08\x02\x10\xa1\x86\x95;\x1a\x04dddd'  
b'\x08\x02\x10\xa1\x86\x95;\x1a\x04dddd"\x03eee'  
b'\x08\x02\x10\xa1\x86\x95;\x1a\x04dddd"\x03eee(\x01'  
b'\x08\x02\x10\xa1\x86\x95;\x1a\x04dddd"\x03eee(\x012\x02ff'  
b'\x08\x02\x10\xa1\x86\x95;\x1a\x04dddd"\x03eee(\x012\x02ff:\x01g'  
Response Testing:  
b'\n\x08aabbccdd'  
b'\n\x08aabbccdd\x10\x01'  
b'\n\x08aabbccdd\x10\x01\x1a\rinnerResponse'  
```

From this it takes some short analysis to see that each 'element' in the
protobuf array is roughly 1 byte type (including the type and ID), 1 byte
length (if a variable length type), and variable length data.  
Since the `innerRequest` will be the type we end up sending later and
`innerResponse` is used in the explanation later, the breakdown for that
protobuf is:

```  
InnerRequest:  
08 01                 -- Command cmd = 1; value == "1" (SENDMSG)  
12 02 'a' 'a'         -- string arg1 = 2; value == length 2, 'aa'  
1A 03 'b' 'b' 'b'     -- string arg2 = 3; value == length 3, 'bbb'  
20 14                 -- uint32 arg2num = 4; value == 20 = 0x14  
28 01                 -- uint32 timestamp = 5; value == 1 == 0x01  
28 E7 8A 8D 09        -- uint32 timestamp = 5; value == 0x1234567  
32 04 'c' 'c' 'c' 'c' -- bytes padding = 6; value == length 4, 'cccc'

Inner Response (differences):  
10 A1 86 95 3B        -- uint32 timestamp = 2; value == 0x7654321  
22 03 'e' 'e' 'e'     -- string result2 = 4; value == length 3, 'eee'  
3A 01 'g'             -- bytes padding = 7; value == length 1, 'g'  
```

I'm sure all of this is explained in the protobuf spec and details, but it
definitely helps me to see it all concretely. In terms of how these are
organized in a payload buffer, it does not seem to matter what order or how
many times each of these individual elements occurs in a protobuf. However, if
the protobuf has a first byte of the right index but wrong type, then the
`server` application does not seem to parse it correctly and throws an error.
Basically what this means is that if you take a server innerResponse (which
includes a 'uint32 timestamp = 2' type) and try to send it in a innerRequest
then since the types do not match the server will throw an error and return
nothing.

## Challenge Details

And now we get to the main part of the problem. What is pretty obvious after
reviewing the spec and seeing some of the traffic is the fact that there is no
authentication (MAC, HMAC, hash, etc.) on any part of the protocol. A lot of
the messages sent back and forth are encrypted in CBC mode, but without an
authenticated piece this opens the protocol up to attacks where we can craft
encrypted payloads. Furthermode, the decrypted payloads shown in the first
section contain a bunch of PKCS5 padding which, when combined with CBC mode,
means we're likely dealing with a CBC padding oracle attack.

Some further implementation details that are relevant in this are:

* the IV is not provided in a request or innerRequest message, it is fixed - so we cannot construct a complete message since we don't control the IV  
* the encryption keys used in the sample payload are not the same as the challenge server - this is evidenced by the fact that we cannot replay messages from the pcap file on the real server  
* The server only processes requests which have a SHA256 hash which starts with the bytes "1206" - this significantly slows down any script we're going to write as a lot of messages will just get thrown out to begin with  
* The requests and responses both use the same key/iv for a given user.

## Getting Fuzzy

This part is the biggest logical leap I had to take in order to solve the
challenge. After exhausting pretty much every other avenue (replaying packets,
sending responses, parts of responses or other data as requests, etc) did I
get to this point. It turns out that the protobuf parsing library will
sometimes parse random data correctly (who knew!). I only figured this out
through fuzzing the `server` program, and a sample of this is given below. The
trick to fuzzing here is that our message contains some amount of known bytes
(`08 01` corresponding to Command SENDMSG in this case) prepended with random
data.

```python  
def get_sha(data):  
	s = SHA256.new()  
	s.update(data)  
	return s.hexdigest()

def sha_matches(data):  
	return get_sha(data).startswith('1206')

def send_and_recv(sock,req_data,catch_timeout=False):

	try:  
		sock.sendto(req_data,(UDP_IP,UDP_PORT))  
		res_data,res_addr = sock.recvfrom(1024)  
		return res_data  
	except socket.timeout as e:  
		print('timed out')  
		if catch_timeout:  
			return None  
		raise e

	return None

def do_unencrypted_fuzz(size,ending=b'\x08\x01'):

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
	sock.settimeout(2)

	seed = 0  
	while True:  
		ocd_found = False  
		while not ocd_found:  
			random.seed(seed)  
			req_inner = bytes([random.randint(0,255) for i in range(size)]) + ending  
			req = udpsanta_pb2.Request()  
			req._from = 'Timmy'  
			#req.encrypted = 0  
			req.innerRequest = req_inner  
			req_data = req.SerializeToString()  
			ocd_found = sha_matches(req_data)  
			seed += 1

		print('innerRequest (seed %d):'%seed,req.innerRequest)  
		res = send_and_recv(sock,req_data,catch_timeout=True)  
		if res is not None:  
			parse_response(binascii.hexlify(res))  
			break

if __name__ == '__main__':  
	do_unencrypted_fuzz(4)  
	do_unencrypted_fuzz(16)  
```

And some output:

```  
$ time ./challenge6.py  
innerRequest (seed 3618): b'P\xd2\x10\xbb\x08\x01'  
timed out  
innerRequest (seed 11303): b'\xc8\xc0\x00t\x08\x01'  
================================================================================  
RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE
RESPONSE  
replyTo: "1206659322a00be3c31dfd3754d04d276781a8d0b213a9dc3ac1539f8bc54f80"  
innerResponse:
"Wi\331_rW\030M\343\341\267sD\317q\221E\322\021qC\231T\035\357\242W\201\301[`\316\r\035a\313[\300\235\260jt\220\327\316\321\023\r\273\202\000
\327(Rd\'O?\371O\3264\272h\221\360\"\356\243\340\246`\333\'\240\351\3074;\256\252_S\273\360w\233v<\023\243y\217\225V\364\257q\t\323\313\201\017\365\237\302\005\203T\007.c-%\264\347X&\376\025\034t\267*n\252\205\212=\000\032\275\255|\037ZK\353\326\320\247\335\t"

cipher 144
b'Wi\xd9_rW\x18M\xe3\xe1\xb7sD\xcfq\x91E\xd2\x11qC\x99T\x1d\xef\xa2W\x81\xc1[`\xce\r\x1da\xcb[\xc0\x9d\xb0jt\x90\xd7\xce\xd1\x13\r\xbb\x82\x00
\xd7(Rd\'O?\xf9O\xd64\xbah\x91\xf0"\xee\xa3\xe0\xa6`\xdb\'\xa0\xe9\xc74;\xae\xaa_S\xbb\xf0w\x9bv<\x13\xa3y\x8f\x95V\xf4\xafq\t\xd3\xcb\x81\x0f\xf5\x9f\xc2\x05\x83T\x07.c-%\xb4\xe7X&\xfe\x15\x1ct\xb7*n\xaa\x85\x8a=\x00\x1a\xbd\xad|\x1fZK\xeb\xd6\xd0\xa7\xdd\t'  
plain 144 b"\x08\x04\x10\xf6\x87\xb5\xe1\x05\x1a^Due to an unprecedented
amount of requests, Santa's messaging server has run out of
diskspace.(\x00:\x14QtuNod3fLomkv8dOus6\x00\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"  
cmd: ERROR  
timestamp: 1546470390  
result1: "Due to an unprecedented amount of requests, Santa\'s messaging
server has run out of diskspace."  
padding: "QtuNod3fLomkv8dOus6\000"

innerRequest (seed 66100):
b'\xd6x\xa4_\xd3_\xcd\x82\xb7"\xeb\x99g\xb9\xef}\x08\x01'  
timed out  
innerRequest (seed 152570):
b'7W\x13GI\xe3\xc6\x835\x1b?\xe9\x97\x9a\x03\x1e\x08\x01'  
timed out  
innerRequest (seed 172943):
b'\xf6\x14\x80\xbc\xb5\xd2\xa3KUyWkD\x96\x85\xf4\x08\x01'  
timed out  
innerRequest (seed 404572):
b'\xb0\x1a\x17\xd0K\x03\xaa`\xf9\x9cO\x10\xcb\x03#4\x08\x01'  
timed out  
innerRequest (seed 491882):
b'@\x16\xa8\x0b\x98\x97\x9ag\x133\x97\x98\x8a\x13\x0c~\x08\x01'  
timed out  
innerRequest (seed 513458):
b'\x06\t\xde~H\xae\xfd\xef\xae\xfc\xfd\xd3E\xd0\xac \x08\x01'  
timed out  
innerRequest (seed 580614):
b'\xea\xc2\x0c\xc3\xc1<\xdb\xad\x95\xb5/\xc6\x9e\x04XK\x08\x01'  
timed out  
innerRequest (seed 599714):
b'\xe1\xd6\xf87\xd6u\x90\x9c\x85\xc0%@\x10\xbe\x12\\\x08\x01'  
timed out  
innerRequest (seed 713991):
b'm`\x11X\x98\xef\xebq4W\xb8\x13\xfa\xcbz\x1a\x08\x01'  
timed out  
innerRequest (seed 759799):
b'\xc7c\xce)p\x97l\xc4\xbdj\xf8\r\xde\x8bV\x03\x08\x01'  
timed out  
innerRequest (seed 768849):
b'\xc2\xcc\xcb\xb3*R`p\x84\xf4wb\xba\x7f\xff\xe1\x08\x01'  
timed out  
innerRequest (seed 786371):
b"\xbee\x11\xea'\xb8\xcct^N\xab\x80\x12\xde\xe0o\x08\x01"  
timed out  
innerRequest (seed 827936): b'\x95-n#\xd2\xd0\xe1s\\\x8f==q)w\xc2\x08\x01'  
================================================================================  
RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE RESPONSE
RESPONSE  
replyTo: "1206a7b0ef409eb0e6cb7603112afd7221e35f098e63386843bc15364b3ac512"  
innerResponse:
"\016\213\016\233\247\025\351\374\363\272\317z\222V\'>\211\244)\306\201|.\'u\216~\013\017U)\n\374\301_e\205]xze\210c\177-\336\2574\3522H\257\354m?\362\255G\035L\307\235v\347\302c\001\tm\010\nHb\007\253U\360\375\0139_\271\373\377W\210\275\344\360E\353\245\351c\277r|;T\243X\014\325\362\312\024\227\266@\352\264\306T\313\356,\227\363-\252}]\"-\262\001Q\243\340\205\325K\024(\230\022G\326\303N\t\3478\024"

cipher 144
b'\x0e\x8b\x0e\x9b\xa7\x15\xe9\xfc\xf3\xba\xcfz\x92V\'>\x89\xa4)\xc6\x81|.\'u\x8e~\x0b\x0fU)\n\xfc\xc1_e\x85]xze\x88c\x7f-\xde\xaf4\xea2H\xaf\xecm?\xf2\xadG\x1dL\xc7\x9dv\xe7\xc2c\x01\tm\x08\nHb\x07\xabU\xf0\xfd\x0b9_\xb9\xfb\xffW\x88\xbd\xe4\xf0E\xeb\xa5\xe9c\xbfr|;T\xa3X\x0c\xd5\xf2\xca\x14\x97\xb6@\xea\xb4\xc6T\xcb\xee,\x97\xf3-\xaa}]"-\xb2\x01Q\xa3\xe0\x85\xd5K\x14(\x98\x12G\xd6\xc3N\t\xe78\x14'  
plain 144 b"\x08\x04\x10\xbc\x88\xb5\xe1\x05\x1a^Due to an unprecedented
amount of requests, Santa's messaging server has run out of
diskspace.(\x00:\x14I7opdFhJiuD7aXpObsH\x00\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"  
cmd: ERROR  
timestamp: 1546470460  
result1: "Due to an unprecedented amount of requests, Santa\'s messaging
server has run out of diskspace."  
padding: "I7opdFhJiuD7aXpObsH\000"

real    1m14.164s  
user    0m45.887s  
sys     0m0.114s  
```

As you can see, getting a random string of bytes to parse is not a quick
process, but it does work! The above program takes about a minute to run for
me so without some speedup this primitive (combined with the SHA256 "1206"
match) will take a very long time as part of an automated padding oracle
attack.

## Constructing a Padding Oracle

Ok, so to recap we have the following:

* We can get encrypted messages from the server  
* We can send encrypted messages to the server using the same key  
* We cannot control the IV used  
* Each user (probably) has their own key  
* There is likely a CBC padding oracle  
* We know how to construct an `innerRequest` protobuf  
* We can prefix random data to a message and have it parse ... sometimes

The next step for a padding oracle attack is to create some buffer which we
can send to the server which will return a response if the padding matches
_irrespective of if the protobuf parses_, otherwise it will return no
response. Starting with the same error response we've been using the entire
time (Command SENDMSG), we can see that the last block of this error message
is reliably all `0x10` bytes (perfect!). By taking the last two blocks of
ciphertext from this message, we can then create an arbitrary block of data
(or several as it turns out). Using this block I constructed

```  
        Ciphertext                   Plaintext  
Block 0: unknown_iv                   random plaintext  
Block 1: modified 2nd-to-last block   08 01 08 01 08 01 08 01 08 01 32 33 ??
?? ?? ??  
Block 2: unmodified last block        random plaintext  
Block 3*:modified target 2TL block    random plaintext  
Block 4: unmodified target LB         (irrelevant plaintext)  .. .. .. .. ..
.. .. 01  
```

Note: This writeup was written a couple weeks after I finished the problem. I
believe I actually inserted another dummy block between number 2 and 3 which I
_think_ matches the source code below. Either way, the code below is very
similar to the construction described here.

This plaintext block has: some random data to start, several `08 02` elements
for Command SENDMSG, `32 33` for a 0x32-long padding element, and a single
`0x01` padding byte. By creating several of these and sending them to the
server to wait for a response we have a template which we can use as part of a
padding oracle attack. Unfortunately, this only works for constructing a
template for a single padding length (0x01), but the process can be repeated
for each size 1..16.

With this set of templates, we can then go about getting a relevant encrypted
message from the server, and decrypting it one byte at a time by filling it in
as the "target" block(s) and guessing the correct padding.

This attack is extremely slow in python and had I used it to decrypt the
amount of data from the server I needed, it would have taken waaaay too long.
So, after figuring all this out I re-wrote my padding oracle in C. Its given
below:

```c  
// gcc challenge6.c -o challenge6

#include <stdint.h>  
#include <string.h>  
#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <unistd.h>  
#include <assert.h>  
#include <arpa/inet.h>  
#include <sys/socket.h>  
#include <time.h>  
#include <openssl/sha.h>

#define TRUE  1  
#define FALSE 0  
#define min(X,Y) ((X)<(Y)?(X):(Y))  
#define max(X,Y) ((X)>(Y)?(X):(Y))

#define PORT 1206  
//#define SERVER_NAME "192.168.129.196"  
#define SERVER_NAME "18.205.93.120"

void print_plaintext(uint8_t *plaintext)  
{  
	printf("plaintext: ");  
	for (int i=0; i<16; i++)  
		printf("%02x", plaintext[i]);  
	printf("  ");  
	for (int i=0; i<16; i++) {  
		if (plaintext[i] >= 0x20 && plaintext[i] < 0x7f)  
			printf("%c", plaintext[i]);  
		else  
			printf(".");  
	}  
	printf("\n");  
}

static uint8_t RECV_BUFFER[1024];

int send_and_recv(uint8_t *data, int size)  
{  
	static int sockfd = -1;  
	static struct sockaddr_in servaddr;

	if (sockfd == -1) {  
		// Creating socket file descriptor  
	    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {  
	        perror("socket creation failed");  
	        exit(EXIT_FAILURE);  
	    }

        memset(&servaddr, 0, sizeof(servaddr));

		// Filling server information   
		servaddr.sin_family = AF_INET;   
		servaddr.sin_port = htons(PORT);   
		servaddr.sin_addr.s_addr = inet_addr(SERVER_NAME);

		struct timeval tv;  
		memset(&tv,0,sizeof(tv));  
		//tv.tv_sec = 1;  
		//tv.tv_usec = 100000;  
		tv.tv_usec = 50000;

		setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));  
	}

	int n;  
	socklen_t len = sizeof(servaddr);

	if (0) {  
		printf("sending: ");  
		for (int i=0; i<size; i++)  
			printf("%02x",data[i]);  
		printf("\n");  
	}  
	sendto(sockfd, data, size, 0, (const struct sockaddr *) &servaddr, len);

	n = recvfrom(sockfd, (char *)RECV_BUFFER, sizeof(RECV_BUFFER), MSG_WAITALL, (struct sockaddr *) &servaddr, &len;;  
	RECV_BUFFER[n] = '\0';  
	return n;  
}

void parse_hex(char *arg, uint8_t *ciphertext, int len)  
{  
	int i;  
	for (i=0; i<len; i++) {  
		unsigned int ch;  
		sscanf(&arg[2*i],"%02x", &ch);  
		ciphertext[i] = (uint8_t)ch;  
	}  
}

uint8_t *get_prefix(char *username, int npad)  
{  
	static uint8_t prefix_list[17][80];

	if (strncmp(SERVER_NAME, "192.168", 7) == 0) {  
		parse_hex("8cb465dd4d28e8a803e48015beb110c787d47e870a4bf87eef5ad1fbb498ae07000000000000000000000000000000007b499220bad51f55f4194dd9f2f6b48787d47e870a4bf87eef5ad1fbb498ae07",prefix_list[1],80);  
		parse_hex("2ced96da847c20e942a8eba6c865ae2f0f8037ffd5511b7ff3a013cff1dd038a00000000000000000000000000000000db1061277381d714b555266bb72461aa0f8037ffd5511b7ff3a013cff1dd038a",prefix_list[2],80);  
		parse_hex("fc2d657265d211ee86bbd6ffd8e69d220fec27d089d3f55af5cc504ca8529185000000000000000000000000000000000bd0928f922fe61371461b31764d1a6c0fec27d089d3f55af5cc504ca8529185",prefix_list[3],80);  
		parse_hex("f95a31b71730d93c580fb81ff5f8d5265bd5e0630966425aa8df3bfe69402614000000000000000000000000000000000ea7c64ae0cd2ec1aff275d05f4c0cda5bd5e0630966425aa8df3bfe69402614",prefix_list[4],80);  
		parse_hex("2ec77fcd309dc4d03b34aaba21f63ee276afed1973b5bcbfe46a943fd23c697900000000000000000000000000000000d93a8830c760332dccc967901f5f3b5e76afed1973b5bcbfe46a943fd23c6979",prefix_list[5],80);  
		parse_hex("fe6805373de9295e867f038d5edefc7e8306d091ea5f922c6dae279c9f632e28000000000000000000000000000000000995f2caca14dea3718237a5e012cc1d8306d091ea5f922c6dae279c9f632e28",prefix_list[6],80);  
		parse_hex("fbee632a822b04e3a7537d4444c200f94dc90f37de97199a5e8f4c2647c023e7000000000000000000000000000000000c1394d775d6f31e5056486e756e548a4dc90f37de97199a5e8f4c2647c023e7",prefix_list[7],80);  
		parse_hex("a64af2a41b199de3a74c28f8efc229786cc91af9b13061857e26e6e3a855f91e0000000000000000000000000000000051b70559ece46a1ea74612dc4dc798986cc91af9b13061857e26e6e3a855f91e",prefix_list[8],80);  
		parse_hex("377a25905242675b12f351875789beb41d999a4602bfb9d781efbe8f87eab36600000000000000000000000000000000c087d26da5bf905013f86aa5a5fd966a1d999a4602bfb9d781efbe8f87eab366",prefix_list[9],80);  
		parse_hex("eca54705ca893a0f0fc987b5d55bc1d28dacd43d2b0cb724abcaa720c61eb779000000000000000000000000000000001b58b0f83d7438070dc1bf95c20ee42b8dacd43d2b0cb724abcaa720c61eb779",prefix_list[10],80);  
		parse_hex("322f34d51b0d51ea2fb47f92e4b906512ca9687d9f144d7313c7315f75e3b94900000000000000000000000000000000c5d2c328ec0452e32cbd46b0a251809d2ca9687d9f144d7313c7315f75e3b949",prefix_list[11],80);  
		parse_hex("f8161cda18a70e36330a8876ab090275381d6782011a5ec47ff453ac26802058000000000000000000000000000000000febeb271ca90a383704b6522533aeb2381d6782011a5ec47ff453ac26802058",prefix_list[12],80);  
		parse_hex("7ff744297af3cfb14c089998cc4988422aa017f73d984a9083b7d4b11b42766d00000000000000000000000000000000880ab3267ffccabe4907a6b26f2ce5382aa017f73d984a9083b7d4b11b42766d",prefix_list[13],80);  
		parse_hex("94e11286d7a3f9a557b649f5ea91b8956f64b9d2a752042df85bf195e71a731600000000000000000000000000000000631c148ad1afffa951ba75dd271d7bda6f64b9d2a752042df85bf195e71a7316",prefix_list[14],80);  
		parse_hex("d4b40a2239267d6a7a93a2cc5cb46bd3ab408b22e6fda8f1cf8533e4816ac6b90000000000000000000000000000000023b90d2f3e2b7a677d9e9fe6604feef1ab408b22e6fda8f1cf8533e4816ac6b9",prefix_list[15],80);  
		parse_hex("a90283ba2898ef75158f69750e76c9940dbe81ff88f6b17fc4a6cf8f86977e4900000000000000000000000000000000b1109ba8308af7670d9d4b41de0071040dbe81ff88f6b17fc4a6cf8f86977e49",prefix_list[16],80);  
	} else  
	if (strcmp(username,"Timmy") == 0) {  
		parse_hex("d96dcb7ea53a4d9c712599d3f0c5a2d577f2ed25e834fd168839954b986dc6bb000000000000000000000000000000002e903c8352c7ba6186d8541ff3d661fa77f2ed25e834fd168839954b986dc6bb",prefix_list[1],80);  
		parse_hex("979cd574282466f27859adf5e795bbfd8f4a6bcc58c949333425807bb0b3de3c0000000000000000000000000000000060612289dfd9910f8fa460380448538e8f4a6bcc58c949333425807bb0b3de3c",prefix_list[2],80);  
		parse_hex("9edc2bc89c70a520e80859eaa6c900eeddf7582db938dc1ca0b19b44f0d08f05000000000000000000000000000000006921dc356b8d52dd1ff59424ff2948cbddf7582db938dc1ca0b19b44f0d08f05",prefix_list[3],80);  
		parse_hex("9b0dfd1815792bc9d3db20b186800e100a3820ec9586399d90286c644709d6ae000000000000000000000000000000006cf00ae5e284dc342426ed7e3179b0be0a3820ec9586399d90286c644709d6ae",prefix_list[4],80);  
		parse_hex("d4a358ec6ad3b8949151b3ff8e0c1444b65d3b15a6b3ebe26280b09d05b6b6ec00000000000000000000000000000000235eaf119d2e4f6966ac7ed54a1fe251b65d3b15a6b3ebe26280b09d05b6b6ec",prefix_list[5],80);  
		parse_hex("06ea7733ad08bfb9242cacde13dda7bcb7cce9f1ef3dc94d03586620c2d9cfe300000000000000000000000000000000f11780ce5af54844d3d198f688af5ae4b7cce9f1ef3dc94d03586620c2d9cfe3",prefix_list[6],80);  
		parse_hex("ad50f2e23220b10608f99c484adc79e2b0a0d8fab929bc6443a2c47ad0f3930e000000000000000000000000000000005aad051fc5dd46fbfffca962fd97a6a5b0a0d8fab929bc6443a2c47ad0f3930e",prefix_list[7],80);  
		parse_hex("4ba98dea5161bcf96ab5b7cb22d10a4b5f09d312fff77f956faa58de751dd7c200000000000000000000000000000000bc547a17a69c4b046abf8defce4004295f09d312fff77f956faa58de751dd7c2",prefix_list[8],80);  
		parse_hex("7a3b9cb77752e0001c06a0039fc03db9ea9e570fd49a9b60d7b61cf6b5e88807000000000000000000000000000000008dc66b4a80af170b1d0d9b212e218798ea9e570fd49a9b60d7b61cf6b5e88807",prefix_list[9],80);  
		parse_hex("840dc11b97b41902324baafb6473217aeca2f8ab35cd010ac569c122e1e12c140000000000000000000000000000000073f036e660491b0a304392dbbbd65e58eca2f8ab35cd010ac569c122e1e12c14",prefix_list[10],80);  
		parse_hex("8353a86dc74ae1c971840445faf2dbccbc406e088699d2172ca716cd0e26fa250000000000000000000000000000000074ae5f903043e2c0728d3d671a983439bc406e088699d2172ca716cd0e26fa25",prefix_list[11],80);  
		parse_hex("885ddaca3619c108455f32f5db152af3a19ca01e3f9de1983e8091a7d7ca403d000000000000000000000000000000007fa02d373217c50641510cd1d89187a9a19ca01e3f9de1983e8091a7d7ca403d",prefix_list[12],80);  
		parse_hex("3fc7bec7ed8b70e86cb56e4e5bf5e3f24eb0da440fee822cc25fab4f6dd8e7a700000000000000000000000000000000c83a49c8e88475e769ba5164b1b5da1b4eb0da440fee822cc25fab4f6dd8e7a7",prefix_list[13],80);  
		parse_hex("a303864d24ca6720ff295215c4cba5ae20054484d638692c66fa9c8dea76fbb90000000000000000000000000000000054fe804122c6612cf9256e3d4219b14020054484d638692c66fa9c8dea76fbb9",prefix_list[14],80);  
		parse_hex("4ed26dca380a4f5c0c333a650f666630cc4c8f95cc8ada064db8b28da6297cc200000000000000000000000000000000b9df6ac73f0748510b3e074fecdf472acc4c8f95cc8ada064db8b28da6297cc2",prefix_list[15],80);  
		parse_hex("2685fc2c0daa2b5a89e4abfc7ba84f0e6e8ab31a53aad850e4de3ff8c67a34e0000000000000000000000000000000003e97e43e15b8334891f689c888b0743e6e8ab31a53aad850e4de3ff8c67a34e0",prefix_list[16],80);  
	} else if (strcmp(username,"Charlotte") == 0) {  
		parse_hex("eeead7dcb7f51d2f8c47d659e05c39edbaacf5b323b49971290c4a8e9138931300000000000000000000000000000000191720214008ead27bba1b95ba152a22baacf5b323b49971290c4a8e91389313",prefix_list[1],80);  
		parse_hex("7f8cc0f9f903bd350fbc273a2e2fce99d873b0c9027e4c6351064d6a1814623c00000000000000000000000000000000887137040efe4ac8f841eaf7f6d833f5d873b0c9027e4c6351064d6a1814623c",prefix_list[2],80);  
		parse_hex("bce6a19bcf66b7e354586f8bf95d23f94434a437657e192164c5f55cedb044df000000000000000000000000000000004b1b5666389b401ea3a5a2450fbe8c064434a437657e192164c5f55cedb044df",prefix_list[3],80);  
		parse_hex("75695d30b7546c02a762332606a25331d26462a0cf3b9a4430019765b53f2419000000000000000000000000000000008294aacd40a99bff509ffee9158d11d0d26462a0cf3b9a4430019765b53f2419",prefix_list[4],80);  
		parse_hex("66146f8f122e8409cfcc98f279ce453d59478301b2409e86c6fda613ad064ea40000000000000000000000000000000091e99872e5d373f4383155d883d0a37059478301b2409e86c6fda613ad064ea4",prefix_list[5],80);  
		parse_hex("bbebe46042c749337a9deacb44466b613beb7cbf2ca9d8cb5b8cef023a531177000000000000000000000000000000004c16139db53abece8d60dee3309d99db3beb7cbf2ca9d8cb5b8cef023a531177",prefix_list[6],80);  
		parse_hex("ab1aa94c3782d508a11d40217e35a24ed04bed5926ec851cc5a825ef03c6d804000000000000000000000000000000005ce75eb1c07f22f55618750b19daa3cbd04bed5926ec851cc5a825ef03c6d804",prefix_list[7],80);  
		parse_hex("f25a72d669b69fe589950eea594e837fa3df38e61dd7b35c0793362b912aadf30000000000000000000000000000000005a7852b9e4b6818899f34ce6685c205a3df38e61dd7b35c0793362b912aadf3",prefix_list[8],80);  
		parse_hex("221568749982effaba1d63ac20e358041740c5bd1edf2e82cb7d7659f1f76e5600000000000000000000000000000000d5e89f896e7f18f1bb16588e44c621241740c5bd1edf2e82cb7d7659f1f76e56",prefix_list[9],80);  
		parse_hex("eb4aef815e0ee53501c7c7bad5ff5301b41ea78c198587eaf8bd5460a704d3ca000000000000000000000000000000001cb7187ca9f3e73d03cfff9ab7416e20b41ea78c198587eaf8bd5460a704d3ca",prefix_list[10],80);  
		parse_hex("e627a4547be3064f504e1f77704b1456ed44a338c0b805964155ae1b2589cf4d0000000000000000000000000000000011da53a98cea0546534726552b20fde7ed44a338c0b805964155ae1b2589cf4d",prefix_list[11],80);  
		parse_hex("993747412f29a60b0f26417e379e719cdc4d76cc16378cf59f9d1ef0d9a8d5fc000000000000000000000000000000006ecab0bc2b27a2050b287f5aff8593d8dc4d76cc16378cf59f9d1ef0d9a8d5fc",prefix_list[12],80);  
		parse_hex("2fbe51c09e3a32b3e1da4f779dbb92706f41087b17caa75f22be5e8c6c115ffe00000000000000000000000000000000d843a6cf9b3537bce4d5705d7fc0de6a6f41087b17caa75f22be5e8c6c115ffe",prefix_list[13],80);  
		parse_hex("f3896a69846bdf6f46605757c3106cf31299ad47da107f85baa9adc743b5bb8c0000000000000000000000000000000004746c658267d963406c6b7f1df295f21299ad47da107f85baa9adc743b5bb8c",prefix_list[14],80);  
		parse_hex("7346bb851583490b68690c95e54eb039a7d9c954d036527b987369de69e5d8df00000000000000000000000000000000844bbc88128e4e066f6431bf2d8df759a7d9c954d036527b987369de69e5d8df",prefix_list[15],80);  
		parse_hex("fbac7b9598b52e9e434a5f2ee9b41247ee90b98ee280926f1bdc7454fd8fe26c00000000000000000000000000000000e3be638780a7368c5b587d1a7e2ae1a5ee90b98ee280926f1bdc7454fd8fe26c",prefix_list[16],80);  
	} else if (strcmp(username,"TheRealSanta") == 0) {  
		parse_hex("12d20512fb298dafd831b1285c59890dd2540cb17d1a96b6ab4fea7c40a5e10700000000000000000000000000000000e52ff2ef0cd47a522fcc7ce41f1209f3d2540cb17d1a96b6ab4fea7c40a5e107",prefix_list[1],80);  
		parse_hex("3951099d848a612c574eba5ba3cb7402fe42402c2092a7dbf5d42733c8810b4100000000000000000000000000000000ceacfe60737796d1a0b37796f5e8b5d8fe42402c2092a7dbf5d42733c8810b41",prefix_list[2],80);  
		parse_hex("97b7daa2e5ad5bf81ef968d6b9dfc2a961875440e8d836cf67aea3619b949b4a00000000000000000000000000000000604a2d5f1250ac05e904a5180c6f6e1861875440e8d836cf67aea3619b949b4a",prefix_list[3],80);  
		parse_hex("bcf4f855acb4e77b89e734b0f692308ee03a365aef6a7885307a886473335053000000000000000000000000000000004b090fa85b4910867e1af97f3a41e216e03a365aef6a7885307a886473335053",prefix_list[4],80);  
		parse_hex("ee50ef7303731f00374edb5d624482c90b55b622d440a8a48d989d53dcb308ae0000000000000000000000000000000019ad188ef48ee8fdc0b31677a9e577420b55b622d440a8a48d989d53dcb308ae",prefix_list[5],80);  
		parse_hex("8626cc3145530c53c4dbe3966df1396fb98e53c56a76bbb71460f37666eff3dc0000000000000000000000000000000071db3bccb2aefbae3326d7befa9c607fb98e53c56a76bbb71460f37666eff3dc",prefix_list[6],80);  
		parse_hex("b9f24b2169bea3d70500627eafb2a51e70032400b5600f5cb329e8d3a7d99ad0000000000000000000000000000000004e0fbcdc9e43542af2055754f2e0476770032400b5600f5cb329e8d3a7d99ad0",prefix_list[7],80);  
		parse_hex("56f4d0a2caa8d1022d1ab5de1af79105950bbeec3d4550cc2ce1179f6ecdac7100000000000000000000000000000000a109275f3d5526ff2d108ffa017fdaa7950bbeec3d4550cc2ce1179f6ecdac71",prefix_list[8],80);  
		parse_hex("271ea7eca4e5604df45c4ebcf5bae190d3877e34fde23c76819f1513cbc9059700000000000000000000000000000000d0e3501153189746f557759e8ad8bff4d3877e34fde23c76819f1513cbc90597",prefix_list[9],80);  
		parse_hex("3bb514c1d17b22c1887cd8e91fdfd3ee8a227cb8b1419610204241eb13cb957900000000000000000000000000000000cc48e33c268620c98a74e0c98e1140988a227cb8b1419610204241eb13cb9579",prefix_list[10],80);  
		parse_hex("8138e0158c3a1725c7f614a4b326a5431f620e255e28183c29f18119f783e5550000000000000000000000000000000076c517e87b33142cc4ff2d8626abed771f620e255e28183c29f18119f783e555",prefix_list[11],80);  
		parse_hex("090a973c432f707224a6dadce78122b5d1afbb39f6cd32a5deffaa15a18d639100000000000000000000000000000000fef760c14721747c20a8e4f85c7b9c05d1afbb39f6cd32a5deffaa15a18d6391",prefix_list[12],80);  
		parse_hex("bef79fd20c2bfd586ee2f12f3a1c84b30531c5c53ad1cea79676601bde69916200000000000000000000000000000000490a68dd0924f8576bedce0533a537a80531c5c53ad1cea79676601bde699162",prefix_list[13],80);  
		parse_hex("552a14290319dfd191c26497ef809b7c5f5d260cded8813a87ace6ac6334ec0300000000000000000000000000000000a2d712250515d9dd97ce58bf911ca91d5f5d260cded8813a87ace6ac6334ec03",prefix_list[14],80);  
		parse_hex("d79b4679fae87d6a5b246d9c181c9787c342e82824807acf1dbbf124aa2579440000000000000000000000000000000020964174fde57a675c2950b6a8b7ccdec342e82824807acf1dbbf124aa257944",prefix_list[15],80);  
		parse_hex("eff0df07b643edd8a99942e85496d93f1c3beb8958fb775e43c04a5e6512062500000000000000000000000000000000f7e2c715ae51f5cab18b60dcafe854581c3beb8958fb775e43c04a5e65120625",prefix_list[16],80);  
	} else if (strcmp(username,"Jessica") == 0) {  
		parse_hex("bc03874d6724f1272144ccdac48c36b54460c879143fb9bed078d15a11b1fd86000000000000000000000000000000004bfe70b090d906dad6b901167d269b664460c879143fb9bed078d15a11b1fd86",prefix_list[1],80);  
		parse_hex("02084d8fab5a7510d9f9b3af78efd3c77826f9dcd448cd5537604a5030ed200200000000000000000000000000000000f5f5ba725ca782ed2e047e62e94967797826f9dcd448cd5537604a5030ed2002",prefix_list[2],80);  
		parse_hex("b5fff0ee6e64c943509d8182e4718c138089f492a49bd769a48c562cfb392583000000000000000000000000000000004202071399993ebea7604c4c99964f4f8089f492a49bd769a48c562cfb392583",prefix_list[3],80);  
		parse_hex("de7038756193d729710bde8c7cea48ad9b9e0196b4d404c9fa871e193a5e8c2500000000000000000000000000000000298dcf88966e20d486f613433d0c14b09b9e0196b4d404c9fa871e193a5e8c25",prefix_list[4],80);  
		parse_hex("8876817f0991f02f81f4c6a11b186c5c17cf13b9b1b0c26fc0a1b60cc47e7cf7000000000000000000000000000000007f8b7682fe6c07d276090b8b0fb60d5517cf13b9b1b0c26fc0a1b60cc47e7cf7",prefix_list[5],80);  
		parse_hex("aea3e449490dbd2bfacfd2511c882e603deb2e6c9039e7b9ee6d7ee43b1c2a1a00000000000000000000000000000000595e13b4bef04ad60d32e679bb3453cf3deb2e6c9039e7b9ee6d7ee43b1c2a1a",prefix_list[6],80);  
		parse_hex("f90a0e9eb6efc196f5229ef18744fa0e322d4b035d0323bf790a8e15ecd41b91000000000000000000000000000000000ef7f9634112366b0227abdb4bb8856f322d4b035d0323bf790a8e15ecd41b91",prefix_list[7],80);  
		parse_hex("a40491369be295acf86f366eeb8d92e448b3d0a29fa036212e49bfba9789639b0000000000000000000000000000000053f966cb6c1f6251f8650c4a6492a06048b3d0a29fa036212e49bfba9789639b",prefix_list[8],80);  
		parse_hex("e08ed53b6c52c2cf739d81cd0209afe406e3187953fa9dc4043a1daf99d4c47400000000000000000000000000000000177322c69baf35c47296baefd2b109f206e3187953fa9dc4043a1daf99d4c474",prefix_list[9],80);  
		parse_hex("5c3a3956e6bb52a69d6c594ebb1b9437668609f02a6307884a3cbb9df2e518da00000000000000000000000000000000abc7ceab114650ae9f64616eb09d86a0668609f02a6307884a3cbb9df2e518da",prefix_list[10],80);  
		parse_hex("78d838757516eed5d6b4b3638825ab564669f4c3878f099f50820b5d4af394fe000000000000000000000000000000008f25cf88821feddcd5bd8a4164e065034669f4c3878f099f50820b5d4af394fe",prefix_list[11],80);  
		parse_hex("f5fcf3e1b5602d31cc45d96a2904e6ad18731d77e4aad3d6868024727bae83af000000000000000000000000000000000201041cb16e293fc84be74e420e573a18731d77e4aad3d6868024727bae83af",prefix_list[12],80);  
		parse_hex("e9098d6ef807675464e1860c662a580732d64c3c44453735098aecffbecbc243000000000000000000000000000000001ef47a61fd08625b61eeb926eb7f02ee32d64c3c44453735098aecffbecbc243",prefix_list[13],80);  
		parse_hex("dcc5da29605f161fe3f1cb9d944973b2d3f51a68a6397d70040fe53c03effe72000000000000000000000000000000002b38dc2566531013e5fdf7b5476d9e2dd3f51a68a6397d70040fe53c03effe72",prefix_list[14],80);  
		parse_hex("b37f42ee33b00b5b311a98d6a3a3ffb165f62306ace5dbbd93265538f7b1baf000000000000000000000000000000000447245e334bd0c563617a5fce4c7e72065f62306ace5dbbd93265538f7b1baf0",prefix_list[15],80);  
		parse_hex("3de70c3647467bf725eae82a25fe16b83c3a6920aeab7100d8962ef319ca3d600000000000000000000000000000000025f514245f5463e53df8ca1e77ca3a4b3c3a6920aeab7100d8962ef319ca3d60",prefix_list[16],80);  
	}

	return prefix_list[npad];  
}

int sha_matches(uint8_t *data, int size)  
{  
	SHA256_CTX c;  
	uint8_t md[32];

	SHA256_Init(&c);  
	SHA256_Update(&c,data,size);  
	SHA256_Final(md,&c);

	return md[0]==0x12 && md[1]==0x06;  
}

void padding_oracle_prefix(uint8_t *ciphertext, uint8_t *guess_plaintext, char
*username, int max_npad)  
{  
	int npad;  
	int byteval;  
	uint8_t new_ciphertext[80];  
	int i;  
	int seed;  
	int ocd_found = 0;  
	uint8_t request[200];  
	int request_size = 0;  
	int n;

	for (npad=1; npad <= max_npad; npad++) {  
		uint8_t *prefix = get_prefix(username, npad);  
		for (byteval=0; byteval<256; byteval++) {  
			memcpy(new_ciphertext,prefix,48);  
			memcpy(new_ciphertext+48,ciphertext,32);  
			for (i=0; i<16; i++) {  
				new_ciphertext[48+i] ^= guess_plaintext[i];  
			}  
			for (i=0; i<npad; i++) {  
				new_ciphertext[48+15-i] ^= npad;  
			}  
			new_ciphertext[48+16-npad] ^= byteval;  
			seed = 0;  
			ocd_found = 0;  
			while (!ocd_found) {  
				srandom(seed);  
				seed++;  
				new_ciphertext[32] = (uint8_t)(random()&0xff);  
				new_ciphertext[33] = (uint8_t)(random()&0xff);  
				new_ciphertext[34] = (uint8_t)(random()&0xff);  
				new_ciphertext[35] = (uint8_t)(random()&0xff);

				request_size = 0;  
				//   
				request[request_size] = 0x0a; request_size++;  
				request[request_size] = strlen(username); request_size++;  
				strcpy((char*)&request[request_size],username); request_size += strlen(username);  
				request[request_size] = 0x10; request_size++;  
				request[request_size] = 0x01; request_size++;  
				request[request_size] = 0x1a; request_size++;  
				request[request_size] = 80; request_size++;  
				memcpy(&request[request_size],new_ciphertext,80); request_size += 80;

				ocd_found = sha_matches(request,request_size);  
			}  
			n = send_and_recv(request,request_size);  
			if (n > 0) {  
				uint8_t v = ciphertext[16-npad] ^ new_ciphertext[80-16-npad] ^ npad;  
				//printf("Possible byte found [%d]: %02x %c -- %d\n", npad, v, v, n);  
				guess_plaintext[16-npad] = v;  
				print_plaintext(guess_plaintext);  
				break;  
			}  
			//printf("not found byte [%d]: %02x -- %d\n", npad, ciphertext[16-npad] ^ new_ciphertext[80-16-npad] ^ npad, n);  
		}  
	}  
}

void get_oracle_prefix(char *username, int npad)  
{  
	int byteval;  
	uint8_t new_ciphertext[80];  
	int i;  
	int seed;  
	int ocd_found = 0;  
	uint8_t request[200];  
	int request_size = 0;  
	int n;

	//res = send_and_recv(sock,create_request(username,udpsanta_pb2.SENDMSG)) # 0x10 pad  
	seed = 0;  
	ocd_found = 0;  
	while (!ocd_found) {  
		srandom(seed);  
		seed++;

		request_size = 0;  
		request[request_size] = 0x0a; request_size++;  
		request[request_size] = strlen(username); request_size++;  
		strcpy((char*)&request[request_size],username); request_size += strlen(username);  
		request[request_size] = 0x1a; request_size++;  
		request[request_size] = 8; request_size++;  
		request[request_size] = 0x08; request_size++;  
		request[request_size] = 0x01; request_size++;  
		request[request_size] = 0x32; request_size++;  
		request[request_size] = 0x04; request_size++;  
		request[request_size] = (uint8_t)(random()&0xff); request_size++;  
		request[request_size] = (uint8_t)(random()&0xff); request_size++;  
		request[request_size] = (uint8_t)(random()&0xff); request_size++;  
		request[request_size] = (uint8_t)(random()&0xff); request_size++;

		ocd_found = sha_matches(request,request_size);  
	}

	n = send_and_recv(request,request_size);  
	//printf("got all 0x10 pad (n=%d)\n", n);

	memset(new_ciphertext,0,sizeof(new_ciphertext));  
	memcpy(&new_ciphertext[0],&RECV_BUFFER[n-32],32);  
	memcpy(&new_ciphertext[48],&RECV_BUFFER[n-32],32);  
	new_ciphertext[0] ^= 0x10 ^ 0x08;  
	new_ciphertext[1] ^= 0x10 ^ 0x02;  
	new_ciphertext[2] ^= 0x10 ^ 0x08;  
	new_ciphertext[3] ^= 0x10 ^ 0x02;  
	new_ciphertext[4] ^= 0x10 ^ 0x08;  
	new_ciphertext[5] ^= 0x10 ^ 0x02;  
	new_ciphertext[6] ^= 0x10 ^ 0x08;  
	new_ciphertext[7] ^= 0x10 ^ 0x02;  
	new_ciphertext[8] ^= 0x10 ^ 0x08;  
	new_ciphertext[9] ^= 0x10 ^ 0x02;  
	new_ciphertext[10] ^= 0x10 ^ '2';  
	new_ciphertext[11] ^= 0x10 ^ (4+32+16-npad);  
	for (i=48; i<64-npad; i++)  
		new_ciphertext[i] ^= 0x10 ^ 0xff;  
	for (i=64-npad; i<64; i++)  
		new_ciphertext[i] ^= 0x10 ^ npad;  
	while (1) {  
		ocd_found = 0;  
		while (!ocd_found) {  
			srandom(seed);  
			seed++;  
			new_ciphertext[12] = (uint8_t)(random()&0xff);  
			new_ciphertext[13] = (uint8_t)(random()&0xff);  
			new_ciphertext[14] = (uint8_t)(random()&0xff);  
			new_ciphertext[15] = (uint8_t)(random()&0xff);

			request_size = 0;  
			request[request_size] = 0x0a; request_size++;  
			request[request_size] = strlen(username); request_size++;  
			strcpy((char*)&request[request_size],username); request_size += strlen(username);  
			request[request_size] = 0x10; request_size++;  
			request[request_size] = 0x01; request_size++;  
			request[request_size] = 0x1a; request_size++;  
			request[request_size] = 80; request_size++;  
			memcpy(&request[request_size],new_ciphertext,80); request_size += 80;

			ocd_found = sha_matches(request,request_size);  
		}

		n = send_and_recv(request,request_size);  
		if (n > 0) {  
			//printf("Found oracle prefix:\n");

			//printf("prefix_lookup['%s','%s',%d] = b'", SERVER_NAME, username, npad);  
			//for (i=0; i<80; i++)  
			//	printf("%02x", new_ciphertext[i]);  
			//printf("'\n");

			printf("parse_hex(\"");  
			for (i=0; i<80; i++)  
				printf("%02x", new_ciphertext[i]);  
			printf("\",prefix_list[%d],80);\n", npad);

			return;  
		}  
	}  
}

int main(int argc, char **argv)  
{  
	uint8_t ciphertext[32];  
	uint8_t plaintext[16];  
	char *username = "Timmy";  
	int i;

	//for (i=1;i<=16;i++)  
	//	get_oracle_prefix("Timmy",i);  
	//return 0;

	memset(ciphertext,0,sizeof(ciphertext));  
	memset(plaintext,0,sizeof(plaintext));

	if (argc <= 1) {  
		printf("missing arg[1]\n");  
		return 0;  
	}  
	if (argc >= 2) {  
		parse_hex(argv[1],ciphertext,32);  
	}  
	if (argc >= 3) {  
		parse_hex(argv[2],plaintext,16);  
	}  
	if (argc >= 4) {  
		username = argv[3];  
	}

	if (0) {  
		printf("ciphertext: ");  
		for (i=0; i<32; i++)  
			printf("%02x", ciphertext[i]);  
		printf("\n");  
		printf("plaintext:  ");  
		for (i=0; i<16; i++)  
			printf("%02x", plaintext[i]);  
		printf("\n");  
	}

	padding_oracle_prefix(ciphertext, plaintext, username, 16);

	return 0;  
}  
```

## Decrypting Data

Finally we get to the part where we decrypt data. First, we choose a user
(lets start with `Timmy`), list all of the messages sent to timmy via the
LISTMSGS command, then get the contents for each of those messages via the
GETMSG command. Unfortunately, we don't know what the IV is for a particular
user so we'll have to solve that first. Luckily the server responds with a
pretty formulaic error message under various conditions so sending a message
we know will return an error and decrypting the first block of the result will
give us a close approximation to the IV bytes. Then, with this its "quick"
work to list all messages for a user and then get each message. Some python
code to do that for "Timmy" is given below.

```python  
def xor_bytes(a,b):  
	return bytes([a[i]^b[i] for i in range(16)])

def create_request(_from,cmd,arg1=None,arg2=None,arg2num=None):

	pad = 0  
	ocd_found = False  
	while not ocd_found:  
		reqi = udpsanta_pb2.RequestInner()  
		reqi.cmd = cmd  
		if arg1 is not None:  
			reqi.arg1 = arg1  
		if arg2 is not None:  
			reqi.arg2 = arg2  
		if arg2num is not None:  
			reqi.arg2num = arg2num  
		reqi.timestamp = int(time.time())  
		random.seed(pad)  
		reqi.padding = bytes([ord(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')) for i in range(19)]+[0])

		req = udpsanta_pb2.Request()  
		req._from = _from  
		req.innerRequest = reqi.SerializeToString()

		req_data = req.SerializeToString()  
		ocd_found = sha_matches(req_data)  
		pad += 1

	return req_data

def res_to_resi(packet):  
	res = udpsanta_pb2.Response()  
	res.ParseFromString(packet)  
	return res.innerResponse

def solve_iv(username='Timmy'):  
	print('Solve IV:', username)  
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
	sock.settimeout(2)  
	req = create_request(username,udpsanta_pb2.LISTMSGS)  
	res = send_and_recv(sock,req)  
	resi = res_to_resi(res)  
	cipher = binascii.hexlify(b'\x08\x04\x10\x94\xf1\xf5\xe0\x05\x1a\x13Invali'+resi[:16]).decode('ascii')  
	plain = '0'*32  
	subprocess.Popen(['./challenge6',cipher,plain,username]).wait()

def padding_oracle(username,cipher,solved_iv):  
	_cipher = binascii.hexlify(solved_iv+cipher[0:16]).decode('ascii')  
	plain = '0'*32  
	subprocess.Popen(['./challenge6',_cipher,plain,username]).wait()  
	for offset in range(0,len(cipher)-16,16):  
		_cipher = binascii.hexlify(cipher[offset:offset+32]).decode('ascii')  
		subprocess.Popen(['./challenge6',_cipher,plain,username]).wait()

def solve_list_messages(username,solved_iv,num=3):  
	print('List Messages', username)  
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
	sock.settimeout(2)  
	res = send_and_recv(sock,create_request(username,udpsanta_pb2.LISTMSGS,arg2num=num))  
	padding_oracle(username,res_to_resi(res),solved_iv)

def solve_get_message(username,solved_iv,msgid):  
	print('Get Message',username,msgid)  
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
	sock.settimeout(2)  
	res = send_and_recv(sock,create_request(username,udpsanta_pb2.GETMSG,arg2num=msgid))  
	padding_oracle(username,res_to_resi(res),solved_iv)

if __name__ == '__main__':

	# run once, get the IV, then copy/paste here  
	solve_iv('Timmy')  
	solved_iv = binascii.unhexlify('92c4c8941bb410e588759a14ab96be1e') XXX TODO FIXME

	# run to get the lst of messages, copy/paste each message id here  
	solve_list_messages('Timmy',solved_iv)

	# run a third time to decrypt a message  
	solve_get_message('Timmy',solved_iv,0x6065)  
```

And some output

```  
$ ./challenge6.py  
Solve IV: Timmy  
plaintext: 00000000000000000000000000000057  ...............W  
plaintext: 00000000000000000000000000006257  ..............bW  
plaintext: 00000000000000000000000000316257  .............1bW  
plaintext: 00000000000000000000000037316257  ............71bW  
plaintext: 00000000000000000000006837316257  ...........h71bW  
plaintext: 00000000000000000000646837316257  ..........dh71bW  
plaintext: 00000000000000000071646837316257  .........qdh71bW  
plaintext: 00000000000000005171646837316257  ........Qqdh71bW  
plaintext: 00000000000000355171646837316257  .......5Qqdh71bW  
plaintext: 00000000000069355171646837316257  ......i5Qqdh71bW  
plaintext: 00000000003469355171646837316257  .....4i5Qqdh71bW  
plaintext: 000000006c3469355171646837316257  ....l4i5Qqdh71bW  
plaintext: 000000006c3469355171646837316257  ....l4i5Qqdh71bW  
plaintext: 000045006c3469355171646837316257  ..E.l4i5Qqdh71bW  
plaintext: 004145006c3469355171646837316257  .AE.l4i5Qqdh71bW  
plaintext: 674145006c3469355171646837316257  gAE.l4i5Qqdh71bW  
$ ./challenge6.py  
List Messages Timmy  
plaintext: 00000000000000000000000000000000  ................  
plaintext: 00000000000000000000000000000000  ................  
plaintext: 00000000000000000000000000600000  .............`..  
plaintext: 00000000000000000000000065600000  ............e`..  
plaintext: 00000000000000000000000c65600000  ............e`..  
plaintext: 00000000000000000000320c65600000  ..........2.e`..  
plaintext: 00000000000000000000320c65600000  ..........2.e`..  
plaintext: 00000000000000002800320c65600000  ........(.2.e`..  
plaintext: 00000000000000052800320c65600000  ........(.2.e`..  
plaintext: 000000000000e0052800320c65600000  ........(.2.e`..  
plaintext: 0000000000f5e0052800320c65600000  ........(.2.e`..  
plaintext: 00000000e2f5e0052800320c65600000  ........(.2.e`..  
plaintext: 0000008de2f5e0052800320c65600000  ........(.2.e`..  
plaintext: 0000108de2f5e0052800320c65600000  ........(.2.e`..  
plaintext: 0002108de2f5e0052800320c65600000  ........(.2.e`..  
plaintext: 0802108de2f5e0052800320c65600000  ........(.2.e`..  
plaintext: 00000000000000000000000000000042  ...............B  
plaintext: 00000000000000000000000000003142  ..............1B  
plaintext: 00000000000000000000000000493142  .............I1B  
plaintext: 0000000000000000000000007a493142  ............zI1B  
plaintext: 0000000000000000000000577a493142  ...........WzI1B  
plaintext: 0000000000000000000062577a493142  ..........bWzI1B  
plaintext: 0000000000000000001462577a493142  ..........bWzI1B  
plaintext: 00000000000000003a1462577a493142  ........:.bWzI1B  
plaintext: 00000000000000ff3a1462577a493142  ........:.bWzI1B  
plaintext: 000000000000ffff3a1462577a493142  ........:.bWzI1B  
plaintext: 0000000000ffffff3a1462577a493142  ........:.bWzI1B  
plaintext: 00000000ffffffff3a1462577a493142  ........:.bWzI1B  
plaintext: 000000ffffffffff3a1462577a493142  ........:.bWzI1B  
plaintext: 0000ffffffffffff3a1462577a493142  ........:.bWzI1B  
plaintext: 00ffffffffffffff3a1462577a493142  ........:.bWzI1B  
plaintext: ffffffffffffffff3a1462577a493142  ........:.bWzI1B  
plaintext: 00000000000000000000000000000002  ................  
plaintext: 00000000000000000000000000000202  ................  
plaintext: 00000000000000000000000000000202  ................  
plaintext: 0000000000000000000000004d000202  ............M...  
plaintext: 0000000000000000000000504d000202  ...........PM...  
plaintext: 000000000000000000004e504d000202  ..........NPM...  
plaintext: 000000000000000000704e504d000202  .........pNPM...  
plaintext: 000000000000000050704e504d000202  ........PpNPM...  
plaintext: 000000000000004e50704e504d000202  .......NPpNPM...  
plaintext: 000000000000554e50704e504d000202  ......UNPpNPM...  
plaintext: 00000000005a554e50704e504d000202  .....ZUNPpNPM...  
plaintext: 00000000685a554e50704e504d000202  ....hZUNPpNPM...  
plaintext: 00000064685a554e50704e504d000202  ...dhZUNPpNPM...  
plaintext: 00004164685a554e50704e504d000202  ..AdhZUNPpNPM...  
plaintext: 00744164685a554e50704e504d000202  .tAdhZUNPpNPM...  
plaintext: 6e744164685a554e50704e504d000202  ntAdhZUNPpNPM...  
$ ./challenge6.py  
Get Message Timmy 24677 0x6065  
plaintext: 00000000000000000000000000000061  ...............a  
plaintext: 00000000000000000000000000006561  ..............ea  
plaintext: 00000000000000000000000000526561  .............Rea  
plaintext: 00000000000000000000000065526561  ............eRea  
plaintext: 00000000000000000000006865526561  ...........heRea  
plaintext: 00000000000000000000546865526561  ..........TheRea  
plaintext: 0000000000000000000c546865526561  ..........TheRea  
plaintext: 00000000000000001a0c546865526561  ..........TheRea  
plaintext: 00000000000000051a0c546865526561  ..........TheRea  
plaintext: 000000000000e0051a0c546865526561  ..........TheRea  
plaintext: 000000000080e0051a0c546865526561  ..........TheRea  
plaintext: 00000000cc80e0051a0c546865526561  ..........TheRea  
plaintext: 000000b1cc80e0051a0c546865526561  ..........TheRea  
plaintext: 000010b1cc80e0051a0c546865526561  ..........TheRea  
plaintext: 000310b1cc80e0051a0c546865526561  ..........TheRea  
plaintext: 080310b1cc80e0051a0c546865526561  ..........TheRea  
plaintext: 00000000000000000000000000000074  ...............t  
plaintext: 00000000000000000000000000002074  .............. t  
plaintext: 000000000000000000000000006f2074  .............o t  
plaintext: 0000000000000000000000006c6f2074  ............lo t  
plaintext: 00000000000000000000006c6c6f2074  ...........llo t  
plaintext: 00000000000000000000656c6c6f2074  ..........ello t  
plaintext: 00000000000000000048656c6c6f2074  .........Hello t  
plaintext: 00000000000000000248656c6c6f2074  .........Hello t  
plaintext: 00000000000000d00248656c6c6f2074  .........Hello t  
plaintext: 00000000000022d00248656c6c6f2074  ......"..Hello t  
plaintext: 00000000006122d00248656c6c6f2074  .....a"..Hello t  
plaintext: 00000000746122d00248656c6c6f2074  ....ta"..Hello t  
plaintext: 0000006e746122d00248656c6c6f2074  ...nta"..Hello t  
plaintext: 0000616e746122d00248656c6c6f2074  ..anta"..Hello t  
plaintext: 0053616e746122d00248656c6c6f2074  .Santa"..Hello t  
plaintext: 6c53616e746122d00248656c6c6f2074  lSanta"..Hello t  
plaintext: 00000000000000000000000000000073  ...............s  
plaintext: 00000000000000000000000000002073  .............. s  
plaintext: 00000000000000000000000000492073  .............I s  
plaintext: 0000000000000000000000000a492073  .............I s  
plaintext: 00000000000000000000000a0a492073  .............I s  
plaintext: 000000000000000000002c0a0a492073  ..........,..I s  
plaintext: 000000000000000000792c0a0a492073  .........y,..I s  
plaintext: 00000000000000006d792c0a0a492073  ........my,..I s  
plaintext: 000000000000006d6d792c0a0a492073  .......mmy,..I s  
plaintext: 000000000000696d6d792c0a0a492073  ......immy,..I s  
plaintext: 000000000054696d6d792c0a0a492073  .....Timmy,..I s  
plaintext: 000000002054696d6d792c0a0a492073  .... Timmy,..I s  
plaintext: 000000652054696d6d792c0a0a492073  ...e Timmy,..I s  
plaintext: 000072652054696d6d792c0a0a492073  ..re Timmy,..I s  
plaintext: 006572652054696d6d792c0a0a492073  .ere Timmy,..I s  
plaintext: 686572652054696d6d792c0a0a492073  here Timmy,..I s  
plaintext: 00000000000000000000000000000068  ...............h  
plaintext: 00000000000000000000000000007468  ..............th  
plaintext: 00000000000000000000000000207468  ............. th  
plaintext: 0000000000000000000000006b207468  ............k th  
plaintext: 00000000000000000000006f6b207468  ...........ok th  
plaintext: 000000000000000000006f6f6b207468  ..........ook th  
plaintext: 000000000000000000626f6f6b207468  .........book th  
plaintext: 000000000000000020626f6f6b207468  ........ book th  
plaintext: 000000000000007920626f6f6b207468  .......y book th  
plaintext: 0000000000006d7920626f6f6b207468  ......my book th  
plaintext: 0000000000206d7920626f6f6b207468  ..... my book th  
plaintext: 000000006e206d7920626f6f6b207468  ....n my book th  
plaintext: 000000696e206d7920626f6f6b207468  ...in my book th  
plaintext: 000020696e206d7920626f6f6b207468  .. in my book th  
plaintext: 006520696e206d7920626f6f6b207468  .e in my book th  
plaintext: 656520696e206d7920626f6f6b207468  ee in my book th  
plaintext: 00000000000000000000000000000020  ...............  
plaintext: 00000000000000000000000000007420  ..............t  
plaintext: 000000000000000000000000006f7420  .............ot  
plaintext: 0000000000000000000000006e6f7420  ............not  
plaintext: 0000000000000000000000206e6f7420  ........... not  
plaintext: 0000000000000000000065206e6f7420  ..........e not  
plaintext: 0000000000000000007665206e6f7420  .........ve not  
plaintext: 0000000000000000617665206e6f7420  ........ave not  
plaintext: 0000000000000068617665206e6f7420  .......have not  
plaintext: 0000000000002068617665206e6f7420  ...... have not  
plaintext: 0000000000752068617665206e6f7420  .....u have not  
plaintext: 000000006f752068617665206e6f7420  ....ou have not  
plaintext: 000000796f752068617665206e6f7420  ...you have not  
plaintext: 000020796f752068617665206e6f7420  .. you have not  
plaintext: 007420796f752068617665206e6f7420  .t you have not  
plaintext: 617420796f752068617665206e6f7420  at you have not  
plaintext: 00000000000000000000000000000069  ...............i  
plaintext: 00000000000000000000000000006869  ..............hi  
plaintext: 00000000000000000000000000746869  .............thi  
plaintext: 00000000000000000000000020746869  ............ thi  
plaintext: 00000000000000000000007920746869  ...........y thi  
plaintext: 00000000000000000000747920746869  ..........ty thi  
plaintext: 00000000000000000068747920746869  .........hty thi  
plaintext: 00000000000000006768747920746869  ........ghty thi  
plaintext: 00000000000000756768747920746869  .......ughty thi  
plaintext: 00000000000061756768747920746869  ......aughty thi  
plaintext: 00000000006e61756768747920746869  .....naughty thi  
plaintext: 00000000206e61756768747920746869  .... naughty thi  
plaintext: 0000006e206e61756768747920746869  ...n naughty thi  
plaintext: 0000656e206e61756768747920746869  ..en naughty thi  
plaintext: 0065656e206e61756768747920746869  .een naughty thi  
plaintext: 6265656e206e61756768747920746869  been naughty thi  
plaintext: 00000000000000000000000000000020  ...............  
plaintext: 00000000000000000000000000007520  ..............u  
plaintext: 000000000000000000000000006f7520  .............ou  
plaintext: 000000000000000000000000796f7520  ............you  
plaintext: 000000000000000000000020796f7520  ........... you  
plaintext: 000000000000000000006420796f7520  ..........d you  
plaintext: 0000000000000000006e6420796f7520  .........nd you  
plaintext: 0000000000000000616e6420796f7520  ........and you  
plaintext: 000000000000000a616e6420796f7520  ........and you  
plaintext: 0000000000002c0a616e6420796f7520  ......,.and you  
plaintext: 0000000000722c0a616e6420796f7520  .....r,.and you  
plaintext: 0000000061722c0a616e6420796f7520  ....ar,.and you  
plaintext: 0000006561722c0a616e6420796f7520  ...ear,.and you  
plaintext: 0000796561722c0a616e6420796f7520  ..year,.and you  
plaintext: 0020796561722c0a616e6420796f7520  . year,.and you  
plaintext: 7320796561722c0a616e6420796f7520  s year,.and you  
plaintext: 00000000000000000000000000000069  ...............i  
plaintext: 00000000000000000000000000006c69  ..............li  
plaintext: 00000000000000000000000000206c69  ............. li  
plaintext: 00000000000000000000000064206c69  ............d li  
plaintext: 00000000000000000000006c64206c69  ...........ld li  
plaintext: 00000000000000000000756c64206c69  ..........uld li  
plaintext: 0000000000000000006f756c64206c69  .........ould li  
plaintext: 0000000000000000776f756c64206c69  ........would li  
plaintext: 0000000000000020776f756c64206c69  ....... would li  
plaintext: 0000000000007520776f756c64206c69  ......u would li  
plaintext: 00000000006f7520776f756c64206c69  .....ou would li  
plaintext: 00000000796f7520776f756c64206c69  ....you would li  
plaintext: 00000020796f7520776f756c64206c69  ... you would li  
plaintext: 00007920796f7520776f756c64206c69  ..y you would li  
plaintext: 00617920796f7520776f756c64206c69  .ay you would li  
plaintext: 73617920796f7520776f756c64206c69  say you would li  
plaintext: 00000000000000000000000000000020  ...............  
plaintext: 00000000000000000000000000007220  ..............r  
plaintext: 000000000000000000000000006f7220  .............or  
plaintext: 000000000000000000000000666f7220  ............for  
plaintext: 000000000000000000000020666f7220  ........... for  
plaintext: 000000000000000000007420666f7220  ..........t for  
plaintext: 0000000000000000006f7420666f7220  .........ot for  
plaintext: 0000000000000000726f7420666f7220  ........rot for  
plaintext: 0000000000000072726f7420666f7220  .......rrot for  
plaintext: 0000000000006172726f7420666f7220  ......arrot for  
plaintext: 0000000000706172726f7420666f7220  .....parrot for  
plaintext: 0000000020706172726f7420666f7220  .... parrot for  
plaintext: 0000006120706172726f7420666f7220  ...a parrot for  
plaintext: 0000206120706172726f7420666f7220  .. a parrot for  
plaintext: 0065206120706172726f7420666f7220  .e a parrot for  
plaintext: 6b65206120706172726f7420666f7220  ke a parrot for  
plaintext: 0000000000000000000000000000006f  ...............o  
plaintext: 0000000000000000000000000000636f  ..............co  
plaintext: 0000000000000000000000000020636f  ............. co  
plaintext: 0000000000000000000000006620636f  ............f co  
plaintext: 00000000000000000000004f6620636f  ...........Of co  
plaintext: 000000000000000000000a4f6620636f  ...........Of co  
plaintext: 0000000000000000003f0a4f6620636f  .........?.Of co  
plaintext: 0000000000000000733f0a4f6620636f  ........s?.Of co  
plaintext: 0000000000000061733f0a4f6620636f  .......as?.Of co  
plaintext: 0000000000006d61733f0a4f6620636f  ......mas?.Of co  
plaintext: 0000000000746d61733f0a4f6620636f  .....tmas?.Of co  
plaintext: 0000000073746d61733f0a4f6620636f  ....stmas?.Of co  
plaintext: 0000006973746d61733f0a4f6620636f  ...istmas?.Of co  
plaintext: 0000726973746d61733f0a4f6620636f  ..ristmas?.Of co  
plaintext: 0068726973746d61733f0a4f6620636f  .hristmas?.Of co  
plaintext: 4368726973746d61733f0a4f6620636f  Christmas?.Of co  
plaintext: 00000000000000000000000000000020  ...............  
plaintext: 00000000000000000000000000006f20  ..............o  
plaintext: 00000000000000000000000000646f20  .............do  
plaintext: 00000000000000000000000020646f20  ............ do  
plaintext: 00000000000000000000006c20646f20  ...........l do  
plaintext: 000000000000000000006c6c20646f20  ..........ll do  
plaintext: 000000000000000000696c6c20646f20  .........ill do  
plaintext: 000000000000000077696c6c20646f20  ........will do  
plaintext: 000000000000002077696c6c20646f20  ....... will do  
plaintext: 000000000000492077696c6c20646f20  ......I will do  
plaintext: 000000000020492077696c6c20646f20  ..... I will do  
plaintext: 000000002120492077696c6c20646f20  ....! I will do  
plaintext: 000000652120492077696c6c20646f20  ...e! I will do  
plaintext: 000073652120492077696c6c20646f20  ..se! I will do  
plaintext: 007273652120492077696c6c20646f20  .rse! I will do  
plaintext: 757273652120492077696c6c20646f20  urse! I will do  
plaintext: 0000000000000000000000000000006e  ...............n  
plaintext: 0000000000000000000000000000616e  ..............an  
plaintext: 0000000000000000000000000072616e  .............ran  
plaintext: 0000000000000000000000007272616e  ............rran  
plaintext: 0000000000000000000000617272616e  ...........arran  
plaintext: 0000000000000000000020617272616e  .......... arran  
plaintext: 0000000000000000006f20617272616e  .........o arran  
plaintext: 0000000000000000746f20617272616e  ........to arran  
plaintext: 0000000000000020746f20617272616e  ....... to arran  
plaintext: 0000000000007420746f20617272616e  ......t to arran  
plaintext: 0000000000737420746f20617272616e  .....st to arran  
plaintext: 0000000065737420746f20617272616e  ....est to arran  
plaintext: 0000006265737420746f20617272616e  ...best to arran  
plaintext: 0000206265737420746f20617272616e  .. best to arran  
plaintext: 0079206265737420746f20617272616e  .y best to arran  
plaintext: 6d79206265737420746f20617272616e  my best to arran  
plaintext: 00000000000000000000000000000079  ...............y  
plaintext: 00000000000000000000000000006d79  ..............my  
plaintext: 00000000000000000000000000206d79  ............. my  
plaintext: 0000000000000000000000006c206d79  ............l my  
plaintext: 00000000000000000000006c6c206d79  ...........ll my  
plaintext: 00000000000000000000416c6c206d79  ..........All my  
plaintext: 0000000000000000000a416c6c206d79  ..........All my  
plaintext: 00000000000000000a0a416c6c206d79  ..........All my  
plaintext: 00000000000000210a0a416c6c206d79  .......!..All my  
plaintext: 00000000000074210a0a416c6c206d79  ......t!..All my  
plaintext: 00000000006174210a0a416c6c206d79  .....at!..All my  
plaintext: 00000000686174210a0a416c6c206d79  ....hat!..All my  
plaintext: 00000074686174210a0a416c6c206d79  ...that!..All my  
plaintext: 00002074686174210a0a416c6c206d79  .. that!..All my  
plaintext: 00652074686174210a0a416c6c206d79  .e that!..All my  
plaintext: 67652074686174210a0a416c6c206d79  ge that!..All my  
plaintext: 0000000000000000000000000000006f  ...............o  
plaintext: 0000000000000000000000000000486f  ..............Ho  
plaintext: 000000000000000000000000000a486f  ..............Ho  
plaintext: 0000000000000000000000002c0a486f  ............,.Ho  
plaintext: 0000000000000000000000732c0a486f  ...........s,.Ho  
plaintext: 0000000000000000000065732c0a486f  ..........es,.Ho  
plaintext: 0000000000000000006865732c0a486f  .........hes,.Ho  
plaintext: 0000000000000000736865732c0a486f  ........shes,.Ho  
plaintext: 0000000000000069736865732c0a486f  .......ishes,.Ho  
plaintext: 0000000000007769736865732c0a486f  ......wishes,.Ho  
plaintext: 0000000000207769736865732c0a486f  ..... wishes,.Ho  
plaintext: 0000000074207769736865732c0a486f  ....t wishes,.Ho  
plaintext: 0000007374207769736865732c0a486f  ...st wishes,.Ho  
plaintext: 0000657374207769736865732c0a486f  ..est wishes,.Ho  
plaintext: 0062657374207769736865732c0a486f  .best wishes,.Ho  
plaintext: 2062657374207769736865732c0a486f   best wishes,.Ho  
plaintext: 00000000000000000000000000000061  ...............a  
plaintext: 00000000000000000000000000007461  ..............ta  
plaintext: 000000000000000000000000006e7461  .............nta  
plaintext: 000000000000000000000000616e7461  ............anta  
plaintext: 000000000000000000000053616e7461  ...........Santa  
plaintext: 000000000000000000002053616e7461  .......... Santa  
plaintext: 0000000000000000002d2053616e7461  .........- Santa  
plaintext: 00000000000000002d2d2053616e7461  ........-- Santa  
plaintext: 000000000000000a2d2d2053616e7461  ........-- Santa  
plaintext: 0000000000002c0a2d2d2053616e7461  ......,.-- Santa  
plaintext: 00000000006f2c0a2d2d2053616e7461  .....o,.-- Santa  
plaintext: 00000000486f2c0a2d2d2053616e7461  ....Ho,.-- Santa  
plaintext: 00000020486f2c0a2d2d2053616e7461  ... Ho,.-- Santa  
plaintext: 00006f20486f2c0a2d2d2053616e7461  ..o Ho,.-- Santa  
plaintext: 00486f20486f2c0a2d2d2053616e7461  .Ho Ho,.-- Santa  
plaintext: 20486f20486f2c0a2d2d2053616e7461   Ho Ho,.-- Santa  
plaintext: 00000000000000000000000000000068  ...............h  
plaintext: 00000000000000000000000000002068  .............. h  
plaintext: 00000000000000000000000000792068  .............y h  
plaintext: 0000000000000000000000004d792068  ............My h  
plaintext: 0000000000000000000000204d792068  ........... My h  
plaintext: 000000000000000000003a204d792068  ..........: My h  
plaintext: 000000000000000000533a204d792068  .........S: My h  
plaintext: 000000000000000050533a204d792068  ........PS: My h  
plaintext: 000000000000000a50533a204d792068  ........PS: My h  
plaintext: 0000000000000a0a50533a204d792068  ........PS: My h  
plaintext: 0000000000730a0a50533a204d792068  .....s..PS: My h  
plaintext: 0000000075730a0a50533a204d792068  ....us..PS: My h  
plaintext: 0000006175730a0a50533a204d792068  ...aus..PS: My h  
plaintext: 00006c6175730a0a50533a204d792068  ..laus..PS: My h  
plaintext: 00436c6175730a0a50533a204d792068  .Claus..PS: My h  
plaintext: 20436c6175730a0a50533a204d792068   Claus..PS: My h  
plaintext: 00000000000000000000000000000073  ...............s  
plaintext: 00000000000000000000000000002073  .............. s  
plaintext: 000000000000000000000000006f2073  .............o s  
plaintext: 000000000000000000000000746f2073  ............to s  
plaintext: 000000000000000000000020746f2073  ........... to s  
plaintext: 000000000000000000007320746f2073  ..........s to s  
plaintext: 000000000000000000647320746f2073  .........ds to s  
plaintext: 000000000000000065647320746f2073  ........eds to s  
plaintext: 000000000000006565647320746f2073  .......eeds to s  
plaintext: 0000000000006c6565647320746f2073  ......leeds to s  
plaintext: 0000000000626c6565647320746f2073  .....bleeds to s  
plaintext: 0000000020626c6565647320746f2073  .... bleeds to s  
plaintext: 0000007420626c6565647320746f2073  ...t bleeds to s  
plaintext: 0000727420626c6565647320746f2073  ..rt bleeds to s  
plaintext: 0061727420626c6565647320746f2073  .art bleeds to s  
plaintext: 6561727420626c6565647320746f2073  eart bleeds to s  
plaintext: 00000000000000000000000000000020  ...............  
plaintext: 00000000000000000000000000006820  ..............h  
plaintext: 00000000000000000000000000636820  .............ch  
plaintext: 00000000000000000000000075636820  ............uch  
plaintext: 00000000000000000000007375636820  ...........such  
plaintext: 00000000000000000000207375636820  .......... such  
plaintext: 00000000000000000065207375636820  .........e such  
plaintext: 00000000000000007365207375636820  ........se such  
plaintext: 00000000000000757365207375636820  .......use such  
plaintext: 00000000000020757365207375636820  ...... use such  
plaintext: 00000000007520757365207375636820  .....u use such  
plaintext: 000000006f7520757365207375636820  ....ou use such  
plaintext: 000000796f7520757365207375636820  ...you use such  
plaintext: 000020796f7520757365207375636820  .. you use such  
plaintext: 006520796f7520757365207375636820  .e you use such  
plaintext: 656520796f7520757365207375636820  ee you use such  
plaintext: 00000000000000000000000000000075  ...............u  
plaintext: 00000000000000000000000000007375  ..............su  
plaintext: 00000000000000000000000000207375  ............. su  
plaintext: 00000000000000000000000049207375  ............I su  
plaintext: 00000000000000000000000a49207375  ............I su  
plaintext: 000000000000000000002e0a49207375  ............I su  
plaintext: 000000000000000000792e0a49207375  .........y..I su  
plaintext: 000000000000000065792e0a49207375  ........ey..I su  
plaintext: 000000000000006b65792e0a49207375  .......key..I su  
plaintext: 000000000000206b65792e0a49207375  ...... key..I su  
plaintext: 00000000006b206b65792e0a49207375  .....k key..I su  
plaintext: 00000000616b206b65792e0a49207375  ....ak key..I su  
plaintext: 00000065616b206b65792e0a49207375  ...eak key..I su  
plaintext: 00007765616b206b65792e0a49207375  ..weak key..I su  
plaintext: 00207765616b206b65792e0a49207375  . weak key..I su  
plaintext: 61207765616b206b65792e0a49207375  a weak key..I su  
plaintext: 00000000000000000000000000000069  ...............i  
plaintext: 00000000000000000000000000006869  ..............hi  
plaintext: 00000000000000000000000000746869  .............thi  
plaintext: 00000000000000000000000020746869  ............ thi  
plaintext: 00000000000000000000007420746869  ...........t thi  
plaintext: 00000000000000000000617420746869  ..........at thi  
plaintext: 00000000000000000068617420746869  .........hat thi  
plaintext: 00000000000000007468617420746869  ........that thi  
plaintext: 00000000000000207468617420746869  ....... that thi  
plaintext: 00000000000065207468617420746869  ......e that thi  
plaintext: 00000000007065207468617420746869  .....pe that thi  
plaintext: 000000006f7065207468617420746869  ....ope that thi  
plaintext: 000000686f7065207468617420746869  ...hope that thi  
plaintext: 000020686f7065207468617420746869  .. hope that thi  
plaintext: 006520686f7065207468617420746869  .e hope that thi  
plaintext: 726520686f7065207468617420746869  re hope that thi  
plaintext: 00000000000000000000000000000074  ...............t  
plaintext: 00000000000000000000000000007474  ..............tt  
plaintext: 00000000000000000000000000657474  .............ett  
plaintext: 00000000000000000000000062657474  ............bett  
plaintext: 00000000000000000000002062657474  ........... bett  
plaintext: 00000000000000000000732062657474  ..........s bett  
plaintext: 00000000000000000069732062657474  .........is bett  
plaintext: 00000000000000002069732062657474  ........ is bett  
plaintext: 00000000000000722069732062657474  .......r is bett  
plaintext: 00000000000065722069732062657474  ......er is bett  
plaintext: 00000000007665722069732062657474  .....ver is bett  
plaintext: 00000000727665722069732062657474  ....rver is bett  
plaintext: 00000065727665722069732062657474  ...erver is bett  
plaintext: 00007365727665722069732062657474  ..server is bett  
plaintext: 00207365727665722069732062657474  . server is bett  
plaintext: 73207365727665722069732062657474  s server is bett  
plaintext: 00000000000000000000000000000061  ...............a  
plaintext: 00000000000000000000000000006861  ..............ha  
plaintext: 00000000000000000000000000746861  .............tha  
plaintext: 00000000000000000000000020746861  ............ tha  
plaintext: 00000000000000000000006420746861  ...........d tha  
plaintext: 00000000000000000000656420746861  ..........ed tha  
plaintext: 00000000000000000074656420746861  .........ted tha  
plaintext: 00000000000000006374656420746861  ........cted tha  
plaintext: 00000000000000656374656420746861  .......ected tha  
plaintext: 00000000000074656374656420746861  ......tected tha  
plaintext: 00000000006f74656374656420746861  .....otected tha  
plaintext: 00000000726f74656374656420746861  ....rotected tha  
plaintext: 00000070726f74656374656420746861  ...protected tha  
plaintext: 00000a70726f74656374656420746861  ...protected tha  
plaintext: 00720a70726f74656374656420746861  .r.protected tha  
plaintext: 65720a70726f74656374656420746861  er.protected tha  
plaintext: 0000000000000000000000000000006e  ...............n  
plaintext: 0000000000000000000000000000456e  ..............En  
plaintext: 0000000000000000000000000034456e  .............4En  
plaintext: 0000000000000000000000001434456e  .............4En  
plaintext: 00000000000000000000003a1434456e  ...........:.4En  
plaintext: 00000000000000000000003a1434456e  ...........:.4En  
plaintext: 00000000000000000028003a1434456e  .........(.:.4En  
plaintext: 00000000000000002e28003a1434456e  .........(.:.4En  
plaintext: 000000000000002e2e28003a1434456e  .........(.:.4En  
plaintext: 0000000000002e2e2e28003a1434456e  .........(.:.4En  
plaintext: 0000000000742e2e2e28003a1434456e  .....t...(.:.4En  
plaintext: 0000000061742e2e2e28003a1434456e  ....at...(.:.4En  
plaintext: 0000006861742e2e2e28003a1434456e  ...hat...(.:.4En  
plaintext: 0000746861742e2e2e28003a1434456e  ..that...(.:.4En  
plaintext: 0020746861742e2e2e28003a1434456e  . that...(.:.4En  
plaintext: 6e20746861742e2e2e28003a1434456e  n that...(.:.4En  
plaintext: 00000000000000000000000000000031  ...............1  
plaintext: 00000000000000000000000000006b31  ..............k1  
plaintext: 000000000000000000000000006b6b31  .............kk1  
plaintext: 0000000000000000000000004e6b6b31  ............Nkk1  
plaintext: 0000000000000000000000524e6b6b31  ...........RNkk1  
plaintext: 0000000000000000000039524e6b6b31  ..........9RNkk1  
plaintext: 0000000000000000006e39524e6b6b31  .........n9RNkk1  
plaintext: 0000000000000000636e39524e6b6b31  ........cn9RNkk1  
plaintext: 0000000000000049636e39524e6b6b31  .......Icn9RNkk1  
plaintext: 0000000000006949636e39524e6b6b31  ......iIcn9RNkk1  
plaintext: 0000000000456949636e39524e6b6b31  .....EiIcn9RNkk1  
plaintext: 000000006d456949636e39524e6b6b31  ....mEiIcn9RNkk1  
plaintext: 000000696d456949636e39524e6b6b31  ...imEiIcn9RNkk1  
plaintext: 000076696d456949636e39524e6b6b31  ..vimEiIcn9RNkk1  
plaintext: 003476696d456949636e39524e6b6b31  .4vimEiIcn9RNkk1  
plaintext: 793476696d456949636e39524e6b6b31  y4vimEiIcn9RNkk1  
plaintext: 0000000000000000000000000000000f  ................  
plaintext: 00000000000000000000000000000f0f  ................  
plaintext: 000000000000000000000000000f0f0f  ................  
plaintext: 0000000000000000000000000f0f0f0f  ................  
plaintext: 00000000000000000000000f0f0f0f0f  ................  
plaintext: 000000000000000000000f0f0f0f0f0f  ................  
plaintext: 0000000000000000000f0f0f0f0f0f0f  ................  
plaintext: 00000000000000000f0f0f0f0f0f0f0f  ................  
plaintext: 000000000000000f0f0f0f0f0f0f0f0f  ................  
plaintext: 0000000000000f0f0f0f0f0f0f0f0f0f  ................  
plaintext: 00000000000f0f0f0f0f0f0f0f0f0f0f  ................  
plaintext: 000000000f0f0f0f0f0f0f0f0f0f0f0f  ................  
plaintext: 0000000f0f0f0f0f0f0f0f0f0f0f0f0f  ................  
plaintext: 00000f0f0f0f0f0f0f0f0f0f0f0f0f0f  ................  
plaintext: 000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f  ................  
plaintext: 000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f  ................  
```

Doing this we find that "Timmy" does not have have the flag in any of his
messages (as we might expect). However, we see that "TheRealSanta" user is the
one sending "Timmy" his only message. With that we re-start the whole attack
(generate templates, recover the IV, list the message IDs, and decrypt the
messages) and find that Santa has received many messages from many different
users as shown below:

```python  
solve_iv('TheRealSanta')  
solved_iv = binascii.unhexlify('4a707a1e2d65746c6a4f3879526c7852')  
solve_list_messages('TheRealSanta',solved_iv,10)

solve_get_message('TheRealSanta',solved_iv,0x0382)  
solve_get_message('TheRealSanta',solved_iv,0x44b3)  
solve_get_message('TheRealSanta',solved_iv,0x6931)  
solve_get_message('TheRealSanta',solved_iv,0x04c3)  
#solve_get_message('TheRealSanta',solved_iv,0x5e7f)  
#solve_get_message('TheRealSanta',solved_iv,0x3b00)  
#solve_get_message('TheRealSanta',solved_iv,0x237f)  
#solve_get_message('TheRealSanta',solved_iv,0x38fc)  
#solve_get_message('TheRealSanta',solved_iv,0x4dd4)  
#solve_get_message('TheRealSanta',solved_iv,0x1080)  
```

```  
$ ./challenge6.py  
Solve IV: TheRealSanta  
plaintext: 00000000000000000000000000000052  ...............R  
plaintext: 00000000000000000000000000007852  ..............xR  
plaintext: 000000000000000000000000006c7852  .............lxR  
plaintext: 000000000000000000000000526c7852  ............RlxR  
plaintext: 000000000000000000000079526c7852  ...........yRlxR  
plaintext: 000000000000000000003879526c7852  ..........8yRlxR  
plaintext: 0000000000000000004f3879526c7852  .........O8yRlxR  
plaintext: 00000000000000006a4f3879526c7852  ........jO8yRlxR  
plaintext: 000000000000006c6a4f3879526c7852  .......ljO8yRlxR  
plaintext: 000000000000746c6a4f3879526c7852  ......tljO8yRlxR  
plaintext: 000000000065746c6a4f3879526c7852  .....etljO8yRlxR  
plaintext: 000000002d65746c6a4f3879526c7852  ....-etljO8yRlxR  
plaintext: 0000001e2d65746c6a4f3879526c7852  ....-etljO8yRlxR  
plaintext: 00007a1e2d65746c6a4f3879526c7852  ..z.-etljO8yRlxR  
plaintext: 00707a1e2d65746c6a4f3879526c7852  .pz.-etljO8yRlxR  
plaintext: 4a707a1e2d65746c6a4f3879526c7852  Jpz.-etljO8yRlxR  
$ ./challenge6.py  
List Messages TheRealSanta  
plaintext: 00000000000000000000000000000000  ................  
plaintext: 00000000000000000000000000000000  ................  
plaintext: 00000000000000000000000000030000  ................  
plaintext: 00000000000000000000000082030000  ................  
plaintext: 00000000000000000000002882030000  ...........(....  
plaintext: 00000000000000000000322882030000  ..........2(....  
plaintext: 00000000000000000000322882030000  ..........2(....  
plaintext: 00000000000000002800322882030000  ........(.2(....  
plaintext: 00000000000000052800322882030000  ........(.2(....  
plaintext: 000000000000e0052800322882030000  ........(.2(....  
plaintext: 0000000000f5e0052800322882030000  ........(.2(....  
plaintext: 00000000d8f5e0052800322882030000  ........(.2(....  
plaintext: 000000f6d8f5e0052800322882030000  ........(.2(....  
plaintext: 000010f6d8f5e0052800322882030000  ........(.2(....  
plaintext: 000210f6d8f5e0052800322882030000  ........(.2(....  
plaintext: 080210f6d8f5e0052800322882030000  ........(.2(....  
plaintext: 00000000000000000000000000000000  ................  
plaintext: 00000000000000000000000000000000  ................  
plaintext: 000000000000000000000000005e0000  .............^..  
plaintext: 0000000000000000000000007f5e0000  .............^..  
plaintext: 0000000000000000000000007f5e0000  .............^..  
plaintext: 0000000000000000000000007f5e0000  .............^..  
plaintext: 0000000000000000000400007f5e0000  .............^..  
plaintext: 0000000000000000c30400007f5e0000  .............^..  
plaintext: 0000000000000000c30400007f5e0000  .............^..  
plaintext: 0000000000000000c30400007f5e0000  .............^..  
plaintext: 0000000000690000c30400007f5e0000  .....i.......^..  
plaintext: 0000000031690000c30400007f5e0000  ....1i.......^..  
plaintext: 0000000031690000c30400007f5e0000  ....1i.......^..  
plaintext: 0000000031690000c30400007f5e0000  ....1i.......^..  
plaintext: 0044000031690000c30400007f5e0000  .D..1i.......^..  
plaintext: b344000031690000c30400007f5e0000  .D..1i.......^..  
plaintext: 00000000000000000000000000000000  ................  
plaintext: 00000000000000000000000000000000  ................  
plaintext: 000000000000000000000000004d0000  .............M..  
plaintext: 000000000000000000000000d44d0000  .............M..  
plaintext: 000000000000000000000000d44d0000  .............M..  
plaintext: 000000000000000000000000d44d0000  .............M..  
plaintext: 000000000000000000380000d44d0000  .........8...M..  
plaintext: 0000000000000000fc380000d44d0000  .........8...M..  
plaintext: 0000000000000000fc380000d44d0000  .........8...M..  
plaintext: 0000000000000000fc380000d44d0000  .........8...M..  
plaintext: 0000000000230000fc380000d44d0000  .....#...8...M..  
plaintext: 000000007f230000fc380000d44d0000  .....#...8...M..  
plaintext: 000000007f230000fc380000d44d0000  .....#...8...M..  
plaintext: 000000007f230000fc380000d44d0000  .....#...8...M..  
plaintext: 003b00007f230000fc380000d44d0000  .;...#...8...M..  
plaintext: 003b00007f230000fc380000d44d0000  .;...#...8...M..  
plaintext: 0000000000000000000000000000006f  ...............o  
plaintext: 0000000000000000000000000000366f  ..............6o  
plaintext: 0000000000000000000000000036366f  .............66o  
plaintext: 0000000000000000000000004936366f  ............I66o  
plaintext: 00000000000000000000004f4936366f  ...........OI66o  
plaintext: 00000000000000000000444f4936366f  ..........DOI66o  
plaintext: 00000000000000000031444f4936366f  .........1DOI66o  
plaintext: 00000000000000007131444f4936366f  ........q1DOI66o  
plaintext: 00000000000000307131444f4936366f  .......0q1DOI66o  
plaintext: 00000000000056307131444f4936366f  ......V0q1DOI66o  
plaintext: 00000000001456307131444f4936366f  ......V0q1DOI66o  
plaintext: 000000003a1456307131444f4936366f  ....:.V0q1DOI66o  
plaintext: 000000003a1456307131444f4936366f  ....:.V0q1DOI66o  
plaintext: 000000003a1456307131444f4936366f  ....:.V0q1DOI66o  
plaintext: 001000003a1456307131444f4936366f  ....:.V0q1DOI66o  
plaintext: 801000003a1456307131444f4936366f  ....:.V0q1DOI66o  
plaintext: 00000000000000000000000000000006  ................  
plaintext: 00000000000000000000000000000606  ................  
plaintext: 00000000000000000000000000060606  ................  
plaintext: 00000000000000000000000006060606  ................  
plaintext: 00000000000000000000000606060606  ................  
plaintext: 00000000000000000000060606060606  ................  
plaintext: 00000000000000000000060606060606  ................  
plaintext: 00000000000000007100060606060606  ........q.......  
plaintext: 00000000000000357100060606060606  .......5q.......  
plaintext: 00000000000068357100060606060606  ......h5q.......  
plaintext: 00000000006c68357100060606060606  .....lh5q.......  
plaintext: 00000000426c68357100060606060606  ....Blh5q.......  
plaintext: 00000037426c68357100060606060606  ...7Blh5q.......  
plaintext: 00004237426c68357100060606060606  ..B7Blh5q.......  
plaintext: 004d4237426c68357100060606060606  .MB7Blh5q.......  
plaintext: 334d4237426c68357100060606060606  3MB7Blh5q.......  
$ ./challenge6.py  
Get Message TheRealSanta 898 0x382  
plaintext: 00000000000000000000000000000022  ..............."  
plaintext: 00000000000000000000000000007922  ..............y"  
plaintext: 000000000000000000000000006d7922  .............my"  
plaintext: 0000000000000000000000006d6d7922  ............mmy"  
plaintext: 0000000000000000000000696d6d7922  ...........immy"  
plaintext: 0000000000000000000054696d6d7922  ..........Timmy"  
plaintext: 0000000000000000000554696d6d7922  ..........Timmy"  
plaintext: 00000000000000001a0554696d6d7922  ..........Timmy"  
plaintext: 00000000000000051a0554696d6d7922  ..........Timmy"  
plaintext: 000000000000e0051a0554696d6d7922  ..........Timmy"  
plaintext: 0000000000f5e0051a0554696d6d7922  ..........Timmy"  
plaintext: 00000000b3f5e0051a0554696d6d7922  ..........Timmy"  
plaintext: 00000086b3f5e0051a0554696d6d7922  ..........Timmy"  
plaintext: 00001086b3f5e0051a0554696d6d7922  ..........Timmy"  
plaintext: 00031086b3f5e0051a0554696d6d7922  ..........Timmy"  
plaintext: 08031086b3f5e0051a0554696d6d7922  ..........Timmy"  
plaintext: 00000000000000000000000000000049  ...............I  
plaintext: 00000000000000000000000000000a49  ...............I  
plaintext: 000000000000000000000000000a0a49  ...............I  
plaintext: 0000000000000000000000002c0a0a49  ............,..I  
plaintext: 0000000000000000000000612c0a0a49  ...........a,..I  
plaintext: 0000000000000000000074612c0a0a49  ..........ta,..I  
plaintext: 0000000000000000006e74612c0a0a49  .........nta,..I  
plaintext: 0000000000000000616e74612c0a0a49  ........anta,..I  
plaintext: 0000000000000053616e74612c0a0a49  .......Santa,..I  
plaintext: 0000000000002053616e74612c0a0a49  ...... Santa,..I  
plaintext: 0000000000722053616e74612c0a0a49  .....r Santa,..I  
plaintext: 0000000061722053616e74612c0a0a49  ....ar Santa,..I  
plaintext: 0000006561722053616e74612c0a0a49  ...ear Santa,..I  
plaintext: 0000446561722053616e74612c0a0a49  ..Dear Santa,..I  
plaintext: 0001446561722053616e74612c0a0a49  ..Dear Santa,..I  
plaintext: 9c01446561722053616e74612c0a0a49  ..Dear Santa,..I  
plaintext: 00000000000000000000000000000079  ...............y  
padding oracle failure!  
plaintext: 0000000000000000000000000000006c  ...............l  
plaintext: 00000000000000000000000000006c6c  ..............ll  
plaintext: 00000000000000000000000000656c6c  .............ell  
plaintext: 00000000000000000000000077656c6c  ............well  
plaintext: 00000000000000000000002077656c6c  ........... well  
plaintext: 00000000000000000000792077656c6c  ..........y well  
plaintext: 0000000000000000006c792077656c6c  .........ly well  
plaintext: 00000000000000006c6c792077656c6c  ........lly well  
plaintext: 00000000000000616c6c792077656c6c  .......ally well  
plaintext: 0000000000006e616c6c792077656c6c  ......nally well  
plaintext: 00000000006f6e616c6c792077656c6c  .....onally well  
plaintext: 00000000696f6e616c6c792077656c6c  ....ionally well  
plaintext: 00000074696f6e616c6c792077656c6c  ...tionally well  
plaintext: 00007074696f6e616c6c792077656c6c  ..ptionally well  
plaintext: 00657074696f6e616c6c792077656c6c  .eptionally well  
plaintext: 63657074696f6e616c6c792077656c6c  ceptionally well  
plaintext: 00000000000000000000000000000049  ...............I  
plaintext: 00000000000000000000000000002049  .............. I  
plaintext: 00000000000000000000000000642049  .............d I  
plaintext: 0000000000000000000000006e642049  ............nd I  
plaintext: 0000000000000000000000616e642049  ...........and I  
plaintext: 000000000000000000000a616e642049  ...........and I  
plaintext: 000000000000000000720a616e642049  .........r.and I  
plaintext: 000000000000000061720a616e642049  ........ar.and I  
plaintext: 000000000000006561720a616e642049  .......ear.and I  
plaintext: 000000000000796561720a616e642049  ......year.and I  
plaintext: 000000000020796561720a616e642049  ..... year.and I  
plaintext: 000000007320796561720a616e642049  ....s year.and I  
plaintext: 000000697320796561720a616e642049  ...is year.and I  
plaintext: 000068697320796561720a616e642049  ..his year.and I  
plaintext: 007468697320796561720a616e642049  .this year.and I  
plaintext: 207468697320796561720a616e642049   this year.and I  
plaintext: 00000000000000000000000000000069  ...............i  
plaintext: 00000000000000000000000000006c69  ..............li  
plaintext: 00000000000000000000000000206c69  ............. li  
plaintext: 00000000000000000000000079206c69  ............y li  
plaintext: 00000000000000000000006c79206c69  ...........ly li  
plaintext: 000000000000000000006c6c79206c69  ..........lly li  
plaintext: 000000000000000000616c6c79206c69  .........ally li  
plaintext: 000000000000000065616c6c79206c69  ........eally li  
plaintext: 000000000000007265616c6c79206c69  .......really li  
plaintext: 000000000000207265616c6c79206c69  ...... really li  
plaintext: 000000000064207265616c6c79206c69  .....d really li  
plaintext: 000000006c64207265616c6c79206c69  ....ld really li  
plaintext: 000000756c64207265616c6c79206c69  ...uld really li  
plaintext: 00006f756c64207265616c6c79206c69  ..ould really li  
plaintext: 00776f756c64207265616c6c79206c69  .would really li  
plaintext: 20776f756c64207265616c6c79206c69   would really li  
plaintext: 00000000000000000000000000000020  ...............  
plaintext: 00000000000000000000000000007220  ..............r  
plaintext: 000000000000000000000000006f7220  .............or  
plaintext: 000000000000000000000000666f7220  ............for  
plaintext: 000000000000000000000020666f7220  ........... for  
plaintext: 000000000000000000007420666f7220  ..........t for  
plaintext: 0000000000000000006f7420666f7220  .........ot for  
plaintext: 0000000000000000726f7420666f7220  ........rot for  
plaintext: 0000000000000072726f7420666f7220  .......rrot for  
plaintext: 0000000000006172726f7420666f7220  ......arrot for  
plaintext: 0000000000706172726f7420666f7220  .....parrot for  
plaintext: 0000000020706172726f7420666f7220  .... parrot for  
plaintext: 0000006120706172726f7420666f7220  ...a parrot for  
plaintext: 0000206120706172726f7420666f7220  .. a parrot for  
plaintext: 0065206120706172726f7420666f7220  .e a parrot for  
plaintext: 6b65206120706172726f7420666f7220  ke a parrot for  
plaintext: 00000000000000000000000000000064  ...............d  
plaintext: 00000000000000000000000000006c64  ..............ld  
plaintext: 00000000000000000000000000756c64  .............uld  
plaintext: 0000000000000000000000006f756c64  ............ould  
plaintext: 0000000000000000000000586f756c64  ...........Xould  
padding oracle failure!  
plaintext: 0000000000000000000000000000006c  ...............l  
plaintext: 0000000000000000000000000000626c  ..............bl  
plaintext: 0000000000000000000000000069626c  .............ibl  
plaintext: 0000000000000000000000007369626c  ............sibl  
plaintext: 0000000000000000000000737369626c  ...........ssibl  
plaintext: 000000000000000000006f737369626c  ..........ossibl  
plaintext: 000000000000000000706f737369626c  .........possibl  
plaintext: 000000000000000020706f737369626c  ........ possibl  
plaintext: 000000000000006520706f737369626c  .......e possibl  
plaintext: 000000000000626520706f737369626c  ......be possibl  
plaintext: 000000000020626520706f737369626c  ..... be possibl  
plaintext: 000000007420626520706f737369626c  ....t be possibl  
plaintext: 000000617420626520706f737369626c  ...at be possibl  
plaintext: 000068617420626520706f737369626c  ..hat be possibl  
plaintext: 007468617420626520706f737369626c  .that be possibl  
plaintext: 207468617420626520706f737369626c   that be possibl  
plaintext: 00000000000000000000000000000074  ...............t  
plaintext: 00000000000000000000000000007374  ..............st  
plaintext: 00000000000000000000000000657374  .............est  
plaintext: 00000000000000000000000067657374  ............gest  
plaintext: 00000000000000000000006767657374  ...........ggest  
plaintext: 00000000000000000000696767657374  ..........iggest  
plaintext: 00000000000000000062696767657374  .........biggest  
plaintext: 00000000000000002062696767657374  ........ biggest  
plaintext: 00000000000000722062696767657374  .......r biggest  
plaintext: 00000000000075722062696767657374  ......ur biggest  
plaintext: 00000000006f75722062696767657374  .....our biggest  
plaintext: 00000000596f75722062696767657374  ....Your biggest  
plaintext: 0000000a596f75722062696767657374  ....Your biggest  
plaintext: 00000a0a596f75722062696767657374  ....Your biggest  
plaintext: 003f0a0a596f75722062696767657374  .?..Your biggest  
plaintext: 653f0a0a596f75722062696767657374  e?..Your biggest  
plaintext: 00000000000000000000000000000000  ................  
plaintext: 00000000000000000000000000002800  ..............(.  
plaintext: 00000000000000000000000000792800  .............y(.  
plaintext: 0000000000000000000000006d792800  ............my(.  
plaintext: 00000000000000000000006d6d792800  ...........mmy(.  
plaintext: 00000000000000000000696d6d792800  ..........immy(.  
plaintext: 00000000000000000054696d6d792800  .........Timmy(.  
plaintext: 00000000000000002054696d6d792800  ........ Timmy(.  
plaintext: 000000000000002d2054696d6d792800  .......- Timmy(.  
plaintext: 0000000000002d2d2054696d6d792800  ......-- Timmy(.  
plaintext: 00000000000a2d2d2054696d6d792800  ......-- Timmy(.  
plaintext: 000000002c0a2d2d2054696d6d792800  ....,.-- Timmy(.  
plaintext: 0000006e2c0a2d2d2054696d6d792800  ...n,.-- Timmy(.  
plaintext: 0000616e2c0a2d2d2054696d6d792800  ..an,.-- Timmy(.  
plaintext: 0066616e2c0a2d2d2054696d6d792800  .fan,.-- Timmy(.  
plaintext: 2066616e2c0a2d2d2054696d6d792800   fan,.-- Timmy(.  
plaintext: 00000000000000000000000000000058  ...............X  
plaintext: 00000000000000000000000000005658  ..............VX  
plaintext: 00000000000000000000000000325658  .............2VX  
plaintext: 00000000000000000000000044325658  ............D2VX  
plaintext: 00000000000000000000007644325658  ...........vD2VX  
plaintext: 00000000000000000000647644325658  ..........dvD2VX  
plaintext: 0000000000000000005a647644325658  .........ZdvD2VX  
plaintext: 0000000000000000765a647644325658  ........vZdvD2VX  
plaintext: 0000000000000071765a647644325658  .......qvZdvD2VX  
plaintext: 0000000000005871765a647644325658  ......XqvZdvD2VX  
plaintext: 0000000000495871765a647644325658  .....IXqvZdvD2VX  
plaintext: 0000000046495871765a647644325658  ....FIXqvZdvD2VX  
plaintext: 0000004d46495871765a647644325658  ...MFIXqvZdvD2VX  
plaintext: 0000554d46495871765a647644325658  ..UMFIXqvZdvD2VX  
plaintext: 0014554d46495871765a647644325658  ..UMFIXqvZdvD2VX  
plaintext: 3a14554d46495871765a647644325658  :.UMFIXqvZdvD2VX  
plaintext: 0000000000000000000000000000000a  ................  
plaintext: 00000000000000000000000000000a0a  ................  
plaintext: 000000000000000000000000000a0a0a  ................  
plaintext: 0000000000000000000000000a0a0a0a  ................  
plaintext: 00000000000000000000000a0a0a0a0a  ................  
plaintext: 000000000000000000000a0a0a0a0a0a  ................  
plaintext: 0000000000000000000a0a0a0a0a0a0a  ................  
plaintext: 00000000000000000a0a0a0a0a0a0a0a  ................  
plaintext: 000000000000000a0a0a0a0a0a0a0a0a  ................  
plaintext: 0000000000000a0a0a0a0a0a0a0a0a0a  ................  
plaintext: 0000000000000a0a0a0a0a0a0a0a0a0a  ................  
plaintext: 000000006d000a0a0a0a0a0a0a0a0a0a  ....m...........  
plaintext: 000000396d000a0a0a0a0a0a0a0a0a0a  ...9m...........  
plaintext: 000075396d000a0a0a0a0a0a0a0a0a0a  ..u9m...........  
plaintext: 007a75396d000a0a0a0a0a0a0a0a0a0a  .zu9m...........  
plaintext: 797a75396d000a0a0a0a0a0a0a0a0a0a  yzu9m...........  
Get Message TheRealSanta 17587 0x44b3  
plaintext: 00000000000000000000000000000063  ...............c  
plaintext: 00000000000000000000000000006963  ..............ic  
plaintext: 00000000000000000000000000736963  .............sic  
plaintext: 00000000000000000000000073736963  ............ssic  
plaintext: 00000000000000000000006573736963  ...........essic  
plaintext: 000000000000000000004a6573736963  ..........Jessic  
plaintext: 000000000000000000074a6573736963  ..........Jessic  
plaintext: 00000000000000001a074a6573736963  ..........Jessic  
plaintext: 00000000000000051a074a6573736963  ..........Jessic  
plaintext: 000000000000e0051a074a6573736963  ..........Jessic  
plaintext: 0000000000f5e0051a074a6573736963  ..........Jessic  
plaintext: 000000009ff5e0051a074a6573736963  ..........Jessic  
plaintext: 000000c49ff5e0051a074a6573736963  ..........Jessic  
plaintext: 000010c49ff5e0051a074a6573736963  ..........Jessic  
plaintext: 000310c49ff5e0051a074a6573736963  ..........Jessic  
plaintext: 080310c49ff5e0051a074a6573736963  ..........Jessic  
plaintext: 0000000000000000000000000000000a  ................  
plaintext: 00000000000000000000000000002c0a  ..............,.  
plaintext: 00000000000000000000000000612c0a  .............a,.  
plaintext: 00000000000000000000000074612c0a  ............ta,.  
plaintext: 00000000000000000000006e74612c0a  ...........nta,.  
plaintext: 00000000000000000000616e74612c0a  ..........anta,.  
plaintext: 00000000000000000053616e74612c0a  .........Santa,.  
plaintext: 00000000000000002053616e74612c0a  ........ Santa,.  
plaintext: 00000000000000722053616e74612c0a  .......r Santa,.  
plaintext: 00000000000061722053616e74612c0a  ......ar Santa,.  
plaintext: 00000000006561722053616e74612c0a  .....ear Santa,.  
plaintext: 00000000446561722053616e74612c0a  ....Dear Santa,.  
plaintext: 00000001446561722053616e74612c0a  ....Dear Santa,.  
plaintext: 0000b901446561722053616e74612c0a  ....Dear Santa,.  
plaintext: 0022b901446561722053616e74612c0a  ."..Dear Santa,.  
plaintext: 6122b901446561722053616e74612c0a  a"..Dear Santa,.  
plaintext: 00000000000000000000000000000020  ...............  
plaintext: 00000000000000000000000000006420  ..............d  
plaintext: 00000000000000000000000000656420  .............ed  
plaintext: 00000000000000000000000076656420  ............ved  
plaintext: 00000000000000000000006176656420  ...........aved  
plaintext: 00000000000000000000686176656420  ..........haved  
plaintext: 00000000000000000065686176656420  .........ehaved  
plaintext: 00000000000000006265686176656420  ........behaved  
plaintext: 00000000000000206265686176656420  ....... behaved  
plaintext: 00000000000065206265686176656420  ......e behaved  
plaintext: 00000000007665206265686176656420  .....ve behaved  
plaintext: 00000000617665206265686176656420  ....ave behaved  
plaintext: 00000068617665206265686176656420  ...have behaved  
plaintext: 00002068617665206265686176656420  .. have behaved  
plaintext: 00492068617665206265686176656420  .I have behaved  
plaintext: 0a492068617665206265686176656420  .I have behaved  
plaintext: 00000000000000000000000000000065  ...............e  
plaintext: 00000000000000000000000000007765  ..............we  
plaintext: 00000000000000000000000000207765  ............. we  
plaintext: 00000000000000000000000079207765  ............y we  
plaintext: 00000000000000000000006c79207765  ...........ly we  
plaintext: 000000000000000000006c6c79207765  ..........lly we  
plaintext: 000000000000000000616c6c79207765  .........ally we  
plaintext: 00000000000000006e616c6c79207765  ........nally we  
plaintext: 000000000000006f6e616c6c79207765  .......onally we  
plaintext: 000000000000696f6e616c6c79207765  ......ionally we  
plaintext: 000000000074696f6e616c6c79207765  .....tionally we  
plaintext: 000000007074696f6e616c6c79207765  ....ptionally we  
plaintext: 000000657074696f6e616c6c79207765  ...eptionally we  
plaintext: 000063657074696f6e616c6c79207765  ..ceptionally we  
plaintext: 007863657074696f6e616c6c79207765  .xceptionally we  
plaintext: 657863657074696f6e616c6c79207765  exceptionally we  
plaintext: 00000000000000000000000000000064  ...............d  
plaintext: 00000000000000000000000000006e64  ..............nd  
plaintext: 00000000000000000000000000616e64  .............and  
plaintext: 0000000000000000000000000a616e64  .............and  
plaintext: 0000000000000000000000720a616e64  ...........r.and  
plaintext: 0000000000000000000061720a616e64  ..........ar.and  
plaintext: 0000000000000000006561720a616e64  .........ear.and  
plaintext: 0000000000000000796561720a616e64  ........year.and  
plaintext: 0000000000000020796561720a616e64  ....... year.and  
plaintext: 0000000000007320796561720a616e64  ......s year.and  
plaintext: 0000000000697320796561720a616e64  .....is year.and  
plaintext: 0000000068697320796561720a616e64  ....his year.and  
plaintext: 0000007468697320796561720a616e64  ...this year.and  
plaintext: 0000207468697320796561720a616e64  .. this year.and  
plaintext: 006c207468697320796561720a616e64  .l this year.and  
plaintext: 6c6c207468697320796561720a616e64  ll this year.and  
plaintext: 00000000000000000000000000000020  ...............  
plaintext: 00000000000000000000000000007920  ..............y  
plaintext: 000000000000000000000000006c7920  .............ly  
plaintext: 0000000000000000000000006c6c7920  ............lly  
plaintext: 0000000000000000000000616c6c7920  ...........ally  
plaintext: 0000000000000000000065616c6c7920  ..........eally  
plaintext: 0000000000000000007265616c6c7920  .........really  
plaintext: 0000000000000000207265616c6c7920  ........ really  
plaintext: 0000000000000064207265616c6c7920  .......d really  
plaintext: 0000000000006c64207265616c6c7920  ......ld really  
plaintext: 0000000000756c64207265616c6c7920  .....uld really  
plaintext: 000000006f756c64207265616c6c7920  ....ould really  
plaintext: 000000776f756c64207265616c6c7920  ...would really  
plaintext: 000020776f756c64207265616c6c7920  .. would really  
plaintext: 004920776f756c64207265616c6c7920  .I would really  
plaintext: 204920776f756c64207265616c6c7920   I would really  
plaintext: 0000000000000000000000000000006f  ...............o  
plaintext: 0000000000000000000000000000666f  ..............fo  
plaintext: 0000000000000000000000000020666f  ............. fo  
plaintext: 0000000000000000000000006720666f  ............g fo  
plaintext: 0000000000000000000000616720666f  ...........ag fo  
plaintext: 000000000000000000006c616720666f  ..........lag fo  
plaintext: 000000000000000000666c616720666f  .........flag fo  
plaintext: 000000000000000020666c616720666f  ........ flag fo  
plaintext: 000000000000006520666c616720666f  .......e flag fo  
plaintext: 000000000000686520666c616720666f  ......he flag fo  
plaintext: 000000000074686520666c616720666f  .....the flag fo  
plaintext: 000000002074686520666c616720666f  .... the flag fo  
plaintext: 000000652074686520666c616720666f  ...e the flag fo  
plaintext: 00006b652074686520666c616720666f  ..ke the flag fo  
plaintext: 00696b652074686520666c616720666f  .ike the flag fo  
plaintext: 6c696b652074686520666c616720666f  like the flag fo  
plaintext: 00000000000000000000000000000063  ...............c  
plaintext: 00000000000000000000000000002063  .............. c  
plaintext: 00000000000000000000000000612063  .............a c  
plaintext: 00000000000000000000000074612063  ............ta c  
plaintext: 00000000000000000000006e74612063  ...........nta c  
plaintext: 00000000000000000000616e74612063  ..........anta c  
plaintext: 00000000000000000073616e74612063  .........santa c  
plaintext: 00000000000000007073616e74612063  ........psanta c  
plaintext: 00000000000000647073616e74612063  .......dpsanta c  
plaintext: 00000000000075647073616e74612063  ......udpsanta c  
plaintext: 00000000002075647073616e74612063  ..... udpsanta c  
plaintext: 00000000652075647073616e74612063  ....e udpsanta c  
plaintext: 00000068652075647073616e74612063  ...he udpsanta c  
plaintext: 00007468652075647073616e74612063  ..the udpsanta c  
plaintext: 00207468652075647073616e74612063  . the udpsanta c  
plaintext: 72207468652075647073616e74612063  r the udpsanta c  
plaintext: 00000000000000000000000000000072  ...............r  
plaintext: 00000000000000000000000000006872  ..............hr  
plaintext: 00000000000000000000000000436872  .............Chr  
plaintext: 00000000000000000000000020436872  ............ Chr  
plaintext: 00000000000000000000007220436872  ...........r Chr  
plaintext: 000000000000000000006f7220436872  ..........or Chr  
plaintext: 000000000000000000666f7220436872  .........for Chr  
plaintext: 000000000000000020666f7220436872  ........ for Chr  
plaintext: 000000000000006520666f7220436872  .......e for Chr  
plaintext: 000000000000676520666f7220436872  ......ge for Chr  
plaintext: 00000000006e676520666f7220436872  .....nge for Chr  
plaintext: 00000000656e676520666f7220436872  ....enge for Chr  
plaintext: 0000006c656e676520666f7220436872  ...lenge for Chr  
plaintext: 00006c6c656e676520666f7220436872  ..llenge for Chr  
plaintext: 00616c6c656e676520666f7220436872  .allenge for Chr  
plaintext: 68616c6c656e676520666f7220436872  hallenge for Chr  
plaintext: 00000000000000000000000000000068  ...............h  
plaintext: 00000000000000000000000000007468  ..............th  
plaintext: 00000000000000000000000000207468  ............. th  
plaintext: 00000000000000000000000064207468  ............d th  
plaintext: 00000000000000000000006c64207468  ...........ld th  
plaintext: 00000000000000000000756c64207468  ..........uld th  
plaintext: 0000000000000000006f756c64207468  .........ould th  
plaintext: 0000000000000000576f756c64207468  ........Would th  
plaintext: 000000000000000a576f756c64207468  ........Would th  
plaintext: 0000000000002e0a576f756c64207468  ........Would th  
plaintext: 0000000000732e0a576f756c64207468  .....s..Would th  
plaintext: 0000000061732e0a576f756c64207468  ....as..Would th  
plaintext: 0000006d61732e0a576f756c64207468  ...mas..Would th  
plaintext: 0000746d61732e0a576f756c64207468  ..tmas..Would th  
plaintext: 0073746d61732e0a576f756c64207468  .stmas..Would th  
plaintext: 6973746d61732e0a576f756c64207468  istmas..Would th  
plaintext: 0000000000000000000000000000000a  ................  
plaintext: 00000000000000000000000000003f0a  ..............?.  
plaintext: 00000000000000000000000000653f0a  .............e?.  
plaintext: 0000000000000000000000006c653f0a  ............le?.  
plaintext: 0000000000000000000000626c653f0a  ...........ble?.  
plaintext: 0000000000000000000069626c653f0a  ..........ible?.  
plaintext: 0000000000000000007369626c653f0a  .........sible?.  
plaintext: 0000000000000000737369626c653f0a  ........ssible?.  
plaintext: 000000000000006f737369626c653f0a  .......ossible?.  
plaintext: 000000000000706f737369626c653f0a  ......possible?.  
plaintext: 000000000020706f737369626c653f0a  ..... possible?.  
plaintext: 000000006520706f737369626c653f0a  ....e possible?.  
plaintext: 000000626520706f737369626c653f0a  ...be possible?.  
plaintext: 000020626520706f737369626c653f0a  .. be possible?.  
plaintext: 007420626520706f737369626c653f0a  .t be possible?.  
plaintext: 617420626520706f737369626c653f0a  at be possible?.  
plaintext: 00000000000000000000000000000061  ...............a  
plaintext: 00000000000000000000000000006661  ..............fa  
plaintext: 00000000000000000000000000206661  ............. fa  
plaintext: 00000000000000000000000074206661  ............t fa  
plaintext: 00000000000000000000007374206661  ...........st fa  
plaintext: 00000000000000000000657374206661  ..........est fa  
plaintext: 00000000000000000067657374206661  .........gest fa  
plaintext: 00000000000000006767657374206661  ........ggest fa  
plaintext: 00000000000000696767657374206661  .......iggest fa  
plaintext: 00000000000062696767657374206661  ......biggest fa  
plaintext: 00000000002062696767657374206661  ..... biggest fa  
plaintext: 00000000722062696767657374206661  ....r biggest fa  
plaintext: 00000075722062696767657374206661  ...ur biggest fa  
plaintext: 00006f75722062696767657374206661  ..our biggest fa  
plaintext: 00596f75722062696767657374206661  .Your biggest fa  
plaintext: 0a596f75722062696767657374206661  .Your biggest fa  
plaintext: 0000000000000000000000000000003a  ...............:  
plaintext: 0000000000000000000000000000003a  ...............:  
plaintext: 0000000000000000000000000028003a  .............(.:  
plaintext: 0000000000000000000000006128003a  ............a(.:  
plaintext: 0000000000000000000000636128003a  ...........ca(.:  
plaintext: 0000000000000000000069636128003a  ..........ica(.:  
plaintext: 0000000000000000007369636128003a  .........sica(.:  
plaintext: 0000000000000000737369636128003a  ........ssica(.:  
plaintext: 0000000000000065737369636128003a  .......essica(.:  
plaintext: 0000000000004a65737369636128003a  ......Jessica(.:  
plaintext: 0000000000204a65737369636128003a  ..... Jessica(.:  
plaintext: 000000002d204a65737369636128003a  ....- Jessica(.:  
plaintext: 0000002d2d204a65737369636128003a  ...-- Jessica(.:  
plaintext: 00000a2d2d204a65737369636128003a  ...-- Jessica(.:  
plaintext: 002c0a2d2d204a65737369636128003a  .,.-- Jessica(.:  
plaintext: 6e2c0a2d2d204a65737369636128003a  n,.-- Jessica(.:  
plaintext: 0000000000000000000000000000006a  ...............j  
plaintext: 0000000000000000000000000000736a  ..............sj  
plaintext: 0000000000000000000000000044736a  .............Dsj  
plaintext: 0000000000000000000000004644736a  ............FDsj  
plaintext: 0000000000000000000000564644736a  ...........VFDsj  
plaintext: 0000000000000000000045564644736a  ..........EVFDsj  
plaintext: 0000000000000000006245564644736a  .........bEVFDsj  
plaintext: 0000000000000000636245564644736a  ........cbEVFDsj  
plaintext: 0000000000000041636245564644736a  .......AcbEVFDsj  
plaintext: 0000000000003441636245564644736a  ......4AcbEVFDsj  
plaintext: 00000000006e3441636245564644736a  .....n4AcbEVFDsj  
plaintext: 00000000696e3441636245564644736a  ....in4AcbEVFDsj  
plaintext: 0000004f696e3441636245564644736a  ...Oin4AcbEVFDsj  
plaintext: 0000364f696e3441636245564644736a  ..6Oin4AcbEVFDsj  
plaintext: 0058364f696e3441636245564644736a  .X6Oin4AcbEVFDsj  
plaintext: 1458364f696e3441636245564644736a  .X6Oin4AcbEVFDsj  
plaintext: 0000000000000000000000000000000b  ................  
plaintext: 00000000000000000000000000000b0b  ................  
plaintext: 000000000000000000000000000b0b0b  ................  
plaintext: 0000000000000000000000000b0b0b0b  ................  
plaintext: 00000000000000000000000b0b0b0b0b  ................  
plaintext: 000000000000000000000b0b0b0b0b0b  ................  
plaintext: 0000000000000000000b0b0b0b0b0b0b  ................  
plaintext: 00000000000000000b0b0b0b0b0b0b0b  ................  
plaintext: 000000000000000b0b0b0b0b0b0b0b0b  ................  
plaintext: 0000000000000b0b0b0b0b0b0b0b0b0b  ................  
plaintext: 00000000000b0b0b0b0b0b0b0b0b0b0b  ................  
plaintext: 00000000000b0b0b0b0b0b0b0b0b0b0b  ................  
plaintext: 00000063000b0b0b0b0b0b0b0b0b0b0b  ...c............  
plaintext: 00005063000b0b0b0b0b0b0b0b0b0b0b  ..Pc............  
plaintext: 00555063000b0b0b0b0b0b0b0b0b0b0b  .UPc............  
plaintext: 64555063000b0b0b0b0b0b0b0b0b0b0b  dUPc............  
```

We don't have to decrypt too many to see that the user "Jessica" requested
that Santa send her the flag for the challenge so we repeat the process a
third time to get the flag. This gives Santa's message to "Jessica" with the
flag:

```python  
solve_iv('Jessica')  
solved_iv = binascii.unhexlify('366d59132a5a6668686d4d544b623738')  
solve_list_messages('Jessica',solved_iv)  
solve_get_message('Jessica',solved_iv,0x511b)  
```

```  
$ ./challenge6.py  
Solve IV: Jessica  
plaintext: 00000000000000000000000000000038  ...............8  
plaintext: 00000000000000000000000000003738  ..............78  
plaintext: 00000000000000000000000000623738  .............b78  
plaintext: 0000000000000000000000004b623738  ............Kb78  
plaintext: 0000000000000000000000544b623738  ...........TKb78  
plaintext: 000000000000000000004d544b623738  ..........MTKb78  
plaintext: 0000000000000000006d4d544b623738  .........mMTKb78  
plaintext: 0000000000000000686d4d544b623738  ........hmMTKb78  
plaintext: 0000000000000068686d4d544b623738  .......hhmMTKb78  
plaintext: 0000000000006668686d4d544b623738  ......fhhmMTKb78  
plaintext: 00000000005a6668686d4d544b623738  .....ZfhhmMTKb78  
plaintext: 000000002a5a6668686d4d544b623738  ....*ZfhhmMTKb78  
plaintext: 000000132a5a6668686d4d544b623738  ....*ZfhhmMTKb78  
plaintext: 000059132a5a6668686d4d544b623738  ..Y.*ZfhhmMTKb78  
plaintext: 006d59132a5a6668686d4d544b623738  .mY.*ZfhhmMTKb78  
plaintext: 366d59132a5a6668686d4d544b623738  6mY.*ZfhhmMTKb78  
$ ./challenge6.py  
List Messages Jessica  
plaintext: 00000000000000000000000000000000  ................  
plaintext: 00000000000000000000000000000000  ................  
plaintext: 00000000000000000000000000510000  .............Q..  
plaintext: 0000000000000000000000001b510000  .............Q..  
plaintext: 00000000000000000000000c1b510000  .............Q..  
plaintext: 00000000000000000000320c1b510000  ..........2..Q..  
plaintext: 00000000000000000000320c1b510000  ..........2..Q..  
plaintext: 00000000000000002800320c1b510000  ........(.2..Q..  
plaintext: 00000000000000052800320c1b510000  ........(.2..Q..  
plaintext: 000000000000e0052800320c1b510000  ........(.2..Q..  
plaintext: 0000000000f5e0052800320c1b510000  ........(.2..Q..  
plaintext: 00000000d6f5e0052800320c1b510000  ........(.2..Q..  
plaintext: 000000c5d6f5e0052800320c1b510000  ........(.2..Q..  
plaintext: 000010c5d6f5e0052800320c1b510000  ........(.2..Q..  
plaintext: 000210c5d6f5e0052800320c1b510000  ........(.2..Q..  
plaintext: 080210c5d6f5e0052800320c1b510000  ........(.2..Q..  
plaintext: 00000000000000000000000000000079  ...............y  
plaintext: 00000000000000000000000000006c79  ..............ly  
plaintext: 00000000000000000000000000436c79  .............Cly  
plaintext: 00000000000000000000000079436c79  ............yCly  
plaintext: 00000000000000000000006f79436c79  ...........oyCly  
plaintext: 00000000000000000000706f79436c79  ..........poyCly  
plaintext: 00000000000000000014706f79436c79  ..........poyCly  
plaintext: 00000000000000003a14706f79436c79  ........:.poyCly  
plaintext: 00000000000000ff3a14706f79436c79  ........:.poyCly  
plaintext: 000000000000ffff3a14706f79436c79  ........:.poyCly  
plaintext: 0000000000ffffff3a14706f79436c79  ........:.poyCly  
plaintext: 00000000ffffffff3a14706f79436c79  ........:.poyCly  
plaintext: 000000ffffffffff3a14706f79436c79  ........:.poyCly  
plaintext: 0000ffffffffffff3a14706f79436c79  ........:.poyCly  
plaintext: 00ffffffffffffff3a14706f79436c79  ........:.poyCly  
plaintext: ffffffffffffffff3a14706f79436c79  ........:.poyCly  
plaintext: 00000000000000000000000000000002  ................  
plaintext: 00000000000000000000000000000202  ................  
plaintext: 00000000000000000000000000000202  ................  
plaintext: 00000000000000000000000057000202  ............W...  
plaintext: 00000000000000000000005a57000202  ...........ZW...  
plaintext: 000000000000000000004d5a57000202  ..........MZW...  
plaintext: 000000000000000000684d5a57000202  .........hMZW...  
plaintext: 000000000000000033684d5a57000202  ........3hMZW...  
plaintext: 000000000000007833684d5a57000202  .......x3hMZW...  
plaintext: 000000000000327833684d5a57000202  ......2x3hMZW...  
plaintext: 000000000041327833684d5a57000202  .....A2x3hMZW...  
plaintext: 000000005341327833684d5a57000202  ....SA2x3hMZW...  
plaintext: 000000785341327833684d5a57000202  ...xSA2x3hMZW...  
plaintext: 000037785341327833684d5a57000202  ..7xSA2x3hMZW...  
plaintext: 005537785341327833684d5a57000202  .U7xSA2x3hMZW...  
plaintext: 345537785341327833684d5a57000202  4U7xSA2x3hMZW...  
$ ./challenge6.py  
Get Message Jessica 20763 0x511b  
plaintext: 00000000000000000000000000000061  ...............a  
plaintext: 00000000000000000000000000006561  ..............ea  
plaintext: 00000000000000000000000000526561  .............Rea  
plaintext: 00000000000000000000000065526561  ............eRea  
plaintext: 00000000000000000000006865526561  ...........heRea  
plaintext: 00000000000000000000546865526561  ..........TheRea  
plaintext: 0000000000000000000c546865526561  ..........TheRea  
plaintext: 00000000000000001a0c546865526561  ..........TheRea  
plaintext: 00000000000000051a0c546865526561  ..........TheRea  
plaintext: 000000000000e0051a0c546865526561  ..........TheRea  
plaintext: 0000000000f2e0051a0c546865526561  ..........TheRea  
plaintext: 0000000089f2e0051a0c546865526561  ..........TheRea  
plaintext: 000000c189f2e0051a0c546865526561  ..........TheRea  
plaintext: 000010c189f2e0051a0c546865526561  ..........TheRea  
plaintext: 000310c189f2e0051a0c546865526561  ..........TheRea  
plaintext: 080310c189f2e0051a0c546865526561  ..........TheRea  
plaintext: 00000000000000000000000000000074  ...............t  
plaintext: 00000000000000000000000000002074  .............. t  
plaintext: 000000000000000000000000006f2074  .............o t  
plaintext: 0000000000000000000000006c6f2074  ............lo t  
plaintext: 00000000000000000000006c6c6f2074  ...........llo t  
plaintext: 00000000000000000000656c6c6f2074  ..........ello t  
plaintext: 00000000000000000048656c6c6f2074  .........Hello t  
plaintext: 00000000000000000248656c6c6f2074  .........Hello t  
plaintext: 00000000000000950248656c6c6f2074  .........Hello t  
plaintext: 00000000000022950248656c6c6f2074  ......"..Hello t  
plaintext: 00000000006122950248656c6c6f2074  .....a"..Hello t  
plaintext: 00000000746122950248656c6c6f2074  ....ta"..Hello t  
plaintext: 0000006e746122950248656c6c6f2074  ...nta"..Hello t  
plaintext: 0000616e746122950248656c6c6f2074  ..anta"..Hello t  
plaintext: 0053616e746122950248656c6c6f2074  .Santa"..Hello t  
plaintext: 6c53616e746122950248656c6c6f2074  lSanta"..Hello t  
plaintext: 00000000000000000000000000000049  ...............I  
plaintext: 00000000000000000000000000000a49  ...............I  
plaintext: 000000000000000000000000000a0a49  ...............I  
plaintext: 0000000000000000000000002c0a0a49  ............,..I  
plaintext: 0000000000000000000000612c0a0a49  ...........a,..I  
plaintext: 0000000000000000000063612c0a0a49  ..........ca,..I  
plaintext: 0000000000000000006963612c0a0a49  .........ica,..I  
plaintext: 0000000000000000736963612c0a0a49  ........sica,..I  
plaintext: 0000000000000073736963612c0a0a49  .......ssica,..I  
plaintext: 0000000000006573736963612c0a0a49  ......essica,..I  
plaintext: 00000000004a6573736963612c0a0a49  .....Jessica,..I  
plaintext: 00000000204a6573736963612c0a0a49  .... Jessica,..I  
plaintext: 00000065204a6573736963612c0a0a49  ...e Jessica,..I  
plaintext: 00007265204a6573736963612c0a0a49  ..re Jessica,..I  
plaintext: 00657265204a6573736963612c0a0a49  .ere Jessica,..I  
plaintext: 68657265204a6573736963612c0a0a49  here Jessica,..I  
plaintext: 00000000000000000000000000000020  ...............  
plaintext: 00000000000000000000000000006b20  ..............k  
plaintext: 000000000000000000000000006f6b20  .............ok  
plaintext: 0000000000000000000000006f6f6b20  ............ook  
plaintext: 0000000000000000000000626f6f6b20  ...........book  
plaintext: 0000000000000000000020626f6f6b20  .......... book  
plaintext: 0000000000000000007920626f6f6b20  .........y book  
plaintext: 00000000000000006d7920626f6f6b20  ........my book  
plaintext: 00000000000000206d7920626f6f6b20  ....... my book  
plaintext: 0000000000006e206d7920626f6f6b20  ......n my book  
plaintext: 0000000000696e206d7920626f6f6b20  .....in my book  
plaintext: 0000000020696e206d7920626f6f6b20  .... in my book  
plaintext: 0000006520696e206d7920626f6f6b20  ...e in my book  
plaintext: 0000656520696e206d7920626f6f6b20  ..ee in my book  
plaintext: 0073656520696e206d7920626f6f6b20  .see in my book  
plaintext: 2073656520696e206d7920626f6f6b20   see in my book  
plaintext: 0000000000000000000000000000006f  ...............o  
plaintext: 00000000000000000000000000006e6f  ..............no  
plaintext: 00000000000000000000000000206e6f  ............. no  
plaintext: 00000000000000000000000065206e6f  ............e no  
plaintext: 00000000000000000000007665206e6f  ...........ve no  
plaintext: 00000000000000000000617665206e6f  ..........ave no  
plaintext: 00000000000000000068617665206e6f  .........have no  
plaintext: 00000000000000002068617665206e6f  ........ have no  
plaintext: 00000000000000752068617665206e6f  .......u have no  
plaintext: 0000000000006f752068617665206e6f  ......ou have no  
plaintext: 0000000000796f752068617665206e6f  .....you have no  
plaintext: 0000000020796f752068617665206e6f  .... you have no  
plaintext: 0000007420796f752068617665206e6f  ...t you have no  
plaintext: 0000617420796f752068617665206e6f  ..at you have no  
plaintext: 0068617420796f752068617665206e6f  .hat you have no  
plaintext: 7468617420796f752068617665206e6f  that you have no  
plaintext: 00000000000000000000000000000074  ...............t  
plaintext: 00000000000000000000000000002074  .............. t  
plaintext: 00000000000000000000000000792074  .............y t  
plaintext: 00000000000000000000000074792074  ............ty t  
plaintext: 00000000000000000000006874792074  ...........hty t  
plaintext: 00000000000000000000676874792074  ..........ghty t  
plaintext: 00000000000000000075676874792074  .........ughty t  
plaintext: 00000000000000006175676874792074  ........aughty t  
plaintext: 000000000000006e6175676874792074  .......naughty t  
plaintext: 000000000000206e6175676874792074  ...... naughty t  
plaintext: 00000000006e206e6175676874792074  .....n naughty t  
plaintext: 00000000656e206e6175676874792074  ....en naughty t  
plaintext: 00000065656e206e6175676874792074  ...een naughty t  
plaintext: 00006265656e206e6175676874792074  ..been naughty t  
plaintext: 00206265656e206e6175676874792074  . been naughty t  
plaintext: 74206265656e206e6175676874792074  t been naughty t  
plaintext: 0000000000000000000000000000006f  ...............o  
plaintext: 0000000000000000000000000000796f  ..............yo  
plaintext: 0000000000000000000000000020796f  ............. yo  
plaintext: 0000000000000000000000006420796f  ............d yo  
plaintext: 00000000000000000000006e6420796f  ...........nd yo  
plaintext: 00000000000000000000616e6420796f  ..........and yo  
plaintext: 0000000000000000000a616e6420796f  ..........and yo  
plaintext: 00000000000000002c0a616e6420796f  ........,.and yo  
plaintext: 00000000000000722c0a616e6420796f  .......r,.and yo  
plaintext: 00000000000061722c0a616e6420796f  ......ar,.and yo  
plaintext: 00000000006561722c0a616e6420796f  .....ear,.and yo  
plaintext: 00000000796561722c0a616e6420796f  ....year,.and yo  
plaintext: 00000020796561722c0a616e6420796f  ... year,.and yo  
plaintext: 00007320796561722c0a616e6420796f  ..s year,.and yo  
plaintext: 00697320796561722c0a616e6420796f  .is year,.and yo  
plaintext: 68697320796561722c0a616e6420796f  his year,.and yo  
plaintext: 00000000000000000000000000000020  ...............  
plaintext: 00000000000000000000000000006420  ..............d  
plaintext: 000000000000000000000000006c6420  .............ld  
plaintext: 000000000000000000000000756c6420  ............uld  
plaintext: 00000000000000000000006f756c6420  ...........ould  
plaintext: 00000000000000000000776f756c6420  ..........would  
plaintext: 00000000000000000020776f756c6420  ......... would  
plaintext: 00000000000000007520776f756c6420  ........u would  
plaintext: 000000000000006f7520776f756c6420  .......ou would  
plaintext: 000000000000796f7520776f756c6420  ......you would  
plaintext: 000000000020796f7520776f756c6420  ..... you would  
plaintext: 000000007920796f7520776f756c6420  ....y you would  
plaintext: 000000617920796f7520776f756c6420  ...ay you would  
plaintext: 000073617920796f7520776f756c6420  ..say you would  
plaintext: 002073617920796f7520776f756c6420  . say you would  
plaintext: 752073617920796f7520776f756c6420  u say you would  
plaintext: 0000000000000000000000000000006f  ...............o  
plaintext: 0000000000000000000000000000666f  ..............fo  
plaintext: 0000000000000000000000000020666f  ............. fo  
plaintext: 0000000000000000000000006720666f  ............g fo  
plaintext: 0000000000000000000000616720666f  ...........ag fo  
plaintext: 000000000000000000006c616720666f  ..........lag fo  
plaintext: 000000000000000000666c616720666f  .........flag fo  
plaintext: 000000000000000020666c616720666f  ........ flag fo  
plaintext: 000000000000006520666c616720666f  .......e flag fo  
plaintext: 000000000000686520666c616720666f  ......he flag fo  
plaintext: 000000000074686520666c616720666f  .....the flag fo  
plaintext: 000000002074686520666c616720666f  .... the flag fo  
plaintext: 000000652074686520666c616720666f  ...e the flag fo  
plaintext: 00006b652074686520666c616720666f  ..ke the flag fo  
plaintext: 00696b652074686520666c616720666f  .ike the flag fo  
plaintext: 6c696b652074686520666c616720666f  like the flag fo  
plaintext: 00000000000000000000000000000063  ...............c  
plaintext: 00000000000000000000000000002063  .............. c  
plaintext: 00000000000000000000000000612063  .............a c  
plaintext: 00000000000000000000000074612063  ............ta c  
plaintext: 00000000000000000000006e74612063  ...........nta c  
plaintext: 00000000000000000000616e74612063  ..........anta c  
plaintext: 00000000000000000073616e74612063  .........santa c  
plaintext: 00000000000000007073616e74612063  ........psanta c  
plaintext: 00000000000000647073616e74612063  .......dpsanta c  
plaintext: 00000000000075647073616e74612063  ......udpsanta c  
plaintext: 00000000002075647073616e74612063  ..... udpsanta c  
plaintext: 00000000652075647073616e74612063  ....e udpsanta c  
plaintext: 00000068652075647073616e74612063  ...he udpsanta c  
plaintext: 00007468652075647073616e74612063  ..the udpsanta c  
plaintext: 00207468652075647073616e74612063  . the udpsanta c  
plaintext: 72207468652075647073616e74612063  r the udpsanta c  
plaintext: 00000000000000000000000000000072  ...............r  
plaintext: 00000000000000000000000000006872  ..............hr  
plaintext: 00000000000000000000000000436872  .............Chr  
plaintext: 00000000000000000000000020436872  ............ Chr  
plaintext: 00000000000000000000007220436872  ...........r Chr  
plaintext: 000000000000000000006f7220436872  ..........or Chr  
plaintext: 000000000000000000666f7220436872  .........for Chr  
plaintext: 000000000000000020666f7220436872  ........ for Chr  
plaintext: 000000000000006520666f7220436872  .......e for Chr  
plaintext: 000000000000676520666f7220436872  ......ge for Chr  
plaintext: 00000000006e676520666f7220436872  .....nge for Chr  
plaintext: 00000000656e676520666f7220436872  ....enge for Chr  
plaintext: 0000006c656e676520666f7220436872  ...lenge for Chr  
plaintext: 00006c6c656e676520666f7220436872  ..llenge for Chr  
plaintext: 00616c6c656e676520666f7220436872  .allenge for Chr  
plaintext: 68616c6c656e676520666f7220436872  hallenge for Chr  
plaintext: 00000000000000000000000000000073  ...............s  
plaintext: 00000000000000000000000000007273  ..............rs  
plaintext: 00000000000000000000000000757273  .............urs  
plaintext: 0000000000000000000000006f757273  ............ours  
plaintext: 0000000000000000000000636f757273  ...........cours  
plaintext: 0000000000000000000020636f757273  .......... cours  
plaintext: 0000000000000000006620636f757273  .........f cours  
plaintext: 00000000000000004f6620636f757273  ........Of cours  
plaintext: 000000000000000a4f6620636f757273  ........Of cours  
plaintext: 0000000000003f0a4f6620636f757273  ......?.Of cours  
plaintext: 0000000000733f0a4f6620636f757273  .....s?.Of cours  
plaintext: 0000000061733f0a4f6620636f757273  ....as?.Of cours  
plaintext: 0000006d61733f0a4f6620636f757273  ...mas?.Of cours  
plaintext: 0000746d61733f0a4f6620636f757273  ..tmas?.Of cours  
plaintext: 0073746d61733f0a4f6620636f757273  .stmas?.Of cours  
plaintext: 6973746d61733f0a4f6620636f757273  istmas?.Of cours  
plaintext: 00000000000000000000000000000041  ...............A  
plaintext: 00000000000000000000000000002041  .............. A  
plaintext: 00000000000000000000000000732041  .............s A  
plaintext: 00000000000000000000000069732041  ............is A  
plaintext: 00000000000000000000002069732041  ........... is A  
plaintext: 00000000000000000000672069732041  ..........g is A  
plaintext: 00000000000000000061672069732041  .........ag is A  
plaintext: 00000000000000006c61672069732041  ........lag is A  
plaintext: 00000000000000666c61672069732041  .......flag is A  
plaintext: 00000000000020666c61672069732041  ...... flag is A  
plaintext: 00000000006520666c61672069732041  .....e flag is A  
plaintext: 00000000686520666c61672069732041  ....he flag is A  
plaintext: 00000054686520666c61672069732041  ...The flag is A  
plaintext: 00002054686520666c61672069732041  .. The flag is A  
plaintext: 00212054686520666c61672069732041  .! The flag is A  
plaintext: 65212054686520666c61672069732041  e! The flag is A  
plaintext: 0000000000000000000000000000005f  ..............._  
plaintext: 0000000000000000000000000000735f  ..............s_  
plaintext: 0000000000000000000000000061735f  .............as_  
plaintext: 0000000000000000000000006161735f  ............aas_  
plaintext: 00000000000000000000006c6161735f  ...........laas_  
plaintext: 000000000000000000006b6c6161735f  ..........klaas_  
plaintext: 000000000000000000726b6c6161735f  .........rklaas_  
plaintext: 000000000000000065726b6c6161735f  ........erklaas_  
plaintext: 000000000000007465726b6c6161735f  .......terklaas_  
plaintext: 0000000000006e7465726b6c6161735f  ......nterklaas_  
plaintext: 0000000000696e7465726b6c6161735f  .....interklaas_  
plaintext: 0000000053696e7465726b6c6161735f  ....Sinterklaas_  
plaintext: 0000007b53696e7465726b6c6161735f  ...{Sinterklaas_  
plaintext: 0000577b53696e7465726b6c6161735f  ..W{Sinterklaas_  
plaintext: 0054577b53696e7465726b6c6161735f  .TW{Sinterklaas_  
plaintext: 4f54577b53696e7465726b6c6161735f  OTW{Sinterklaas_  
plaintext: 00000000000000000000000000000061  ...............a  
plaintext: 00000000000000000000000000007061  ..............pa  
plaintext: 00000000000000000000000000537061  .............Spa  
plaintext: 0000000000000000000000005f537061  ............_Spa  
plaintext: 0000000000000000000000795f537061  ...........y_Spa  
plaintext: 000000000000000000006d795f537061  ..........my_Spa  
plaintext: 0000000000000000005f6d795f537061  ........._my_Spa  
plaintext: 00000000000000007a5f6d795f537061  ........z_my_Spa  
plaintext: 00000000000000697a5f6d795f537061  .......iz_my_Spa  
plaintext: 0000000000005f697a5f6d795f537061  ......_iz_my_Spa  
plaintext: 0000000000795f697a5f6d795f537061  .....y_iz_my_Spa  
plaintext: 000000006c795f697a5f6d795f537061  ....ly_iz_my_Spa  
plaintext: 0000006c6c795f697a5f6d795f537061  ...lly_iz_my_Spa  
plaintext: 0000616c6c795f697a5f6d795f537061  ..ally_iz_my_Spa  
plaintext: 0065616c6c795f697a5f6d795f537061  .eally_iz_my_Spa  
plaintext: 7265616c6c795f697a5f6d795f537061  really_iz_my_Spa  
plaintext: 0000000000000000000000000000002e  ................  
plaintext: 00000000000000000000000000007d2e  ..............}.  
plaintext: 000000000000000000000000002e7d2e  ..............}.  
plaintext: 0000000000000000000000002e2e7d2e  ..............}.  
plaintext: 00000000000000000000002e2e2e7d2e  ..............}.  
plaintext: 000000000000000000006e2e2e2e7d2e  ..........n...}.  
plaintext: 000000000000000000696e2e2e2e7d2e  .........in...}.  
plaintext: 000000000000000073696e2e2e2e7d2e  ........sin...}.  
plaintext: 000000000000007573696e2e2e2e7d2e  .......usin...}.  
plaintext: 0000000000006f7573696e2e2e2e7d2e  ......ousin...}.  
plaintext: 0000000000636f7573696e2e2e2e7d2e  .....cousin...}.  
plaintext: 000000005f636f7573696e2e2e2e7d2e  ...._cousin...}.  
plaintext: 000000685f636f7573696e2e2e2e7d2e  ...h_cousin...}.  
plaintext: 000073685f636f7573696e2e2e2e7d2e  ..sh_cousin...}.  
plaintext: 006973685f636f7573696e2e2e2e7d2e  .ish_cousin...}.  
plaintext: 6e6973685f636f7573696e2e2e2e7d2e  nish_cousin...}.  
plaintext: 00000000000000000000000000000069  ...............i  
plaintext: 00000000000000000000000000007769  ..............wi  
plaintext: 00000000000000000000000000207769  ............. wi  
plaintext: 00000000000000000000000074207769  ............t wi  
plaintext: 00000000000000000000007374207769  ...........st wi  
plaintext: 00000000000000000000657374207769  ..........est wi  
plaintext: 00000000000000000062657374207769  .........best wi  
plaintext: 00000000000000002062657374207769  ........ best wi  
plaintext: 00000000000000792062657374207769  .......y best wi  
plaintext: 0000000000006d792062657374207769  ......my best wi  
plaintext: 0000000000206d792062657374207769  ..... my best wi  
plaintext: 000000006c206d792062657374207769  ....l my best wi  
plaintext: 0000006c6c206d792062657374207769  ...ll my best wi  
plaintext: 0000416c6c206d792062657374207769  ..All my best wi  
plaintext: 000a416c6c206d792062657374207769  ..All my best wi  
plaintext: 0a0a416c6c206d792062657374207769  ..All my best wi  
plaintext: 0000000000000000000000000000000a  ................  
plaintext: 00000000000000000000000000002c0a  ..............,.  
plaintext: 000000000000000000000000006f2c0a  .............o,.  
plaintext: 000000000000000000000000486f2c0a  ............Ho,.  
plaintext: 000000000000000000000020486f2c0a  ........... Ho,.  
plaintext: 000000000000000000006f20486f2c0a  ..........o Ho,.  
plaintext: 000000000000000000486f20486f2c0a  .........Ho Ho,.  
plaintext: 000000000000000020486f20486f2c0a  ........ Ho Ho,.  
plaintext: 000000000000006f20486f20486f2c0a  .......o Ho Ho,.  
plaintext: 000000000000486f20486f20486f2c0a  ......Ho Ho Ho,.  
plaintext: 00000000000a486f20486f20486f2c0a  ......Ho Ho Ho,.  
plaintext: 000000002c0a486f20486f20486f2c0a  ....,.Ho Ho Ho,.  
plaintext: 000000732c0a486f20486f20486f2c0a  ...s,.Ho Ho Ho,.  
plaintext: 000065732c0a486f20486f20486f2c0a  ..es,.Ho Ho Ho,.  
plaintext: 006865732c0a486f20486f20486f2c0a  .hes,.Ho Ho Ho,.  
plaintext: 736865732c0a486f20486f20486f2c0a  shes,.Ho Ho Ho,.  
plaintext: 00000000000000000000000000000000  ................  
plaintext: 00000000000000000000000000002800  ..............(.  
plaintext: 00000000000000000000000000732800  .............s(.  
plaintext: 00000000000000000000000075732800  ............us(.  
plaintext: 00000000000000000000006175732800  ...........aus(.  
plaintext: 000000000000000000006c6175732800  ..........laus(.  
plaintext: 000000000000000000436c6175732800  .........Claus(.  
plaintext: 000000000000000020436c6175732800  ........ Claus(.  
plaintext: 000000000000006120436c6175732800  .......a Claus(.  
plaintext: 000000000000746120436c6175732800  ......ta Claus(.  
plaintext: 00000000006e746120436c6175732800  .....nta Claus(.  
plaintext: 00000000616e746120436c6175732800  ....anta Claus(.  
plaintext: 00000053616e746120436c6175732800  ...Santa Claus(.  
plaintext: 00002053616e746120436c6175732800  .. Santa Claus(.  
plaintext: 002d2053616e746120436c6175732800  .- Santa Claus(.  
plaintext: 2d2d2053616e746120436c6175732800  -- Santa Claus(.  
plaintext: 0000000000000000000000000000005a  ...............Z  
plaintext: 0000000000000000000000000000375a  ..............7Z  
plaintext: 0000000000000000000000000038375a  .............87Z  
plaintext: 0000000000000000000000005838375a  ............X87Z  
plaintext: 0000000000000000000000765838375a  ...........vX87Z  
plaintext: 0000000000000000000077765838375a  ..........wvX87Z  
plaintext: 0000000000000000004477765838375a  .........DwvX87Z  
plaintext: 0000000000000000694477765838375a  ........iDwvX87Z  
plaintext: 0000000000000054694477765838375a  .......TiDwvX87Z  
plaintext: 0000000000006f54694477765838375a  ......oTiDwvX87Z  
plaintext: 0000000000736f54694477765838375a  .....soTiDwvX87Z  
plaintext: 0000000050736f54694477765838375a  ....PsoTiDwvX87Z  
plaintext: 0000004150736f54694477765838375a  ...APsoTiDwvX87Z  
plaintext: 0000494150736f54694477765838375a  ..IAPsoTiDwvX87Z  
plaintext: 0014494150736f54694477765838375a  ..IAPsoTiDwvX87Z  
plaintext: 3a14494150736f54694477765838375a  :.IAPsoTiDwvX87Z  
plaintext: 0000000000000000000000000000000a  ................  
plaintext: 00000000000000000000000000000a0a  ................  
plaintext: 000000000000000000000000000a0a0a  ................  
plaintext: 0000000000000000000000000a0a0a0a  ................  
plaintext: 00000000000000000000000a0a0a0a0a  ................  
plaintext: 000000000000000000000a0a0a0a0a0a  ................  
plaintext: 0000000000000000000a0a0a0a0a0a0a  ................  
plaintext: 00000000000000000a0a0a0a0a0a0a0a  ................  
plaintext: 000000000000000a0a0a0a0a0a0a0a0a  ................  
plaintext: 0000000000000a0a0a0a0a0a0a0a0a0a  ................  
plaintext: 0000000000000a0a0a0a0a0a0a0a0a0a  ................  
plaintext: 0000000051000a0a0a0a0a0a0a0a0a0a  ....Q...........  
plaintext: 0000003951000a0a0a0a0a0a0a0a0a0a  ...9Q...........  
plaintext: 0000613951000a0a0a0a0a0a0a0a0a0a  ..a9Q...........  
plaintext: 0074613951000a0a0a0a0a0a0a0a0a0a  .ta9Q...........  
plaintext: 6c74613951000a0a0a0a0a0a0a0a0a0a  lta9Q...........  
```

Included in that message is the flag we need for the solution
`AOTW{Sinterklaas_really_iz_my_Spanish_cousin...}`  

Original writeup
(https://github.com/nononovak/otwadvent2018-ctfwriteup/blob/master/day6.md).