# DragonSector 2021 - EasyNFT

## Introduction

The challenge gives us a domain `easynft.hackable.software` and a Tarball
([files.tar.gz](./files.tar.gz)), which contains an
[easynft.pcap](./task/easynft.pcap) and a [README.md](./task/README.md)

The `README.md` state:

```  
One of our servers is acting strangely lately.  
There are even rumours that it gives out flags if [asked in a right
way](https://xkcd.com/424/).

Our forensic team didn't find any backdoors, but when we try to list firewall
rules, `nft` just hangs.  
The best we could get is this the netlink dump attached in easynft.pcap.

Could you help us figure out what's going on?

P.S. Obviously, the flag was redacted from the dump.  
```

So apparently, the pcap contains traces of interactions between the `nft`
binary and the `netfilters` backend.

## Pcap analysis

Quickly scanning the capture with wireshark, we identify the typical keywords
from a routing table (`filter`, `input`, `output`, `forward`...), several
interesting keywords (`flag`, `hack`) and a fake flag
`dnrgs{REDACTEDREDACTEDREDACTEDREDACTED}`.

The rest of the data seems binary and we cannot get much more from the
capture.

We also notice that all packets start with a constant **16 bytes** `Linux
netlink (cooked header)`, followed by a variable length and content `Netlink
message`.

## Decoding the packets

My `tshark` jutsu isn't that great, so we start by dumping the whole capture
with an hexdump of each packets:

```  
tshark -r easynft.pcap -x  
```

And we clean it up to keep only the hex bytes on a single line

```  
tshark -r easynft.pcap -x | grep -v "0000" | awk -F "  " '{print $2}' | tr -d ' ' | perl -00 -lpe 'tr/\n//d' | grep -Ev '^\s* > easynft_netlink.dump  
```

We now have a 23 lines file with the `Netlink messages` ready to parse. (see
[easynft_netlink.dump](./easynft_netlink.dump))

As I usually pick go as my first language choice, I've found the
`github.com/mdlayher/netlink` library exposing a promising
[Message.UnmarshalBinary([]byte)
error](https://pkg.go.dev/github.com/mdlayher/[email protected]?utm_source=gopls#Message.UnmarshalBinary)
method we could feed with our packet bytes and see what happen.

We also notice when checking the source code of this method, that the first 4
bytes of the message are **its length**. And some of the packet hex strings
contains more bytes than these first bytes indicate. This means we can have
multiple `netlink.Message` per packet.

From here, the parsing code is quite straigtforward:

```go  
package main

import (  
	"bufio"  
	"encoding/binary"  
	"encoding/hex"  
	"fmt"  
	"os"

	"github.com/mdlayher/netlink"  
)

func main() {  
	f, err := os.Open("hex_netlink.dump")  
	if err != nil {  
		panic(err)  
	}  
	defer f.Close()

	scanner := bufio.NewScanner(f)  
	var messages []netlink.Message

	for scanner.Scan() {  
		packetHex := scanner.Text()

		d, err := hex.DecodeString(packetHex)  
		if err != nil {  
			panic(err)  
		}

		// packet may contains multiple messages, so split on size  
       // https://github.com/mdlayher/netlink/blob/v1.4.1/message.go#L234  
		for {  
			size := binary.LittleEndian.Uint32(d[:4])

			packet := d  
			if len(d) > int(size) {  
				packet = d[:size]  
			}  
			d = d[size:]

			msg := netlink.Message{}  
			if err := msg.UnmarshalBinary(packet); err != nil {  
				panic(fmt.Errorf("failed to unmarshal: %v - packet: %x", err, d))  
			}

			messages = append(messages, msg)  
			if len(d) == 0 {  
				break  
			}  
		}  
	}

	fmt.Printf("Parsed %d messages\n", len(messages))  
	for _, m := range messages {  
		fmt.Printf("%#v\n", m)  
	}  
}  
```

As an output, we get **28 decoded `netlink.Message`**

```  
Parsed 28 messages  
netlink.Message{Header:netlink.Header{Length:0x14, Type:0xa10, Flags:0x1,
Sequence:0x0, PID:0x0}, Data:[]uint8{0x0, 0x0, 0x0, 0x0}}  
netlink.Message{Header:netlink.Header{Length:0x2c, Type:0xa0f, Flags:0x0,
Sequence:0x0, PID:0x200a}, Data:[]uint8{0x0, 0x0, 0xbb, 0x75, 0x8, 0x0, 0x1,
0x0, 0x0, 0x0, 0xbb, 0x75, 0x8, 0x0, 0x2, 0x0, 0x0, 0x0, 0x20, 0xa, 0x8, 0x0,
0x3, 0x0, 0x6e, 0x66, 0x74, 0x0}}  
netlink.Message{Header:netlink.Header{Length:0x14, Type:0xa01, Flags:0x301,
Sequence:0x0, PID:0x0}, Data:[]uint8{0x0, 0x0, 0x0, 0x0}}  
...truncated...  
```

We now have more raw bytes in the `Data` field, which the `Type` field could
help us identify and understand further.

## Identifying Netlink messages

From the pcap, we saw wireshark identified the messages are using the `netlink
netfilter` protocol. Turns out `netfilter` is a sub component of the whole
netfilter framework, responsible of the packet routing. Luckily, another
library exists extending the netlink's one, to provide us the netfilter
decoding features, such as [unmarshalling netlink messages into netfilter
header and attributes](https://pkg.go.dev/github.com/ti-
mo/[email protected]?utm_source=gopls#UnmarshalNetlink)

We can update our previous loop over the messages to add the netfilter
decoding:

```go  
   // add import "github.com/ti-mo/netfilter"  
   fmt.Printf("Parsed %d messages\n", len(messages))  
	for _, m := range messages {  
		header, attrs, err := netfilter.UnmarshalNetlink(m)  
		if err != nil {  
			panic(err)  
		}  
		fmt.Printf("%s\n", header)  
		for _, attr := range attrs {  
			fmt.Printf("\t%s\n", attr.String())  
		}  
	}  
```

This start giving us a bit more info on what's going on:

```  
Parsed 28 messages  
<Subsystem: NFSubsysNFTables, Message Type: 16, Family: ProtoUnspec, Version:
0, ResourceID: 0>  
<Subsystem: NFSubsysNFTables, Message Type: 15, Family: ProtoUnspec, Version:
0, ResourceID: 47989>  
       <Length 4, Type 1, Nested false, NetByteOrder false, [0 0 187 117]>  
       <Length 4, Type 2, Nested false, NetByteOrder false, [0 0 32 10]>  
       <Length 4, Type 3, Nested false, NetByteOrder false, [110 102 116 0]>  
<Subsystem: NFSubsysNFTables, Message Type: 1, Family: ProtoUnspec, Version:
0, ResourceID: 0>  
<Subsystem: NFSubsysNFTables, Message Type: 0, Family: ProtoIPv4, Version: 0,
ResourceID: 47989>  
       <Length 7, Type 1, Nested false, NetByteOrder false, [102 105 108 116 101 114 0]>  
       <Length 4, Type 2, Nested false, NetByteOrder false, [0 0 0 0]>  
       <Length 4, Type 3, Nested false, NetByteOrder false, [0 0 0 5]>  
       <Length 8, Type 4, Nested false, NetByteOrder false, [0 0 0 0 0 0 0 150]>  
<Subsystem: NFSubsysNone, Message Type: 3, Family: ProtoUnspec, Version: 0,
ResourceID: 0>  
...truncated...  
```

Now, it's time to start trying to understand these message types. This has
been a quite long search, which eventually ended in the linux kernel sources,
on the magic `nf_tables_msg_types` enum. (see
[nf_tables.h#L101](https://elixir.bootlin.com/linux/v5.15.5/source/include/uapi/linux/netfilter/nf_tables.h#L101)).

Using the kernel sources comments and navigating the various enum, we end up
replicating them to allow looking up those meaningfull names in place of the
message types using 2 global variables:

```go  
//
https://elixir.bootlin.com/linux/v5.15.5/source/include/uapi/linux/netfilter/nf_tables.h#L101  
var messageTypeNames = []string{  
	"NFT_MSG_NEWTABLE",  
	"NFT_MSG_GETTABLE",  
	"NFT_MSG_DELTABLE",  
	"NFT_MSG_NEWCHAIN",  
	"NFT_MSG_GETCHAIN",  
	"NFT_MSG_DELCHAIN",  
	"NFT_MSG_NEWRULE",  
	"NFT_MSG_GETRULE",  
	// ... truncated ...  
}

var attributeTypeNames = map[string][]string{  
	"NFT_MSG_NEWGEN": { // https://elixir.bootlin.com/linux/v5.15.5/source/include/uapi/linux/netfilter/nf_tables.h#L1505  
		"NFTA_GEN_UNSPEC",  
		"NFTA_GEN_ID",  
		"NFTA_GEN_PROC_PID",  
		"NFTA_GEN_PROC_NAME",  
	},  
	"NFT_MSG_NEWTABLE": { // https://elixir.bootlin.com/linux/v5.15.5/source/include/uapi/linux/netfilter/nf_tables.h#L181  
		"NFTA_TABLE_UNSPEC",  
		"NFTA_TABLE_NAME",  
		"NFTA_TABLE_FLAGS",  
		"NFTA_TABLE_USE",  
		"NFTA_TABLE_HANDLE",  
		"NFTA_TABLE_PAD",  
		"NFTA_TABLE_USERDATA",  
		"NFTA_TABLE_OWNER",  
		"__NFTA_TABLE_MAx",  
	},  
	"NFT_MSG_NEWCHAIN": { // https://elixir.bootlin.com/linux/v5.15.5/source/include/uapi/linux/netfilter/nf_tables.h#L218  
		"NFTA_CHAIN_UNSPEC",  
		"NFTA_CHAIN_TABLE",  
		"NFTA_CHAIN_HANDLE",  
		"NFTA_CHAIN_NAME",  
		"NFTA_CHAIN_HOOK",  
		"NFTA_CHAIN_POLICY",  
   // ... truncated ...  
}  
```

Now we update our loop once again to make use of those pretty names:

```go  
   fmt.Printf("Parsed %d messages\n", len(messages))  
	for _, m := range messages {  
		header, attrs, err := netfilter.UnmarshalNetlink(m)  
		if err != nil {  
			panic(err)  
		}  
       // lookup message name from its message type  
		fmt.Printf("%s\n", messageTypeNames[header.MessageType])  
		for _, attr := range attrs {  
           // lookup attribute name from its message type and attribute type  
           // or just keep default string repr if no name exists  
			attributeName := attr.String()   
			attrNames, ok := attributeTypeNames[messageTypeNames[header.MessageType]]  
			if ok {  
				attributeName = attrNames[int(attr.Type)]  
			}  
			fmt.Printf("\t%s - %q\n", attributeName, attr.Data)  
		}  
	}  
```

and tada! we can now put some sense on all of that:

```  
Parsed 28 messages  
NFT_MSG_GETGEN  
NFT_MSG_NEWGEN  
       NFTA_GEN_ID - "\x00\x00\xbbu"  
       NFTA_GEN_PROC_PID - "\x00\x00 \n"  
       NFTA_GEN_PROC_NAME - "nft\x00"  
NFT_MSG_GETTABLE  
NFT_MSG_NEWTABLE  
       NFTA_TABLE_NAME - "filter\x00"  
       NFTA_TABLE_FLAGS - "\x00\x00\x00\x00"  
       NFTA_TABLE_USE - "\x00\x00\x00\x05"  
       NFTA_TABLE_HANDLE - "\x00\x00\x00\x00\x00\x00\x00\x96"  
NFT_MSG_NEWCHAIN  
NFT_MSG_GETCHAIN  
NFT_MSG_NEWCHAIN  
       NFTA_CHAIN_TABLE - "filter\x00"  
       NFTA_CHAIN_HANDLE - "\x00\x00\x00\x00\x00\x00\x00\x01"  
       NFTA_CHAIN_NAME - "input\x00"  
... truncated ...  
```

From here, we clearly see client requests (such as the one issued using the
`nft` commands - `NFT_MSG_GET...`) and server response (`NFT_MSG_NEW...`),
which then get parsed by `nft` to display tables, rules or whatever was
requested to the terminal.

So we now start to see some human readable table, chains, rules and other
pieces of a routing table:

```  
filter {  
   # chains  
   input {}  
   forward {}  
   output {  
       # rule 0x5  
   }  
   hack {  
       # rule 0xa  
   }  
  
   # set  
   flag {  
       # fake flag stored here  
   }  
}  
```

We're now having **2 rules** and a **set** still containing raw binary that we
have to decode further the attributes.  
Some of these attributes clearly contains multiple sub-attributes, so we can
write a simple function to decode them all:

```go  
func printAttrRecursive(data []byte, level int) {  
	attrs, err := netfilter.UnmarshalAttributes(data)  
	if err != nil {  
		return  
	}

	for _, attr := range attrs {  
		if len(attr.Data) > 0 {  
			fmt.Printf("%sType: %d: %q\n", strings.Repeat("\t", level), attr.Type, attr.Data)  
			printAttrRecursive(attr.Data, level+1)  
		}  
	}  
}  
```

and update our previous loop on attributes:

```go  
       fmt.Printf("%s\n", messageTypeNames[header.MessageType])  
		for _, attr := range attrs {  
			// lookup attribute name from its message type and attribute type  
			// or just keep default string repr if no name exists  
			attributeName := attr.String()  
			attrNames, ok := attributeTypeNames[messageTypeNames[header.MessageType]]  
			if ok {  
				attributeName = attrNames[int(attr.Type)]  
			}

			switch attributeName {  
			case "NFTA_SET_ELEM_LIST_ELEMENTS":  
				fmt.Printf("\t%s\n", attributeName)  
				printAttrRecursive(attr.Data, 2)  
			case "NFTA_RULE_EXPRESSIONS":  
				fmt.Printf("\t%s\n", attributeName)  
				printAttrRecursive(attr.Data, 2)  
			default:  
				fmt.Printf("\t%s - %q\n", attributeName, attr.Data)  
			}  
		}  
```

- Program sources: [./netlinkdump/main.go](./netlinkdump/main.go)  
- Program output: [./netlink.dump](./netlink.dump)

## Decoding the full routing table

Now we'll start manually replacing the various types with their constant
names, by looking up the parent in the kernel sources.

We end up with a nice decoded routing table, after looking up every enum
values / structs for all kind of attributes such as:

- nft_immediate_attributes: https://elixir.bootlin.com/linux/v5.15.5/source/include/uapi/linux/netfilter/nf_tables.h#L531  
- nft_cmp_attributes: https://elixir.bootlin.com/linux/v5.15.5/source/include/uapi/linux/netfilter/nf_tables.h#L648  
- nft_cmp_ops: https://elixir.bootlin.com/linux/v5.15.5/source/include/uapi/linux/netfilter/nf_tables.h#L632  
- nft_payload_attributes: https://elixir.bootlin.com/linux/v5.15.5/source/include/uapi/linux/netfilter/nf_tables.h#L792

```  
filter {  
   # set  
   flag {  
       0: "dnrgs{REDACTEDREDACTEDREDACTEDREDACTED}"  
   }  
  
   # chains  
   input {}  
   forward {}  
   output {  
       immediate {  
           NFTA_IMMEDIATE_DREG: 0  
           NFTA_IMMEDIATE_DATA:   
               NFTA_DATA_VALUE: "\xff\xff\xff\xfd"  
               NFTA_DATA_VERDICT : "hack\x00"  
       }  
   }  
   hack {  
       payload {  
           NFTA_PAYLOAD_DREG:      1  
           NFTA_PAYLOAD_BASE:      NFT_PAYLOAD_TRANSPORT_HEADER  
           NFTA_PAYLOAD_OFFSET:    0x1c  
           NFTA_PAYLOAD_LEN:       8  
       }  
       cmp {  
           NFTA_CMP_SREG:  1  
           NFTA_CMP_OP:    NFT_CMP_EQ  
           NFTA_CMP_DATA:    
               NFTA_DATA_VALUE: dd48d0cfd3103cd4  
       }  
       immediate {  
           NFTA_IMMEDIATE_DREG: 0x12  
           NFTA_IMMEDIATE_DATA:  
               NFTA_DATA_VALUE: 0  
       }  
       lookup {  
           NFTA_LOOKUP_SET:    flag  
           NFTA_LOOKUP_SREG:   0x12  
           NFTA_LOOKUP_DREG:   1  
           NFTA_LOOKUP_FLAGS:  0  
       }  
       payload {  
           NFTA_PAYLOAD_SREG:          1  
           NFTA_PAYLOAD_BASE:          2  
           NFTA_PAYLOAD_OFFSET:        0x3c  
           NFTA_PAYLOAD_LEN:           0x27  
           NFTA_PAYLOAD_CSUM_TYPE:     0  
           NFTA_PAYLOAD_CSUM_OFFSET:   0  
           NFTA_PAYLOAD_CSUM_FLAGS:    0  
       }  
   }  
}  
```

From here, we're almost done! The `hack` rule is now *human readable*, and we
can see that 8 bytes are loaded from our incoming packet (offset `0x1c` from
the `NFT_PAYLOAD_TRANSPORT_HEADER` section), then compared to the
`dd48d0cfd3103cd4` value, and when it matches, the flag value is loaded from
the set, and its `0x27` bytes are written to the response packet at the offset
`0x3c`. It's now time to craft our packet!

## Flag time!

Now having the expected payload and the various offsets, we can craft a
packet. Seeing no mention of any specific protocol or ports on the routing
rules, we could just use any. But given the specific offets of the flag
(`0x3c`), we need somehow to control the response size. We could try forging
some TCP packet, since the port 22 is open, but the response packet is to
small to contains the flag. Some bigger packets could work later during the
SSH handshake, but we have some easier options: ICMP !

Then, let's go with some easy to craft `ICMP echo` packets, where we can send
a packet of at least `0x3c` bytes and get it echoed back:

```go  
package main

import (  
	"bytes"  
	"encoding/hex"  
	"fmt"  
	"log"  
	"math/rand"  
	"net"

	"golang.org/x/net/icmp"  
	"golang.org/x/net/ipv4"  
)

func main() {  
	targetIP := "34.159.43.116"

	payload, _ := hex.DecodeString("dd48d0cfd3103cd4")  
	payloadOffset := 0x1c  
	responseOffset := 0x3c  
	responseSize := 0x27

	// craft the expected payload given the above offets  
	padding := bytes.Repeat([]byte("A"), payloadOffset-len(payload))  
	data := append(padding, payload...)  
	responseFill := bytes.Repeat([]byte("B"), (responseOffset - (payloadOffset + len(payload)) + responseSize))  
	data = append(data, responseFill...)

	// Make a new ICMP message  
	m := icmp.Message{  
		Type: ipv4.ICMPTypeEcho, Code: 0,  
		Body: &icmp.Echo{  
			ID: rand.Int(), Seq: rand.Int(),  
			Data: data,  
		},  
	}  
	packet, err := m.Marshal(nil)  
	if err != nil {  
		panic(err)  
	}

	conn, err := net.Dial("ip4:icmp", targetIP)  
	if err != nil {  
		log.Fatalf("Dial: %s\n", err)  
	}

	n, err := conn.Write(packet)  
	if err != nil {  
		panic(err)  
	}  
	fmt.Printf("write %d bytes\n", n)  
	fmt.Println(hex.Dump(packet))  
}  
```

- Source: [./packetforge/main.go](./packetforge/main.go)

Now fire a tcpdump in a window:

```  
sudo tcpdump -n host 34.159.43.116 -X  
```

and run that script:

```  
sudo go run ./packetforge/main.go  
```

And the flag should show up on the tcpdump window:

```  
	0x0000:  4500 0077 db92 0000 3c01 e215 229f 2b74  E..w....<...".+t  
	0x0010:  c0a8 b222 0000 59cd fd52 164f 4141 4141  ..."..Y..R.OAAAA  
	0x0020:  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA  
	0x0030:  dd48 d0cf d310 3cd4 4242 4242 4242 4242  .H....<.BBBBBBBB  
	0x0040:  4242 4242 4242 4242 4242 4242 4242 4242  BBBBBBBBBBBBBBBB  
	0x0050:  4472 676e 537b 6338 6439 3862 3037 6434  DrgnS{c8d98b07d4  
	0x0060:  6332 6634 6133 6363 6332 6663 3130 6234  c2f4a3ccc2fc10b4  
	0x0070:  6636 3238 3135 7d                        f62815}  
```

> Note: we can't just read the packet response from the socket connection in
> the code, as the packet get modified by the routing table, and the checksum
> isn't recomputed (got: 0xfd52, want: 0xc180). We could've read it using a
> lower level connection (such as raw socket & syscalls), but tcpdump does the
> trick here.

## Conclusion

Despite having missed the flag validation by a couple of minutes, this was a
pretty fun and interesting challenge. The multiple rounds of decoding, each
providing some more bits of information kept me hooked. Having only a very
high level of understanding of `nftables` and overall packet routing, diving
in the sources unveiled quite a lot of the magic of it, even if there's still
lots of dark spot!

Original writeup (https://github.com/daeMOn63/ctf-
writeups/tree/main/dragonsector21/easyNFT).