## Disclaimer  
Please check the original writeup on
https://dothidden.xyz/dantectf_2023/routesmarkthespot/  if you want to see it
with the pictures.

## Description of the challenge

Aha, the little spirit says that the human became more ingenious! What a weird
way to transmit something, though.

## Solution

We are provided with a pcap file, let's open it with Wireshark.  
Let's go trough the different packets and see if we can find something unusual
into the info column.

From packet number 66 we start to see some more data in the hexdump of the
packets but if we go to the packet number 88,  
we can see that the protocol used is IPv6 and the hexdump looks like:

```òK¬V²b2sB2SÝ`Ø;@RlTÚC&òúëH[ØèV¡ôK×?z5ÛÞv'4yCK6F0xEs3vk0SRYA3t0sTQKJaFtqBl3P3ItFdufJtnKOIgHxYBWIQGJddGO28GKBtYowMnt2i5952qnKVYptX:n:wsIdZVn5F2UedZAqwjSwiJDGFhamjMDMWk5tzOCafGy2sSeVGdgy1uqtlHMQRL4lRAygqkao9qIY5LrQ5bHcxqD7zW9J15oAoO9amLnTtnm0ltQ5TJZ6bg7T4Vt940```

What is fascinating is that all the next IPv6 packets have the same hexdump
pattern with `:X:` (replace `X` by a char).  
Maybe we can try so take only the IPv6 packets and extract the char between
the `:` and see if we can find something.

As the following picture show, we can see that we found something related to
the flag because we have  
all the required char for the flag format which is `DANTE{...}`.

Unfortunately, the packets are not in the right order, so we need to sort in a
way to have the flag in the right order.  
But if we look at every binary flow label, we notice that we can use it to
sort the packets.

For example, the first packet with the capital `D` of DANTE has the flow label
`0000 0000 0000 0000 0000` and the second packet with the capital `A` has the
flow label `0000 0000 0000 0001` and so on.  
We can now add a column in Wireshark to sort the packets by flow label and get
the right order of the flag.

The flag is `DANTE{l4b3l5_c4n_m34n_m4ny_7h1ngs}`.

Original writeup (https://dothidden.xyz/dantectf_2023/routesmarkthespot/).