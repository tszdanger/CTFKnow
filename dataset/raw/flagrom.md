# Challenge Description  
This 8051 board has a SecureEEPROM installed. It's obvious the flag is stored
there. Go and get it.

nc flagrom.ctfcompetition.com 1337

# Prep Work  
Lets start by seeing what the network service gives us upon connecting.

```  
$ nc flagrom.ctfcompetition.com 1337  
What's a printable string less than 64 bytes that starts with flagrom- whose
md5 starts with e3ae75?  
```

Seems like a proof of work.

After passing the proof of work, we are asked:  
```  
What's the length of your payload?  
```

The server expects an integer, followed by newline and a binary payload of the
size specified.

Lets script the interaction.  
Additionally, we patch the proof of work check out of the local binary for
rapid testing.

```python  
from pwn import *

local = False

def calc_pow(prefix):  
   prefix = prefix.decode('hex')  
   while True:  
       s = 'flagrom-{0}'.format(randoms(10))  
       if md5sum(s).startswith(prefix):  
           return s

if local:  
   s = process('./flagrom')  
else:  
   s = remote('flagrom.ctfcompetition.com', 1337)  
   l = s.recvline()  
   prefix = l[-8:-2]  
   proof = calc_pow(prefix)  
   s.sendline(proof)  
  
s.readuntil("What's the length of your payload?")

payload = open('payload.bin', 'rb').read()  
s.writeline(str(len(payload)))  
s.write(payload)  
s.stream()  
```

# Investigation

## The firmware  
We are given source code to the firmware that is executed before our payload,
along with a SystemVerilog description of the theoretical secure eeprom
device.

The eeprom device is 256 bytes large, with banks of 64 bytes that can be
secured to prevent reading.

The firmware writes a flag into address `64` of the eeprom and then secures
the corresponding bank to prevent the flag from being read back.  It then
writes a "welcome" message to address 0 of the eeprom (which is not secured),
presumably so we can sanity check our payload to ensure it is working
correctly.

The firmware makes use of some special function registers (SFR) beginning at
address `0xfe00` to allow the 8051 hardware to handle the minutiae of
interacting with the I2C bus, but we also have two interesting definitions in
the firmware source code that are unused.

```c  
__sfr __at(0xfa) RAW_I2C_SCL;  
__sfr __at(0xfb) RAW_I2C_SDA;  
```

This suggests we have direct access to twiddle the I2C lines ourselves.

## The I2C Protocol

The actual I2C protocol is somewhat hidden from view by use of the SFR block
at `0xfe00`, but we can reverse engineer some of the `flagrom` binary itself
to better understand it.  Helpfully, the binary appears to have symbols
included.

The most relevant function is `sfr_i2c_module` and the functions it calls
within.  
```c  
bool __fastcall sfr_i2c_module(void *emu, int access_type, int address_type,
unsigned __int8 a4, unsigned __int8 *value)  
{  
 bool result; // al  
 unsigned __int8 v7; // al  
 I2C_REG_BLOCK I2C; // [rsp+20h] [rbp-20h]  
 int direction; // [rsp+30h] [rbp-10h] MAPDST  
 int pos; // [rsp+34h] [rbp-Ch]  
 char success; // [rsp+3Bh] [rbp-5h]  
 int last_direction; // [rsp+3Ch] [rbp-4h]

 if ( access_type )  
 {  
   if ( *value & 1 )  
   {  
     emu8051::mem_read(emu, 2LL, 0xFE00LL, &I2C, 16LL);  
     if ( I2C.LENGTH <= 7u )  
     {  
       if ( I2C.LENGTH )  
       {  
         I2C.ADDR &= 0xFEu;  
         last_direction = 0;  
         success = 1;  
         pos = 0;  
         while ( I2C.LENGTH )  
         {  
           if ( ((signed int)I2C.RW_MASK >> pos) & 1 )  
             direction = 2;  
           else  
             direction = 1;  
           if ( direction != last_direction )  
           {  
             send_start(dev_i2c[0]);  
             send_byte(dev_i2c[0], I2C.ADDR | (direction == 2));  
             if ( !recv_ack(dev_i2c[0]) )  
             {  
               I2C.ERROR_CODE = 2;  
               success = 0;  
               break;  
             }  
             last_direction = direction;  
           }  
           if ( direction == 2 )  
           {  
             v7 = recv_byte(dev_i2c[0]);  
             I2C.DATA[pos] = v7;  
           }  
           else  
           {  
             send_byte(dev_i2c[0], I2C.DATA[pos]);  
           }  
           if ( !recv_ack(dev_i2c[0]) )  
           {  
             I2C.ERROR_CODE = 3;  
             success = 0;  
             break;  
           }  
           --I2C.LENGTH;  
           ++pos;  
         }  
         if ( success )  
           I2C.ERROR_CODE = 0;  
       }  
       else  
       {  
         send_start(dev_i2c[0]);  
         send_byte(dev_i2c[0], I2C.ADDR);  
         if ( recv_ack(dev_i2c[0]) )  
           I2C.ERROR_CODE = 0;  
         else  
           I2C.ERROR_CODE = 5;  
       }  
     }  
     else  
     {  
       I2C.ERROR_CODE = 1;  
     }  
     send_stop(dev_i2c[0]);  
     emu8051::mem_write(emu, 2LL, 65024LL, &I2C, 16LL);  
     result = 1;  
   }  
   else  
   {  
     result = 1;  
   }  
 }  
 else  
 {  
   *value = 0;  
   result = 1;  
 }  
 return result;  
}  
```

This function is called in response to read or write operations to the
`I2C_STATE` SFR at `0xfc`.  Writing a `1` to this location will trigger an I2C
operation based on the SFR block at `0xfe00`.

From this function we can see that at the lowest level an I2C transaction
looks like the following:  
1. send i2c start sequence  
2. send device address, lowest bit indicating transaction data direction  
3. receive ack  
4. send or receive byte, depending on transaction direction  
5. receive ack  
6. while there is more data: if direction is changing goto step 1, else goto step 4  
7. send i2c stop sequence

In order to read a byte of eeprom data from address `0`, our I2C traffic looks
like the following:  
- send i2c start sequence  
- send device address `SEEPROM_I2C_ADDR_MEMORY`  
- receive ack  
- send byte `0`  
- receive ack  
- send i2c start sequence  
- send device address `SEEPROM_I2C_ADDR_MEMORY | 1`  
- receive ack  
- receive byte  
- receive ack  
- send i2c stop sequence

One key observation about this traffic is that we send multiple i2c start
sequences without sending corresponding i2c stop sequences.

## The SystemVerilog

The verilog has a fair bit going on, but the only parts that are relevant for
us are those that are required to read a byte of the eeprom.

To start with, we have a register `i2c_state` which determines how the device
reacts to SCL rising edges.

We begin in `I2C_IDLE` and wait for the `i2c_start` wire to become hi, at
which point we transition to `I2C_START` state.  
```verilog  
I2C_IDLE: begin  
 if (i2c_start) begin  
   i2c_state <= I2C_START;  
 end  
end  
```

On the next SCL falling edge, we clear the `i2c_control_bits` and transition
to the `I2C_LOAD_CONTROL` state.  
```verilog  
I2C_START: begin  
 if (i2c_scl_state == I2C_SCL_FALLING) begin  
   i2c_control_bits <= 0;  
   i2c_state <= I2C_LOAD_CONTROL;  
 end  
end  
```

Once in this state, we accumulate bits into `i2c_control` on every SCL rising
edge until we have 8 bits.  
```verilog  
I2C_LOAD_CONTROL: begin  
 if (i2c_control_bits == 8) begin  
   ...  
 end else if (i2c_scl_state == I2C_SCL_RISING) begin  
   i2c_control <= {i2c_control[6:0], i_i2c_sda};  
   i2c_control_bits <= i2c_control_bits + 1;  
 end  
end  
```

At which point we switch on `i2c_control_prefix` to determine if we are
accessing eeprom bytes or updating the secure banks.  
```verilog  
case (i2c_control_prefix)  
 `I2C_CONTROL_EEPROM: begin  
   ...  
 end  
 `I2C_CONTROL_SECURE: begin  
   ...  
 end  
 default: begin  
   i2c_state <= I2C_NACK;  
 end  
endcase  
```

In the `I2C_CONTROL_EEPROM` case, we check the `i2c_control_rw` wire to
determine the transaction direction.  
In the write direction we clear `i2c_address_bits` and transition to the
`I2C_ACK_THEN_LOAD_ADDRESS` state.  
In the read direction we check `i2c_address_valid` and transition to the
`I2C_ACK_THEN_READ` state on success or `I2C_NACK` on failure.  
```verilog  
if (i2c_control_rw) begin  
 if (i2c_address_valid) begin  
   i2c_data_bits <= 0;  
   i2c_state <= I2C_ACK_THEN_READ;  
 end else begin  
   i2c_state <= I2C_NACK;  
 end  
end else begin  
 i2c_address_bits <= 0;  
 i2c_state <= I2C_ACK_THEN_LOAD_ADDRESS;  
end  
```

The `I2C_ACK_THEN_READ` and `I2C_ACK_THEN_LOAD_ADDRESS` states are
inconsequential; they simply send an ack and transition to the next state
(`I2C_READ` and `I2C_LOAD_ADDRESS` respectively).

The `I2C_LOAD_ADDRESS` state accumulates bits into `i2c_address` on each SCL
rising edge until 8 are received.  
```verilog  
if (i2c_address_bits == 8) begin  
 ...  
end else if (i2c_scl_state == I2C_SCL_RISING) begin  
 i2c_address <= {i2c_address[6:0], i_i2c_sda};  
 i2c_address_bits <= i2c_address_bits + 1;  
end  
```

At which point we verify the address is not secure, set `i2c_address_valid`,
and transition to `I2C_ACK_THEN_WRITE`.  
If the address is secure, `i2c_address_valid` is cleared and we transition to
`I2C_NACK`.  
```verilog  
if (i2c_address_secure) begin  
 i2c_address_valid <= 0;  
 i2c_state <= I2C_NACK;  
end else begin  
 i2c_data_bits <= 0;  
 i2c_address_valid <= 1;  
 i2c_state <= I2C_ACK_THEN_WRITE;  
end  
```

At this point if we were writing eeprom data `I2C_WRITE` would begin handling
bytes over i2c.  
Since we are reading eeprom data, we must start a new i2c transaction with the
`i2c_control_rw` bit set.  
In this transaction, the `I2C_LOAD_CONTROL` will verify that
`i2c_address_valid` is set before eventually transitioning us to `I2C_READ`
(through `I2C_ACK_THEN_READ`).

Interestingly, `i2c_address_valid` is cleared when an i2c stop sequence is
seen.  This explains why we see multiple start sequences without corresponding
stop sequences as noted earlier.

The `I2C_READ` state will clock out data one bit at a time until 8 bits have
been sent, at which point it increments `i2c_address` and prepares for another
byte to be transmitted.  However, this is only done if `i2c_address_secure ==
i2c_next_address_secure`.  
```verilog  
if (i2c_data_bits == 8 && i2c_scl_state == I2C_SCL_RISING) begin  
 i2c_data_bits <= 0;  
 if (i2c_address_secure == i2c_next_address_secure) begin  
   i2c_address <= i2c_address + 1;  
   i2c_state <= I2C_ACK_THEN_READ;  
 end else begin  
   i2c_state <= I2C_NACK;  
 end  
end else if (i2c_scl_state == I2C_SCL_FALLING) begin  
 o_i2c_sda <= mem_storage[i2c_address][7 - i2c_data_bits[2:0]];  
 i2c_data_bits <= i2c_data_bits + 1;  
end  
```

At this point our goal is clear: somehow get `i2c_address_valid` to be set
when `i2c_address` contains the address of the flag data.

There is only one condition that will cause `i2c_address_valid` to be set  
- a SCL rising edge while in `I2C_LOAD_ADDRESS` state with `i2c_address_bits == 8` and `i2c_address_secure == 0`

There are two conditions that will cause `i2c_address_valid` to be cleared  
- an SCL rising edge while in `I2C_LOAD_ADDRESS` state with `i2c_address_bits == 8` and `i2c_address_secure == 1`  
- an i2c stop sequence

The second condition can be easily avoided - we simply never send an i2c stop
sequence.

We can cause `i2c_address_valid` to become set by performing a normal eeprom
read with an address that is not secure.  
Now we need to get the flag address into `i2c_address` without triggering the
first `i2c_address_valid` clearing condition.

Lets take a closer look at how `i2c_address` is filled.

While in `I2C_LOAD_ADDRESS` state every SCL rising edge will push the current
SDA state into the LSB of `i2c_address`, shifting the previous contents up by
one bit.  `i2c_address_bits` is also incremented by one.  
```verilog  
i2c_address <= {i2c_address[6:0], i_i2c_sda};  
i2c_address_bits <= i2c_address_bits + 1;  
```

What would happen if we only transmit 7 bits of data and then send an i2c
start condition to exit the `I2C_LOAD_ADDRESS` state?

The address we want to read is `64` which in binary would be `0b0100'0000`. We
must transmit data on the bus MSB first.  If we send `0b0100'000`
`i2c_address` would contain `0b?010'0000`, where `?` is the LSB of the value
it previously contained.

However, lets look at the specifics of an i2c start sequence.  
- SCL lo  
- SDA hi  
- SCL hi  
- SDA lo

We can see that this sequence begins with an SCL rising edge where the SDA bit
is hi.  These will be observed in the `I2C_LOAD_ADDRESS` just before the
transition to `I2C_START`.  Taking this into account our final `i2c_address`
value will become `0b0100'0001`, or `65`.  This is close enough for our needs,
since the first 4 bytes of the flag contents are well known.

Note that `I2C_LOAD_ADDRESS` will never observe `i2c_address_bits == 8`
because we transition away to the `I2C_START` state before another SCL rising
edge occurs.  This means that the upper 7 bits of `i2c_address` can be
controlled without triggering the `i2c_address_secure` checks.  This allows us
to begin reading at any odd address.  The behavior of the `I2C_READ` state
allows us to continue reading sequentially from this point as long as we do
not cross a secure to unsecure block boundary.

# Implementation

We will use the [sdcc](http://sdcc.sourceforge.net/) compiler to write our
payload.

## Makefile  
```make  
all:  
	sdcc payload.c  
	objcopy -I ihex -O binary payload.ihx payload.bin  
```

## Code  
```c  
__sfr __at(0xff) POWEROFF;  
__sfr __at(0xfd) CHAROUT;  
__xdata __at(0xff00) unsigned char FLAG[0x100];

__sfr __at(0xfa) RAW_I2C_SCL;  
__sfr __at(0xfb) RAW_I2C_SDA;

const SEEPROM_I2C_ADDR_MEMORY = 0b10100000;

void print(const char *str) {  
 while (*str) {  
   CHAROUT = *str++;  
 }  
}

void send_start(void) {  
 RAW_I2C_SCL = 0;  
 RAW_I2C_SDA = 1;  
 RAW_I2C_SCL = 1;  
 RAW_I2C_SDA = 0;  
}

void send_byte(unsigned char byte) {  
 unsigned char i;

 for (i = 0; i < 8; i++) {  
   RAW_I2C_SCL = 0;  
   RAW_I2C_SDA = ((byte >> (7 - i)) & 1) != 0;  
   RAW_I2C_SCL = 1;  
 }  
}

void send_7bit(unsigned char byte) {  
 unsigned char i;

 for (i = 1; i < 7; i++) {  
   RAW_I2C_SCL = 0;  
   RAW_I2C_SDA = ((byte >> (7 - i)) & 1) != 0;  
   RAW_I2C_SCL = 1;  
 }  
}

unsigned char recv_byte(void) {  
 unsigned char ret = 0;  
 unsigned char i;

 for (i = 0; i < 8; i++) {  
   RAW_I2C_SCL = 0;  
   RAW_I2C_SCL = 1;  
   ret = 2 * ret | RAW_I2C_SDA;  
 }

 return ret;  
}

unsigned char recv_ack(void) {  
 RAW_I2C_SCL = 0;  
 RAW_I2C_SCL = 1;  
 return RAW_I2C_SDA ^ 1;  
}

void read_flag() {  
 unsigned char i;

 print("[PL] Reading flag...");

 // start a write transaction  
 send_start();  
 send_byte(SEEPROM_I2C_ADDR_MEMORY);  
 recv_ack();

 // send an unsecured address  
 send_byte(0);  
 recv_ack();

 // start a write transaction  
 send_start();  
 send_byte(SEEPROM_I2C_ADDR_MEMORY);  
 recv_ack();

 // send the upper 7 bits of the secured address  
 send_7bit(64);

 // start a new transaction, which shifts a 1 into the address lsb  
 send_start();

 // this is a read transaction  
 send_byte(SEEPROM_I2C_ADDR_MEMORY | 1);  
 recv_ack();

 // read the flag, starting from address 65  
 FLAG[0] = 'C';  
 for (i = 1; i < 64; i++) {  
   FLAG[i] = recv_byte();  
   recv_ack();  
 }

 print("DONE\n");  
}

void main(void) {  
 read_flag();

 print("[PL] Flag: ");  
 print(FLAG);  
 print("\n");

 POWEROFF = 1;  
}  
```

# Dumping the Flag  
Build the payload  
```  
$ make  
sdcc payload.c  
objcopy -I ihex -O binary payload.ihx payload.bin  
```

Run our script  
```  
$ python do.py  
[+] Opening connection to flagrom.ctfcompetition.com on port 1337: Done

Executing firmware...  
[FW] Writing flag to SecureEEPROM...............DONE  
[FW] Securing SecureEEPROM flag banks...........DONE  
[FW] Removing flag from 8051 memory.............DONE  
[FW] Writing welcome message to SecureEEPROM....DONE  
Executing usercode...  
[PL] Reading flag...DONE  
[PL] Flag: CTF{flagrom-and-on-and-on}

Clean exit.  
[*] Closed connection to flagrom.ctfcompetition.com port 1337  
```