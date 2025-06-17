The title is a pun on Barreto-Lynn-Scott aka BLS curves. BLS is a family of
curves for pairing-based cryptography; such a curve has a subgroup of large
prime order, there is a quadratic twist over some low-degree extension field
that has another subgroup of the same order, and there is some magic
irreversible bilinear map that takes two points from those two subgroups. A
map is not required for the task.

The curve in question is the following (SageMath):  
```  
p =
0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab  
Fp = GF(p)  
E = EllipticCurve(Fp, [0, 4])  
r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001  
assert E.order() % r == 0  
```  
and its twist is  
```  
Fp2 = GF(p^2,'gen2',modulus=x^2+1)  
E2 = EllipticCurve(Fp2, [0, 4*(Fp2.gen()+1)])  
assert E2.order() % r == 0  
```

The attached code is so small that can be quoted in its entirety:  
```  
use ark_bls12_381::{Fq, Fq2, Fr, G1Affine, G2Affine};  
use ark_ec::{AffineCurve, ProjectiveCurve};  
use ark_ff::bytes::{FromBytes, ToBytes};  
use std::{  
   env,  
   io::Cursor,  
   process::exit,  
   str::{from_utf8, FromStr},  
};

const ENCRYPTED_DATA: &'static str =
"beiLPpGUsefnBjahYgx8MKNl1Bd59EwQPUfYLXBRg8J7p6b3UhxDKQqtQG2XAUEEHleWprEKGZxW/0uPv4HcZ19jGre+1GW38tqxfWdmNrk5wu/s+t2waB0lBlCxA0QG4RcWc4yqAqEapkFp5eoReESZGcu/gPzWXLCBMuO4HCv2uz0S9nirCKGJZkUKxaAHnoWw2HN3CaZp7Dv5MrqOzROmZwtla3gttGqpgZ5hPyov6rYeL5IpmUFgkQSHtsoYNJGEaj4pTq3rslaUWT0wHluGcnQ0EFJWGjcTHgOzmEcFpNGPQEmual0cZnmTDF4XgJDCMcWzd4GwhruhTbdGGsmFAKB8R0VILMOKJhA0MHYmzaej0mlHhgpjmTZLQqoB1UQk7gO8MTYAozmchcRo667xAeZ2THs5G5FiczIq2Ej0EmijbuUHJfqszlPNvrQBrjtS5Rc2SJUTgCQTVij9d7vEcmTFgLibdcG/Ym8dFiiTjO58H74erbYaUQCLn5MU/ypBlEzhHKmqfYSQmhQuE0fhljz+F0kDduq0OhfcIr2QyL8vFnSiYFvXXXB9WTgUGvWCKNG2UMH9oeAZOZjDfsfTHWO7Iw+xscihEfYnGush7p85KDg6kOPzw+YGgXUOETFbhIHskl7irHtmoZgNfhxJ/oCr4OTaCzT7CeESaFbXOdSLX9rSGRFsxq2SyrwK6ybq2ZEIR0wBdPEP+UY0oNUDnXyVvE0Xgx/AwIYJK9t+GF4Fc3oW0UJBzXslHW0Qx4Dn7XlGWEozkgOHj3SAtMcofSd4hHNqII3ze9lJNTGBB2HwwtMfdL4IWzgJKyQQUTq5zwJd3S6xrka1TsRQx6aVNYLhmHUOFC7uzT3aMjtjWED6dJTlCcaJO4wMf4sW";

#[derive(Clone, Debug)]  
struct EncryptedData {  
   pub g1: G1Affine,  
   pub commited_1: G1Affine,  
   pub g2: G2Affine,  
   pub commited_2: G2Affine,  
   pub encrypted_pt: G1Affine,  
}

fn get_encrypted_data() -> EncryptedData {  
   let encdata_bin = base64::decode(ENCRYPTED_DATA).unwrap();  
   let mut encdata_reader = Cursor::new(&encdata_bin);  
   let data = EncryptedData {  
       g1: G1Affine::new(  
           Fq::read(&mut encdata_reader).unwrap(),  
           Fq::read(&mut encdata_reader).unwrap(),  
           false,  
       ),  
       commited_1: G1Affine::new(  
           Fq::read(&mut encdata_reader).unwrap(),  
           Fq::read(&mut encdata_reader).unwrap(),  
           false,  
       ),  
       g2: G2Affine::new(  
           Fq2::read(&mut encdata_reader).unwrap(),  
           Fq2::read(&mut encdata_reader).unwrap(),  
           false,  
       ),  
       commited_2: G2Affine::new(  
           Fq2::read(&mut encdata_reader).unwrap(),  
           Fq2::read(&mut encdata_reader).unwrap(),  
           false,  
       ),  
       encrypted_pt: G1Affine::new(  
           Fq::read(&mut encdata_reader).unwrap(),  
           Fq::read(&mut encdata_reader).unwrap(),  
           false,  
       ),  
   };  
   assert_eq!(encdata_reader.position(), encdata_bin.len() as u64);  
   data  
}

fn main_result() -> Result<(), String> {  
   let encdata = get_encrypted_data();

   let mut args = env::args();  
   args.next();  
   let first_arg = args.next().ok_or("No key provided")?;  
   if first_arg.len() >= 40 {  
       return Err("invalid key".into());  
   }  
   let key = Fr::from_str(&first_arg).map_err(|()| "invalid key")?;

   // Verify the commitments  
   if encdata.g1.mul(key) != encdata.commited_1 {  
       return Err("invalid key".into());  
   }  
   if encdata.g2.mul(key) != encdata.commited_2 {  
       return Err("invalid key".into());  
   }  
   println!("The key is correct, proceeding to decryption...");

   let decrypted_pt = encdata.encrypted_pt.mul(key).into_affine();  
   let mut decrypted_raw: Vec<u8> = Vec::new();  
   decrypted_pt  
       .x  
       .write(&mut Cursor::new(&mut decrypted_raw))  
       .unwrap();  
   let decrypted = from_utf8(&decrypted_raw).map_err(|_| "invalid key")?;  
   println!("Message: {}", decrypted.trim_end_matches(char::from(0)));  
   Ok(())  
}

fn main() {  
   if let Err(msg) = main_result() {  
       eprintln!("Error: {}", msg);  
       exit(1);  
   }  
}  
```  
In other words, there is a secret key, a public pair of points `g1` and
`commited_1` on `E` related by `g1*key == commited_1`, another public pair of
points `g2` and `commited2` on `E2` with the same relation `g2*key ==
commited_2`, and we need to calculate `encrypted_pt*key` for yet another point
on `E`.

If all points belong to corresponding secure subgroups, that is impossible
(or, more precisely, requires a really big cryptographical breakthrough). The
additional structure for pairings allows to check that they are indeed related
in that way, but nothing more. Maybe these points don't belong to where they
should be? The order of this elliptic curve is much larger than the order of
secure subgroups...  
```  
import base64  
data =
base64.b64decode('beiLPpGUsefnBjahYgx8MKNl1Bd59EwQPUfYLXBRg8J7p6b3UhxDKQqtQG2XAUEEHleWprEKGZxW/0uPv4HcZ19jGre+1GW38tqxfWdmNrk5wu/s+t2waB0lBlCxA0QG4RcWc4yqAqEapkFp5eoReESZGcu/gPzWXLCBMuO4HCv2uz0S9nirCKGJZkUKxaAHnoWw2HN3CaZp7Dv5MrqOzROmZwtla3gttGqpgZ5hPyov6rYeL5IpmUFgkQSHtsoYNJGEaj4pTq3rslaUWT0wHluGcnQ0EFJWGjcTHgOzmEcFpNGPQEmual0cZnmTDF4XgJDCMcWzd4GwhruhTbdGGsmFAKB8R0VILMOKJhA0MHYmzaej0mlHhgpjmTZLQqoB1UQk7gO8MTYAozmchcRo667xAeZ2THs5G5FiczIq2Ej0EmijbuUHJfqszlPNvrQBrjtS5Rc2SJUTgCQTVij9d7vEcmTFgLibdcG/Ym8dFiiTjO58H74erbYaUQCLn5MU/ypBlEzhHKmqfYSQmhQuE0fhljz+F0kDduq0OhfcIr2QyL8vFnSiYFvXXXB9WTgUGvWCKNG2UMH9oeAZOZjDfsfTHWO7Iw+xscihEfYnGush7p85KDg6kOPzw+YGgXUOETFbhIHskl7irHtmoZgNfhxJ/oCr4OTaCzT7CeESaFbXOdSLX9rSGRFsxq2SyrwK6ybq2ZEIR0wBdPEP+UY0oNUDnXyVvE0Xgx/AwIYJK9t+GF4Fc3oW0UJBzXslHW0Qx4Dn7XlGWEozkgOHj3SAtMcofSd4hHNqII3ze9lJNTGBB2HwwtMfdL4IWzgJKyQQUTq5zwJd3S6xrka1TsRQx6aVNYLhmHUOFC7uzT3aMjtjWED6dJTlCcaJO4wMf4sW')  
g1 = E(int.from_bytes(data[:0x30], byteorder='little'),
int.from_bytes(data[0x30:0x60], byteorder='little'))  
commited_1 = E(int.from_bytes(data[0x60:0x90], byteorder='little'),
int.from_bytes(data[0x90:0xC0], byteorder='little'))  
g2 = E2(  
   Fp2([int.from_bytes(data[0xC0:0xF0], byteorder='little'),
int.from_bytes(data[0xF0:0x120], byteorder='little')]),  
   Fp2([int.from_bytes(data[0x120:0x150], byteorder='little'),
int.from_bytes(data[0x150:0x180], byteorder='little')])  
)  
commited_2 = E2(  
   Fp2([int.from_bytes(data[0x180:0x1B0], byteorder='little'),
int.from_bytes(data[0x1B0:0x1E0], byteorder='little')]),  
   Fp2([int.from_bytes(data[0x1E0:0x210], byteorder='little'),
int.from_bytes(data[0x210:0x240], byteorder='little')])  
)  
encrypted_pt = E(int.from_bytes(data[0x240:0x270], byteorder='little'),
int.from_bytes(data[0x270:0x2A0], byteorder='little'))  
factor(g1.order())  
```  
The output is `3 * 11 * 10177 * 859267 * 52437899 *
52435875175126190479447740508185965837690552500527637822603658699938581184513`.
Aha! If we multiply `g1` and `commited_1` by 5243...4513, the relation `g1*key
== commited_1` will keep its form, but the order will fall dramatically to `3
* 11 * 10177 * 859267 * 52437899` that allows discrete logarithming without
major cryptographical breakthroughs:  
```  
order1 = g1.order() // r  
(g1*r).discrete_log(commited_1*r)  
```  
-> 5224296668755879435. Well, that only gives `key` modulo the new order, but it's better than nothing. Plus, we have one more pair of points to exploit. This time, factoring the order from scratch is hard, but we know one divisor from the pairing structure and can use it as a hint:  
```  
pari([r]).addprimes()  
factor(g2.order())  
# outputs 13 * 23 * 2713 * 11953 * 262069 *
52435875175126190479447740508185965837690552500527637822603658699938581184513
*
402096035359507321594726366720466575392706800671181159425656785868777272553337714697862511267018014931937703598282857976535744623203249  
order2 = 13 * 23 * 2713 * 11953 * 262069  
mult2 = g2.order() // order2  
(g2*mult2).discrete_log(commited_2*mult2)  
```  
-> 1408187707785775. Now we have two remainders of `key` modulo two orders, use Chinese Remainder Theorem to combine them:  
`CRT([5224296668755879435,1408187707785775], [order1,order2]) =
5892077238539525450479517562624589`. (Actually, `discrete_log` uses CRT
internally as well, splitting the work to individual prime-order subgroups and
merging the results, or the execution time would be much larger. But this is
hidden from the user behind a convenient facade.)

...`5892077238539525450479517562624589 * g1 == commited_1` returns False, so
this is not yet the `key` but the remainder modulo `order1*order2`. Well, the
key is read from decimal representation that is not greater than 39 digits, so
the quotient cannot be greater than `10**39//(order1*order2) = 26006` and all
variants can be simply enumerated (okay, there is a more computationally-
efficient way using meet-in-the-middle, but I would spend more time to write
it than the naive script has spent to find the answer):  
```  
key = 5892077238539525450479517562624589  
mod = order1*order2  
P = key*g1  
Q = mod*g1  
while P != commited_1:  
   P += Q  
   key += mod  
x = key*encrypted_pt  
int(x[0]).to_bytes(0x30, byteorder='little')  
```  
-> `b'CTF{Ethereum-2.0_have_nice_and_funny_curves!:)}\x00'`