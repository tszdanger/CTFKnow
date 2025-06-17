```  
#!/usr/bin/env python  
import os  
import string

from aiohttp import web  
from stellar_sdk import (  
   Keypair,  
   Account,  
   TransactionBuilder,  
   Asset,  
   Network,  
   TransactionEnvelope,  
)  
from stellar_sdk.exceptions import BadSignatureError

app = web.Application()  
routes = web.RouteTableDef()

STELLAR_SECRET = os.environ.get("STELLAR_SECRET")  
FLAG = os.environ.get("FLAG")  
if STELLAR_SECRET is None or FLAG is None:  
   raise EnvironmentError("Secrets are not set")

# Disabled for now  
# @routes.post("/prepareorder")  
async def prepare_order(request: web.Request):  
   data = await request.post()  
   if "address" not in data:  
       return web.Response(status=500, body="Missing destination address")

   keypair = Keypair.from_secret(STELLAR_SECRET)  
   account = Account(account=keypair.public_key, sequence=1)

   transaction = (  
       TransactionBuilder(  
           source_account=account,  
           network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE,  
           base_fee=100,  
       )  
       .append_payment_op(  
           data["address"], Asset("PIZZA", keypair.public_key), "1"  
       )  
       .build()  
   )  
   transaction.sign(keypair)  
   return web.Response(body=transaction.to_xdr())

@routes.post("/submit")  
async def submit_transaction(request: web.Request):  
   data = await request.post()  
   if "tx" not in data:  
       return web.Response(status=500, body="Missing tx")  
   envelope = TransactionEnvelope.from_xdr(  
       data["tx"], Network.PUBLIC_NETWORK_PASSPHRASE  
   )  
   if len(envelope.signatures) != 1:  
       return web.Response(status=500, body="Invalid envelope")  
   keypair = Keypair.from_secret(STELLAR_SECRET)  
   try:  
       keypair.verify(envelope.hash(), envelope.signatures[0].signature)  
   except BadSignatureError:  
       return web.Response(status=500, body="Invalid signature")  
   # server = Server(horizon_url="https://horizon.stellar.org")  
   # response = server.submit_transaction(envelope)  
   # return response["flag"]  
   return web.Response(body=FLAG)

MAX_PROOF_SIZE = 32  
MAX_TRIES = 30

@routes.post("/publickey")  
async def public_key(request: web.Request):  
   data = await request.post()  
   public_keys = set()

   # Detect Stellar radiations  
   for _ in range(MAX_TRIES):  
       public_keys.add(Keypair.from_secret(STELLAR_SECRET).public_key)  
       if len(public_keys) > 1:  
           return web.Response(status=500)

   sk = Keypair.from_secret(STELLAR_SECRET).signing_key  
   if "proof" in data:  
       # Sign a short "proof" message so that client can verify public key is valid,  
       # in case previous check was not enough.  
       # Proof must be short, printable messages.  
       proof = data["proof"]  
       if len(proof) > MAX_PROOF_SIZE or not all(c in string.printable for c in proof):  
           return web.Response(status=500, body="Invalid proof requested")  
       signed_message = sk.sign(proof.encode())  
       return web.json_response(  
           {  
               "public_key": public_keys.pop(),  
               "signature": signed_message.signature.hex(),  
           }  
       )  
   else:  
       return web.json_response({"public_key": public_keys.pop()})

@routes.get("/")  
async def index(request):  
   return web.FileResponse("./index.html")

if __name__ == "__main__":  
   app.add_routes(routes)  
   web.run_app(app, port=25520)  
```

The task starts as a continuation of Part 1, but the solution is really
different. Faulty public keys are gone, but the server now agrees to sign
anything with its private key, as long as "anything" is <= 32 bytes and
consists only of what Python means by `string.printable` (that is, normal
printable ASCII from 0x20 to 0x7E inclusive, plus five characters from 9 to
0xD, 100 characters total). Normal signing process in Stellar involves
sha256-hashes that are exactly 32-bytes long (no problem here) but are usually
not printable. However, nothing in sha-256 forbids printable hashes.
Probability for a random 32-byte string to be printable is `(100/256)**32`,
and sha-256 outputs are not that different from random strings, so one should
expect to get a printable hash after `2.56**32=1.16e13` attempts on average.

Step 1: generate a template for signing where some bytes can be varied while
remaining a valid message. I have used the following (public key is taken from
the server):  
```  
import stellar_sdk  
transaction=stellar_sdk.TransactionBuilder(source_account=stellar_sdk.Account('GDN72GVC6ACLLR4NOW5HH5H54JB34QMCXORYE3ZBYSRRJOBO32EX5HAY',
sequence=0xCCCCCCCCCCCCCCCC),
network_passphrase=stellar_sdk.Network.PUBLIC_NETWORK_PASSPHRASE,
base_fee=100).build()  
print(transaction.signature_base().hex())  
```  
Placeholder 0xCC...CC is transformed to bytes CC ... CD which means that it is
incremented before building.

Step 2: unleash the power of GPU:  
```  
#include "cuda_runtime.h"  
#include "device_launch_parameters.h"

#include <stdio.h>  
#include <stdint.h>

static const __constant__ unsigned char data[128] = {  
   // actual data  
0x7A,0xC3,0x39,0x97,0x54,0x4E,0x31,0x75,0xD2,0x66,0xBD,0x02,0x24,0x39,0xB2,0x2C,  
0xDB,0x16,0x50,0x8C,0x01,0x16,0x3F,0x26,0xE5,0xCB,0x2A,0x3E,0x10,0x45,0xA9,0x79,  
0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0xDB,0xFD,0x1A,0xA2,0xF0,0x04,0xB5,0xC7,  
0x8D,0x75,0xBA,0x73,0xF4,0xFD,0xE2,0x43,0xBE,0x41,0x82,0xBB,0xA3,0x82,0x6F,0x21,  
0xC4,0xA3,0x14,0xB8,0x2E,0xDE,0x89,0x7E,0x00,0x00,0x00,0x00,0xCC,0xCC,0xCC,0xCC,  
0xCC,0xCC,0xCC,0xCC,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  
   0x00,0x00,0x00,0x00,  
   // padding  
                       0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x20,  
};

static const __constant__ uint32_t dev_k[64] = {  
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,  
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,  
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,  
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,  
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,  
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,  
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,  
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2  
};

struct SHA256_CTX {  
   uint32_t state[8];  
};

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))  
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))  
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))  
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))  
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))  
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))  
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

__host__ __device__ void sha256_loadbytes(uint32_t* m, size_t datapos)  
{  
   uint32_t i, j;  
#pragma unroll 16  
   for (i = 0, j = 0; i < 16; ++i, j += 4)  
       m[i] = (data[datapos + j] << 24) | (data[datapos + j + 1] << 16) | (data[datapos + j + 2] << 8) | (data[datapos + j + 3]);  
}

__host__ __device__ void sha256_transform(SHA256_CTX* ctx, uint32_t m[64])  
{  
   uint32_t a, b, c, d, e, f, g, h, i, t1, t2;

#pragma unroll 64  
   for (i = 16; i < 64; ++i)  
       m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

   a = ctx->state[0];  
   b = ctx->state[1];  
   c = ctx->state[2];  
   d = ctx->state[3];  
   e = ctx->state[4];  
   f = ctx->state[5];  
   g = ctx->state[6];  
   h = ctx->state[7];

#pragma unroll 64  
   for (i = 0; i < 64; ++i) {  
       t1 = h + EP1(e) + CH(e, f, g) + dev_k[i] + m[i];  
       t2 = EP0(a) + MAJ(a, b, c);  
       h = g;  
       g = f;  
       f = e;  
       e = d + t1;  
       d = c;  
       c = b;  
       b = a;  
       a = t1 + t2;  
   }

   ctx->state[0] += a;  
   ctx->state[1] += b;  
   ctx->state[2] += c;  
   ctx->state[3] += d;  
   ctx->state[4] += e;  
   ctx->state[5] += f;  
   ctx->state[6] += g;  
   ctx->state[7] += h;  
}

__global__ void kernel(SHA256_CTX* afterfirst, uint32_t* state, uint32_t
upper)  
{  
   uint32_t x = blockIdx.x * blockDim.x + threadIdx.x;  
   uint32_t m[64];  
   sha256_loadbytes(m, 64);  
   m[3] = upper;  
   uint32_t i, j;  
   for (uint32_t tmp = 0; tmp < 65536; tmp++) {  
       m[4] = (x << 16) | tmp;  
       SHA256_CTX ctx = *afterfirst;  
       sha256_transform(&ctx, m);  
       bool good = true;  
#pragma unroll 8  
       for (i = 0; i < 8; i++) {  
#pragma unroll 4  
           for (j = 0; j < 4; j++) {  
               unsigned char b = (ctx.state[i] >> (8 * j)) & 0xFF;  
               if (b < 9 || b > 13 && b < 32 || b > 126)  
                   good = false;  
           }  
       }  
       if (good) {  
           // hypothetically racy but whatever  
           state[0] = 1;  
           state[1] = m[4];  
       }  
   }  
}

int main()  
{  
   SHA256_CTX afterfirst;  
   afterfirst.state[0] = 0x6a09e667;  
   afterfirst.state[1] = 0xbb67ae85;  
   afterfirst.state[2] = 0x3c6ef372;  
   afterfirst.state[3] = 0xa54ff53a;  
   afterfirst.state[4] = 0x510e527f;  
   afterfirst.state[5] = 0x9b05688c;  
   afterfirst.state[6] = 0x1f83d9ab;  
   afterfirst.state[7] = 0x5be0cd19;  
   {  
       uint32_t m[64];  
       sha256_loadbytes(m, 0);  
       sha256_transform(&afterfirst, m);  
   }  
   uint32_t state[2] = { 0,0 };

   cudaError_t cudaStatus;  
   SHA256_CTX* afterfirst_device = NULL;  
   uint32_t* state_device = NULL;

   // Choose which GPU to run on, change this on a multi-GPU system.  
   cudaStatus = cudaSetDevice(0);  
   if (cudaStatus != cudaSuccess) {  
       fprintf(stderr, "cudaSetDevice failed!  Do you have a CUDA-capable GPU installed?");  
       goto Error;  
   }

   // Allocate GPU buffers  
   cudaStatus = cudaMalloc((void**)&afterfirst_device, sizeof(SHA256_CTX));  
   if (cudaStatus != cudaSuccess) {  
       fprintf(stderr, "cudaMalloc failed!");  
       goto Error;  
   }

   cudaStatus = cudaMalloc((void**)&state_device, 2 * sizeof(uint32_t));  
   if (cudaStatus != cudaSuccess) {  
       fprintf(stderr, "cudaMalloc failed!");  
       goto Error;  
   }

   // Copy input from host memory to GPU buffers.  
   cudaStatus = cudaMemcpy(afterfirst_device, &afterfirst, sizeof(SHA256_CTX),
cudaMemcpyHostToDevice);  
   if (cudaStatus != cudaSuccess) {  
       fprintf(stderr, "cudaMemcpy failed!");  
       goto Error;  
   }

   cudaStatus = cudaMemcpy(state_device, state, 2 * sizeof(uint32_t),
cudaMemcpyHostToDevice);  
   if (cudaStatus != cudaSuccess) {  
       fprintf(stderr, "cudaMemcpy failed!");  
       goto Error;  
   }

   for (uint32_t upper = 0;; upper++) {  
       printf("."); fflush(stdout);  
       // Launch a kernel on the GPU with one thread for each element.  
       kernel<<<256, 256>>> (afterfirst_device, state_device, upper);

       // Check for any errors launching the kernel  
       cudaStatus = cudaGetLastError();  
       if (cudaStatus != cudaSuccess) {  
           fprintf(stderr, "addKernel launch failed: %s\n", cudaGetErrorString(cudaStatus));  
           goto Error;  
       }

       // cudaDeviceSynchronize waits for the kernel to finish, and returns  
       // any errors encountered during the launch.  
       cudaStatus = cudaDeviceSynchronize();  
       if (cudaStatus != cudaSuccess) {  
           fprintf(stderr, "cudaDeviceSynchronize returned error code %d after launching addKernel!\n", cudaStatus);  
           goto Error;  
       }

       // Copy output from GPU buffer to host memory.  
       cudaStatus = cudaMemcpy(state, state_device, 2 * sizeof(uint32_t), cudaMemcpyDeviceToHost);  
       if (cudaStatus != cudaSuccess) {  
           fprintf(stderr, "cudaMemcpy failed!");  
           goto Error;  
       }

       if (state[0]) {  
           printf("found! lower=0x%X upper=0x%X\n", state[1], upper);  
           break;  
       }  
   }

Error:  
   cudaFree(state_device);  
   cudaFree(afterfirst_device);  
   // cudaDeviceReset must be called before exiting in order for profiling and  
   // tracing tools such as Nsight and Visual Profiler to show complete
traces.  
   cudaStatus = cudaDeviceReset();  
   if (cudaStatus != cudaSuccess) {  
       fprintf(stderr, "cudaDeviceReset failed!");  
   }

   return 0;  
}  
```  
`cuda_runtime.h` and `device_launch_parameters.h` were inserted by CUDA
template for Visual Studio (most comments are from that template as well, for
that matter), I haven't bothered to check what exactly they do. I'm not an
expert in CUDA programming, so it's possible that something could be better.
With this code, my notebook has found a good value for placeholder
(0x73F81EF581F) in about three hours.

Step 3: generate the transaction with the value from Step 2 (if you also have
used sequence as placeholder, watch for off-by-one), get the hash and make
sure it is printable, send it to the server to sign, enter the signature:  
```  
>>> import stellar_sdk  
>>>
transaction=stellar_sdk.TransactionBuilder(source_account=stellar_sdk.Account('GDN72GVC6ACLLR4NOW5HH5H54JB34QMCXORYE3ZBYSRRJOBO32EX5HAY',
sequence=0x73F81EF581E),
network_passphrase=stellar_sdk.Network.PUBLIC_NETWORK_PASSPHRASE,
base_fee=100).build()  
>>> transaction.hash()  
b'XM>iUQ9i9~b[*nT{x3!<Rpt \x0c@o0XBj@'  
```  
```  
$ curl http://stellar-radiation.donjon-ctf.io:25520/publickey -d
'proof=XM>iUQ9i9~b[*nT{x3!<Rpt%20%0C@o0XBj@'  
{"public_key": "GDN72GVC6ACLLR4NOW5HH5H54JB34QMCXORYE3ZBYSRRJOBO32EX5HAY",
"signature":
"712559aa2c9b17a3b59747582238d1b729b283e785685b48304d0c59ff148396fe8df2be4639416c90108baebc5b7b2c1d1f3cc1af0d5bef502f18c95ad95c0b"}  
```  
```  
>>>
transaction.sign_hashx("712559aa2c9b17a3b59747582238d1b729b283e785685b48304d0c59ff148396fe8df2be4639416c90108baebc5b7b2c1d1f3cc1af0d5bef502f18c95ad95c0b")  
>>> transaction.to_xdr()  
'AAAAAgAAAADb/Rqi8AS1x411unP0/eJDvkGCu6OCbyHEoxS4Lt6JfgAAAAAAAAc/ge9YHwAAAAAAAAAAAAAAAAAAAAAAAAABfnV9SwAAAEBxJVmqLJsXo7WXR1giONG3KbKD54VoW0gwTQxZ/xSDlv6N8r5GOUFskBCLrrxbeywdHzzBrw1b71AvGMla2VwL'  
```  
```  
$ curl http://stellar-radiation.donjon-ctf.io:25520/submit -d
'tx=AAAAAgAAAADb/Rqi8AS1x411unP0/eJDvkGCu6OCbyHEoxS4Lt6JfgAAAAAAAAc/ge9YHwAAAAAAAAAAAAAAAAAAAAAAAAABfnV9SwAAAEBxJVmqLJsXo7WXR1giONG3KbKD54VoW0gwTQxZ/xSDlv6N8r5GOUFskBCLrrxbeywdHzzBrw1b71AvGMla2VwL'  
CTF{83dd5abec4185700d031420395059819c909bda66e4aab78c8963002935832b7}  
```