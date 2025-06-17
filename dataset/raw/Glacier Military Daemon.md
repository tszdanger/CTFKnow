# Problem Description  
We are presented with a SUID binary `/sbin/grhealth`. It has a retry logic
where on failure it will execute `execv(argv[0], argv);` if it encounters an
error. It takes two arguments, the first is what restart number we are
currently on, the second is the max number of restarts. Both are parsed with
strtol()

We want to read the file /flag.txt. We are given access to a read only system
where we can start the deamon but not create any files.

# Attack Plan  
We are going to try and mess with argv[0] in order to make the restart start a
different program that will read the flag for us.  In bash, we can do this by
using the `-a` option of the `exec` builtin. There are two things we need to
overcome - first the second argument must parse as an integer > 1. Second we
need to ensure the program encounters an error so that it restarts.

We can force it to restart by limiting the max number of file descriptors with
ulimit -n. When it recieves a new incoming connection, a new file descriptor
will be allocated, putting it over the limit. We can make a new connection
using bash's pseudo network devices /dev/tcp/127.0.0.1/80 opens a tcp
connection to local host on port 80 when written to.

strtol() will stop parsing once it hits the first non-integer character. So
"2foo" is considered 2. We cannot create any files, but all we need is file
path starting with a number that evaluates to flag.txt. /proc is useful for
this since it has numbered directories in it.

# Exploit  
Putting this altogether:

```  
bash  
cd /proc  
ulimit -n 7  
exec -a /bin/cat 0 '1/../self/root/flag.txt' &  
echo foo > /dev/tcp/127.0.0.1/80

```

You may need to hit enter a few times after that to wait for the job to
complete and so the jobs output will be put on screen.

The result is `gctf{31230_b4ckd00r3d_pr1v4t3_m1l1t4r1_c0mp4n1_74123}`