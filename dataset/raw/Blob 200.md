# Description

### Title: Blob

Ha. Blob. Did you get the reference?

http://git.ritsec.club:7000/blob.git/

# Solution

The challenge is about git blobs (Binary Large OBjects). First we have to look
at the different commits using  
`git show`.

```  
$ git show a69cb6306e8b75b6762d6aa1b0279244cacf3f3b

commit a69cb6306e8b75b6762d6aa1b0279244cacf3f3b (HEAD -> master,
origin/master, origin/HEAD)  
Author: knif3 <[email protected]>  
Date:   Fri Apr 9 05:49:11 2021 +0000

   Initial Commit

diff --git a/README.md b/README.md  
new file mode 100644  
index 0000000..e597cc8  
--- /dev/null  
+++ b/README.md  
@@ -0,0 +1,3 @@  
+# Blob  
+  
+That pesky flag should be around here somewhere...  
diff --git a/flag.txt b/flag.txt  
new file mode 100644  
index 0000000..df576e1  
--- /dev/null  
+++ b/flag.txt  
@@ -0,0 +1 @@  
+these aren't the droids you're looking for

```  
Here, we only see  one commit. However, if you go to the `.git/objects`
folder, there appear to be several commits. Looking at the next few commits,
we get the flag.

```  
$ git show b9d6753be80df863c3656aa6389418d3213c96f2

tree b9d6753be80df863c3656aa6389418d3213c96f2

README.md  
flag.txt

$ git show d0644363aa853a17c9672cefff587580a43cf45e

RS{refs_can_b3_secret_too}  
```

### Flag

`RS{refs_can_b3_secret_too}`  

Original writeup (https://github.com/black-tul1p/CTF-
Writeups/tree/main/RITSEC-2021/forensics/blob).