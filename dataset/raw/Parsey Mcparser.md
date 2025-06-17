# Parsey Mcparser  
Challenge description:

> Attached is a blob of data with a never-before-seen format. We need
> user_names extracted from all entries based on the group they're in.  
> Direcly below, is some starter code. All we need is the function  
> "**ParseNamesByGroup**" implemented which takes a blob of data  
> (string) and the group name (string). This function should return all  
> user_names belonging to that group.  
>  
> ```  
> '''  
> :param blob: blob of data to parse through (string) :param  
> group_name: A single Group name ("Green", "Red", or "Yellow",etc...)  
>  
> :return: A list of all user names that are part of a given Group  
> '''  
> def ParseNamesByGroup(blob, group_name):  
>     #impliment code  
>     data = raw_input() group_name = data.split('|')[0] blob =
> data.split('|')[1] result_names_list = ParseNamesByGroup(blob,  
> group_name) print result_names_list  
> ```  
>  
> stdin example:  
> ```  
> Black|+++,Bellhomes LLC.,["age":39, "user_name":"Reid Jolley",  
> "Group":"Black"],+++,Greek Ideas,["age":63, "user_name":"Lucius  
> Chadwell", "Group":"Green"],["age":63, "user_name":"Cary Rizzuto",  
> "Group":"Black"],["age":28, "user_name":"Shoshana Bickett",  
> "Group":"Yellow"],["age":69, "user_name":"Madeleine Swallow",  
> "Group":"Green"],["age":41, "user_name":"Buddy Etter",  
> "Group":"Black"],+++,God fire,["age":26, "user_name":"Carlene  
> Caulder", "Group":"Green"],["age":43, "user_name":"Napoleon Peay",  
> "Group":"Purple"],["age":44, "user_name":"Noemi Constant",  
> "Group":"Green"]  
> ```  
>  
> stdout example:  
>  
> ```  
> ['Reid Jolley', 'Cary Rizzuto', 'Buddy Etter']  
> ```

## Solution  
Solution in script.py file.  
```  
$  python2 script.py  
Black|+++,Bellhomes LLC.,["age":39, "user_name":"Reid Jolley",
"Group":"Black"],+++,Greek Ideas,["age":63, "user_name":"Lucius Chadwell",
"Group":"Green"],["age":63, "user_name":"Cary Rizzuto",
"Group":"Black"],["age":28, "user_name":"Shoshana Bickett",
"Group":"Yellow"],["age":69, "user_name":"Madeleine Swallow",
"Group":"Green"],["age":41, "user_name":"Buddy Etter",
"Group":"Black"],+++,God fire,["age":26, "user_name":"Carlene Caulder",
"Group":"Green"],["age":43, "user_name":"Napoleon Peay",
"Group":"Purple"],["age":44, "user_name":"Noemi Constant", "Group":"Green"]  
['Reid Jolley', 'Cary Rizzuto', 'Buddy Etter']  
```

### How to solve the problem

In order to solve this problem, we have just to:

- extract all fields lists (like `["age":69, "user_name":"Madeleine Swallow", "Group":"Green"]`, etc)  
- transform each fields list into a JSON object  
- decode each JSON object  
- search in every object if user belongs to the specified group. If yes, user will be added to the `users` list

Original writeup (https://github.com/Samuele458/CTF-
writeups/tree/master/TenableCTF2021/Code/Parsey-Mcparser).