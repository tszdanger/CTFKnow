# Members - DaVinciCTF

- Category: Web  
- Points: 66  
- Solves: 61  
- Solved by: raff01

## Description

Can you get more information about the members?

`http://challs.dvc.tf:1337/members`

## Analysis

In order to solve this challenge it's necessary to have solved the previous
one called "Authentication" that permits to access the following web service:

`http://challs.dvc.tf:1337/members`

Let's have a look to the web site. We have a page where there is a table with
some information about members on the right and a form that allows to search
members on the left. By analysing the source code of the page we can see that
the form uses the GET method to send search-parameters, so all the text we
write will be encoded into the url. Once the server has recived our data, it
will return information about members. So it seems there's a MySQL Database
back the application. Let's inject some malicious code into the text field:

`Leonard" OR 1=1; --`

and the application will return all the records of the table, so the
application is vulnerable to SQL Injection!

## Solution

Probably the flag isn't in the same table where are archived all the members.
So the best thing to do is to show all the table names and see if there is
something interesting. To do this we can use the **UNION** command that
permits to add a malicious sub-query to the original one and get other data
from the database. In particular the table **information_schema.tables**
contains the information about all the tables located in the db. Let's inject
the following code:

`Leonard" UNION (SELECT TABLE_NAME,2,3 FROM INFORMATION_SCHEMA.TABLES); --`

and the application will return all the table names that are stored in the
database. If we scroll down we can see two interesting tables: **members**
that is the table that contains all the members information and another table
called **supa_secret_table**, let's analyse it. The table called
**information_schema.columns** contains all the information about the columns
of all the tables stored. So we can get the field names of
**supa_secret_table** by injecting this code:

`Leonard" UNION (SELECT COLUMN_NAME,2,3 FROM INFORMATION_SCHEMA.COLUMNS WHERE
TABLE_NAME='supa_secret_table'); --`

the application will return two records with the name of the fields: **id**
and **flag**. So now let's get the content of flag:

`Leonard" UNION (SELECT flag,2,3 FROM supa_secret_table); --`

and the application will print the flag!

## Flag

`dvCTF{1_h0p3_u_d1dnt_us3_sqlm4p}`

Original writeup
(https://github.com/r00tstici/writeups/tree/master/DaVinciCTF_2021/Members).