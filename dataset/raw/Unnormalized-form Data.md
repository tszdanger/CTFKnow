# Unnormalized-form Data – *Write-up by @terjanq*

> Description  
>---  
> Unnormalized-form data is troublesome. [unf.zip](#)  
>  
> (Misc, 127 points)

____

There are two files inside the archive [unf.zip](#): [operation.txt] and
[unf.sql]. The first one contains instruction how to use the given `SQL`
script.

Inside [unf.sql] we have two tables `dict` and `rel`. The second one defines
the recursive relations between objects, and every object has its
corresponding character in `dict`.

```sql  
CREATE TABLE dic (a TEXT[], c TEXT);  
ALTER TABLE dic OWNER TO postgres;

CREATE TABLE rel (s TEXT[], d TEXT[]);  
ALTER TABLE rel OWNER TO postgres;

INSERT INTO dic(a, c) VALUES('{d,B,7}','H');  
INSERT INTO dic(a, c) VALUES('{b,A,4}','.');  
INSERT INTO dic(a, c) VALUES('{b,H,1}','=');

⋮  

INSERT INTO dic(a, c) VALUES('{b,A,7}','D');  
INSERT INTO dic(a, c) VALUES('{c,G,3}','/');

INSERT INTO rel(s, d) VALUES('{b,C,5}','{c,A,6}');  
INSERT INTO rel(s, d) VALUES('{d,D,3}','{a,D,2}');  
INSERT INTO rel(s, d) VALUES('{b,D,7}','{b,E,7}');

⋮  

INSERT INTO rel(s, d) VALUES('{b,C,7}','{c,B,4}');  
INSERT INTO rel(s, d) VALUES('{a,C,5}','{d,A,4}');

CREATE FUNCTION flag() RETURNS text  
   LANGUAGE sql IMMUTABLE SECURITY DEFINER  
   AS $$WITH RECURSIVE r(i, j, a) AS ( VALUES (  
        0,1,'{a,B,4}'::TEXT[]), (0,2,'{d,B,7}'), (0,3,'{b,F,1}'),
(0,4,'{b,D,7}'), (0,5,'{b,E,7}'),  
        (0,6,'{a,E,3}'), (0,7,'{b,A,2}'), (0,8,'{d,F,2}'), (0,9,'{d,F,7}'),
(0,10,'{a,A,4}'),  
        0,11,'{b,H,7}'), (0,12,'{b,H,5}'), (0,13,'{a,E,6}'), (0,14,'{d,C,3}'),
(0,15,'{d,E,5}'),  
        (0,16,'{d,B,1}'), (0,17,'{c,A,5}'), (0,18,'{b,G,6}'),
(0,19,'{d,E,7}'), (0,20,'{c,F,7}'),  
        (0,21,'{c,B,2}'), (0,22,'{d,D,3}'), (0,23,'{c,A,1}'),
(0,24,'{a,G,1}'), (0,25,'{c,G,7}'),  
        (0,26,'{a,B,3}'), (0,27,'{a,C,5}'), (0,28,'{a,C,3}'), (0,29,'{d,C,6}')  
        UNION    SELECT i + 1, j, d FROM r, rel WHERE i < 40 AND a::TEXT[] <@
s  )  
        SELECT string_agg(c, '') FROM  
        (SELECT c FROM r, dic WHERE i = 40 AND r.a::TEXT[] @> dic.a ORDER BY
j) AS t$$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;  
REVOKE ALL ON SCHEMA public FROM postgres;  
GRANT ALL ON SCHEMA public TO postgres;  
GRANT ALL ON SCHEMA public TO PUBLIC;

```

After the part of understanding how the given relations work I was planning to
rewrite them into some language I know ( Yes, I know nothing about
`PostgreSQL` ). But I moved to analyze the `flag function` first.  
Well analyzing is a big word because all I have done was to change some code
and watch how the function adapts to that change...  
Running the command from [operation.txt] returns the following output.

```sh  
$ psql -U postgres -d unf -c "SELECT FLAG()"  
    flag        
---------------  
HarekazeCTF{}  
(1 row)  
```  
I noticed that when I change the `WHERE i = 40` into some other value, the
returned flag started to contain some additional information. I got lucky
because this additional information was the searched flag, so I solved this
task with my first attempt! :)

However, here is a part of the changed code ([unf_modified.sql]) of `unf.sql`
allowing us to choose the starting point.

```sql  
CREATE FUNCTION flag(idx integer) RETURNS text

⋮

SELECT c FROM r, dic WHERE i = idx AND r.a::TEXT[] @> dic.a ORDER BY j) AS
t$$;  
```

And here is a simple loop to iterate over each value

```sh  
$ dropdb unf  
$ createdb unf  
$ psql -U postgres -d unf < unf_modified.sql >> /dev/null  
$ echo "" > dump  
$ for i in {0..40}; do psql -U postgres -d unf -c "SELECT FLAG($i)" >> dump;
done;  
$ head -10 dump  
            flag                
-------------------------------  
}HarekazeCTFTh1rteen_0rphans{  
(1 row)

            flag                
-------------------------------  
HarekazeCTF{H}l$QX#iM72aZONT}  
(1 row)  
```

We see that for `i=0` the result is: `}HarekazeCTFTh1rteen_0rphans{` which
looks almost as the correct flag :)  

  
And the final flag is **HarekazeCTF{Th1rteen_0rphans}**

[operation.txt]:<./files/operation.txt>  
[unf.sql]:<./files/unf.sql>  
[unf_modified.sql]: <./unf_modified.sql>

Original writeup (https://github.com/terjanq/Flag-
Capture/tree/master/Harekaze2018/Unnormalized-form-Data#unnormalized-form-data
--write-up-by-terjanq).