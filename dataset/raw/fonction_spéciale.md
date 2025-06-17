# fonction_spéciale

Info:  
- Category: crypto  
- Points: 240  
- Solved by: 01b4f

## Problem

Selon une mission secrète du gouvernement pour un ordinateur doté
d'intelligence, une fonction mathématique spéciale a été développée. Voici des
exemples de ses entrées et sorties:

```  
f(2522521337)=1215221512112317
f(1215221512112317)=1112111522111511122112131117
f(1112111522111511122112131117)=31123115223115312221121113317  
```

Puisque l'intelligence artificielle ne veut plus nous obéir, nous avons besoin
de votre aide pour trouver le résultat de la fonction

```  
f(2229555555768432252223133777492611)=x  
```

Le drapeau a la forme kks{x}.  
Dans la composition de cette fonction, j'ai été aidé par un écrivain avec les
initiales B. W., qui aime aussi les énigmes, comme nous et vous ;)

### Writeup

The challenge consists of forecasting a mathematical function result by having
in example 3 of its application.  
The idea is to find some pattern knowing that:  
- Between the number of digits in input and those in output there isn't any evident regularity;  
- Digits that appears in input, also appears in output.

#### Steps  
1. Group any recurrence of the same digit:  
	```  
	1215221512112317 --> [1][2][1][5][22][1][5][1][2][11][2][3][1][7]  
	```  
2.  For each group, two digits are produced: the first tells how much that digit repeat itself; the second tells the considered group digit. So:  
	```  
	[1]-->11	(1 times 1)  
	[2]-->12	(1 times 2)  
	[5]-->15	(1 times 5)  
	[22]-->22	(2 times 2)  
	[11]-->21	(2 times 1)  
	[3]-->13	(1 times 3)  
	[7]-->17	(1 times 7)  
	```  
3. Thus coming to have the output:  
	```  
	1112111522111511122112131117  
	```  
  
  
#### Resolution  
Having in input "2229555555768432252223133777492611"  
Let's produce groups of recurring digits:  
```  
[222][9][555555][7][6][8][4][3][2][5][222][3][1][33][777][4][9][2][6][11]  
```  
Obtaining:  
```  
32_19_65_17_16_18_14_13_12_15_32_13_11_23_37_14_19_12_16_21  
```

### Flag:  
```  
kks{3219651716181413221532131123371419121621}  
```  

Original writeup
(https://github.com/r00tstici/writeups/tree/master/kksCTF_2020/fonction_spéciale).