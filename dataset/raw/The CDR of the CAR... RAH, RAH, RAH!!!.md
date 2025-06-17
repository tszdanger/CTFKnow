#  The CDR of the CAR... RAH, RAH, RAH!!!  
## Definition of The Problem

Here, the input of the problem is this list, we name it A :  
```  
('ascent','xray','yarbrough','jackal','minstrel','nevermore','outcast','kitten',  
'victor','pugnacious','wallaby','savant','zarf','tango','ultimatum','papyrus',  
'quill','renegade','llama','ghost','hellscape','industrious','zombification',  
'bestial','cadre','dark','efficacious','foundational')  
```

Also we have this cheer :  
```  
The CDR of the CAR!  
The CDR of the CAR!  
The CAR of the CDR of the CDR  of the CAR!  
The CAR of the CDR of the CDR of the CAR!  
```

This is symbolizing the recursive call string we are gonna have to use, thus :  
```  
C = cdr(car(cdr(car(car(cdr(cdr(car(car(cdr(cdr(car(B))))))))))))  
```

The mission is to obtain `C = ('pugnacious', 'wallaby', 'savant', 'zarf')`.

With the initial list A, we'll have to make a second list B to put in the
cheer to  
get the C output. So we'll have to reformat A into list and sublists.

## Resolution

ascending the recursive calls with the list A and making subgroups one after  
the other, we get the input B :

```  
(('ascent','xray',(('yarbrough','jackal',((('minstrel','nevermore','outcast','kitten'),  
('victor','pugnacious','wallaby','savant','zarf'),('tango','ultimatum','papyrus','quill','renegade',  
'llama','ghost','hellscape','industrious','zombification')),'bestial'),'cadre'),'dark'),  
'efficacious'),'foundational')  
```

### Validation Program

The following python program confirm our hypothesis :  
```python  
def car(a): return a[0]

def cdr(a): return a[1:]

b =
(('ascent','xray',(('yarbrough','jackal',((('minstrel','nevermore','outcast','kitten'),('victor','pugnacious','wallaby','savant','zarf'),('tango','ultimatum','papyrus','quill','renegade','llama','ghost','hellscape','industrious','zombification')),'bestial'),'cadre'),'dark'),'efficacious'),'foundational')

print(cdr(car(cdr(car(car(cdr(cdr(car(car(cdr(cdr(car(b)))))))))))))  
```

### Output

```  
('pugnacious', 'wallaby', 'savant', 'zarf')  
```