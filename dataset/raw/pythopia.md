**Overview**

We are a give a python abstract syntax tree and have to reverse engineer four
checks for the flag.

Firstly, it compares if the key len is 64 and it splits them into key1, key2,
key3 and key4.

```  
If(  
   test=UnaryOp(  
       op=Not(),  
       operand=Compare(  
           left=Call(  
               func=Name(id='len', ctx=Load()),  
               args=[  
                   Name(id='key', ctx=Load())],  
               keywords=[]),  
           ops=[  
               Eq()],  
           comparators=[  
               Constant(value=64)])),  
   body=[

```

```  
Assign(  
   targets=[  
       Name(id='key1', ctx=Store())],  
   value=Subscript(  
       value=Name(id='key', ctx=Load()),  
       slice=Slice(  
           upper=Constant(value=16)),  
       ctx=Load())),  
   [...]

```

Then it defines some class KeyChkr and we notice a part of the flag that
should be key4 because it ends with `}`.

```  
If(  
   test=Compare(  
       left=Name(id='k', ctx=Load()),  
       ops=[  
           Eq()],  
       comparators=[  
           Constant(value='you_solved_it!!}')]),  
   body=[  
       Return(  
           value=Constant(value=True))],  
   orelse=[  
       Return(  
           value=Constant(value=False))])],

```

We then find 16 checks on each of the first 16 characters. We know this will
be key1 because it spells out the flag format.

```  
If(  
   test=Compare(  
       left=Subscript(  
           value=Name(id='key', ctx=Load()),  
           slice=Constant(value=0),  
           ctx=Load()),  
       ops=[  
           Eq()],  
       comparators=[  
           Constant(value='E')]),  
   body=[  
       If(  
           test=Compare(  
               left=Subscript(  
                   value=Name(id='key', ctx=Load()),  
                   slice=Constant(value=1),  
                   ctx=Load()),  
               ops=[  
                   Eq()],  
               comparators=[  
                   Constant(value='N')]),  
           body=[  
   [...]

```

key1 will be `ENO{L13333333333`.

Moving on to key2. The ast file points out the declaration of a list called
`vals`. It then xors every element of this list with 19 and compares it with
out input.

```  
       Assign(  
           targets=[  
               Name(id='vals', ctx=Store())],  
           value=List(  
               elts=[  
                   Constant(value=36),  
                   Constant(value=76),  
                   [...]  
                   Constant(value=120)],  
               ctx=Load())),  
       For(  
           target=Tuple(  
               elts=[  
                   Name(id='i', ctx=Store()),  
                   Name(id='k', ctx=Store())],  
               ctx=Store()),  
           iter=Call(  
               func=Name(id='enumerate', ctx=Load()),  
               args=[  
                   Name(id='key2', ctx=Load())],  
               keywords=[]),  
           body=[  
               Assign(  
                   targets=[  
                       Name(id='v', ctx=Store())],  
                   value=BinOp(  
                       left=Call(  
                           func=Name(id='ord', ctx=Load()),  
                           args=[  
                               Subscript(  
                                   value=Name(id='key2', ctx=Load()),  
                                   slice=Name(id='i', ctx=Load()),  
                                   ctx=Load())],  
                           keywords=[]),  
                       op=BitXor(),  
                       right=Constant(value=19))),  
               If(  
                   test=Compare(  
                       left=Name(id='v', ctx=Load()),  
                       ops=[  
                           NotEq()],  
                       comparators=[  
                           Subscript(  
                               value=Name(id='vals', ctx=Load()),  
                               slice=Name(id='i', ctx=Load()),  
                               ctx=Load())]),  
                   body=[  
                       Assign(  
                           targets=[  
                               Name(id='ok', ctx=Store())],  
                           value=Constant(value=False))],  
                   orelse=[])],  
           orelse=[]),

```

key2 will be `7_super_duper_ok`

The following part just checks key3 to be equal to the reverse of a given
string.

```  
body=[  
       If(  
           test=Compare(  
               left=Subscript(  
                   value=Name(id='k', ctx=Load()),  
                   slice=Slice(  
                       step=UnaryOp(  
                           op=USub(),  
                           operand=Constant(value=1))),  
                   ctx=Load()),  
               ops=[  
                   NotEq()],  
               comparators=[  
                   Constant(value='_!ftcnocllunlol_')]),  
           body=[  
               Return(  
                   value=Constant(value=False))],  
           orelse=[]),  
       Return(  
           value=Constant(value=True))],  
   decorator_list=[]),

```

key4 we already know, therefore the flag will be:

`ENO{L133333333337_super_duper_ok_lolnullconctf!_you_solved_it!!}`