# Write-up

## Intro  
This challenge gives a vim script  
To run the script, open vim, and input the command  
```  
:source task.vim  
```

## How did I solve this challenge  
A smart way is to build a compiler-like program that turns task.vim to ASM
like script, making knowing the logic easier.  
But I don't have programming skill QQ. So I only can use a stupid way to
approach this challenge.

Divide task.vim to smaller vim scripts, conquering every small scripts.

Use human brain to turn task.vim to python script :(

custom_task_auto.vim combines scripts

You can run scripts one by one, simulating dynamic analysis

## File

decoder.py : first version of python script that equivalent to the logic of
task.vim

decoder3.py : make first version of python more easier to understand

solve.py : written by [Frank Lin](https://github.com/eee4017) !  

Original writeup (https://github.com/LJP-
TW/CTF/tree/master/BalsnCTF-2019/reverse/vim).Vim is hard

Original writeup (https://blog.rpis.ec/2017/12/34c3ctf-vim.html).