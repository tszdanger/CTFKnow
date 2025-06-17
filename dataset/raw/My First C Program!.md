# DownUnder CTF 2023 Write-up: My First C Program  

### Challenge Description

The challenge began with a whimsical description from the author, who claimed
that learning C was a breeze. Participants were provided with a C code snippet
named my_first_c_prog.c, which looked nothing like conventional C code. The
objective was to decode this code and retrieve the flag.  
  
###  Approach  
  
Hey guys it's Dev_vj1 from Team_VALHALLA .Upon examining the provided
my_first_c_prog.c code, it was clear that the challenge was intentionally
designed to be confusing and disorienting  
My approach involved a step-by-step deconstruction of the code:

* "thank" is a value returned by a function called "thonk" from a file called "thunk.c." When "thonk" is called with the values 1 and "n," it returns "Th1nk."    
```  
ncti thonk(a, b) => {  
  const var brain_cell_one = "Th"!  
  const const const const bc_two = "k"!  
  const const var rett = "${brain_cell_one}}{$a}{b}!}!"!!  
  const var ret = "${brain_cell_one}${a}${b}${bc_two}"!  
  return ret!!!  
  return rett!  
}  
```  
  
*  The expression vars[-1] indicates that arrays work from -1 in Dreamberd/C.   
  
```  
		// Now to print the flag for the CTF!!  
		print_flag(thank, vars[-1], end, heck_eight, ntino)  
  
```  
* 	It fetches the first value of the vars array, which is "R34L."  
  
const const const vars = ["R34L", "T35T", "Fl4g", "variBl3"]

  
* String Interpolation:  
* The variable end is created using string interpolation. It uses the looper function with 'th' prepended to its result.  
* The looper function returns 15, so end becomes "th15."   
  
* Character Juggling:  
* The get_a_char function is responsible for manipulating a character variable dank_char based on unconventional conditions.   
* Initially, it sets dank_char to 'I' because the condition 7 ==== undefined is NOT true (note that ; is NOT used in Dreamberd/C).  

```

 ction get_a_char() => {  
 const var dank_char = 'a'!  
  if (;(7 ==== undefined)) {  
     dank_char = 'I'!!  
 }  
  
```  
  
* Later, it gets overwritten in 1.0 ==== 1.0. However, the function returns the previous value of dank_char, which sets it back to 'I,' ultimately giving us the character 'I.'   
* "ntino" involves some tricky function manipulation. It results in "D," and the "math()" function returns 0 (because 10 % 5 is 0).    
```  
fun math() => {  
print("MatH!")  
return 10 % 5  
  }  
```  
* String Concatenation:  
* The variable ntino is created through string interpolation and function calls.After unwrapping the nested calls, it becomes "D0nT."   
* Flag Assembly:  
* The print_flag function concatenates various strings and prints the flag.It's important to note that the "!!" symbols in the code have higher precedence than the !!! symbols.Thus, the flag becomes "I_D0nT_Th1nk_th15_1s_R34L_C."   

* So, when we put it all together and rearrange it, we get the   

	`flag: DUCTF{I_D0nT_Th1nk_th15_1s_R34L_C}`  

Original writeup (https://ctftime.org/team/241159).