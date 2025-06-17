> To solve this task, you need to put arithmetic operators into expression in
> the right order.  
> Allowed operators: + - / * (). Final expression must involve all the
> supplied numbers and the number order must be the same as in original
> expression. The last nuber in the line should be an answer.  
> nc ppc-01.v7frkwrfyhsjtbpfcppnu.ctfz.one 2445  
>  
>Example:  
>```  
>2 3 5 4  
>(2-3)+5  
>```  
-----  
**Solution:** Try all possibilities.

How to do this in a simple way?

Every arithmetic expression can be expressed as a (binary) expression tree
where the inner nodes are the operators and the leaves are the numbers:  
```  
        +  
      /   \  
     -     5  
   /  \  
  2    3  
```  
*Notice how the parenthesis disappeared?*

Now we can easily build all these binary trees with a recursive function and
to get the normal string representation we just insert parenthesis in every
step (we do not care if some of them could be omitted without changing the
result).

The input is a list of numbers and the output all possible results when
inserting arithmetic operators. The functions tries all possibilities to split
the list in 2 sublists and inserts one by one all 4 operations at the
splitting position. The task requires to keep the numbers in the same order,
therefore we really just have to split the list at some point.

> Example:  
>  
> Take the list [2 3 5] (4 is the result, we do not need this here)  
>  
> There are 2 possibilities to split the list into to: { [2], [3 5] } and { [2
> 3], [5] }

The evaluation of a list with exactly one element (a leave node) is just the
number itself. If the list is larger, we recursivly call the function again
with the smaller list.

An example is probably easier to understand, so:

> solve list [2 3 5] to get result 4  
>  
> try [2 3] o [5] and [2] o [3 5] where o is one of the 4 operators  
>  
> using [2 3], we can get 4 different results: { 5 (=2+3), -1 (=2-3), 6
> (=2*3), 0.666 (=2/3) } = { 5, -1, 6, 0.666 }  
>  
> using [5], we can only get { 5 }  
>  
> in the case of [2 3] o [5], we have 4 possibilities for 'o' and 4
> possibiliteis for the left result and one for the right -> 16 possible
> results:  
>  
```  
{ 10, 4, 11, 5.666  ,  0, -6, 1, -4.333,   25, -5, 30, 3.333,  1, -0.2, 1.2,
0.1333}  
using +                   using -               using *
using /  
```  
>  
>   we can do the same for the [2] o [3 5] case to get another 16
> possibilities. At least one of those 32 results will be the requested 4.

Here is the code used. (it is not a very clean solution).  
Hopefully the comments are enough to understand it.  
For remarks about speed improvements, see below.  
```  
# recursive function  
# INPUT: nums := list of numbers to be used  
#        erg  := expected result or None if doesn't matter  
# RETURN: if 'erg' is set: a string that evaluates to 'erg'  
#                 else: a list with all possible results that can be achieved  
def solve(nums, erg = None):  
	if len(nums) == 1: # leave node  
		if erg != None: # we need a result of exactly 'erg'  
			if float(nums[0]) == erg:  
				return nums[0] # the only number we have equals the number we need   
			else:  
				return None # this should never happen, proof omitted  
		else:  
			return [float(nums[0])] # all possible results is just this number  
	# otherwise we will simulate a new inner node ...  
	ergs = [] # here we collect all possible results  
	for i in range(1, len(nums)): # we iteratore over all splitting positions  
		a = solve(nums[:i]) # a := list of all numbers possible in the left subtree  
		b = solve(nums[i:]) # b := list of all numbers possible in the right subtree  
		for ai in a:     #  | try all combinations with results from left  
			for bi in b: #  |  with all those from right subtree  
				if erg != None:  
					# we want the result to be exactly 'erg'  
					# therefore we check all operators and when we found a match ...  
					# ... we return a string that evaluates the expected result  
					# we do not know the ai can be constructed => we do the   
					# the recursive call again, but this time  
					# with the 'erg' argument supplied  
					if float(ai + bi) == float(erg):  
						return "(" + solve(nums[:i], ai) + " + " + solve(nums[i:], bi) + ")"  
					if float(ai - bi) == float(erg):  
						return "(" + solve(nums[:i], ai) + " - " + solve(nums[i:], bi) + ")"  
					if float(ai * bi) == float(erg):  
						return "(" + solve(nums[:i], ai) + " * " + solve(nums[i:], bi) + ")"  
					if bi != 0 and ai / float(bi) == float(erg):  
						return "(" + solve(nums[:i], ai) + " / " + solve(nums[i:], bi) + ")"  
				else: # we do not care for a specific result (yet), so just collect all  
					if bi != 0: # avoid division by 0  
						ergs += [ai + bi, ai - bi, ai * bi, ai / float(bi)]  
					else:  
						ergs += [ai + bi, ai - bi, ai * bi]  
	return ergs  
```

## Complexity and Improvements  
The number of different trees with n leave nodes is the n-1-th [catalan
number](https://en.wikipedia.org/wiki/Catalan_number). The problem uses up to
8 numbers -> C_7 is 417. There are 7 inner nodes with 4 possibilities each:
4^7 * 417 <= 7.000.000 possibilites to check -> close to no time required for
solving.  
However, the solution can be optimized:  
* Subtrees are computed multiple times -> use memoization to save all results possible for a range of numbers  
* After finding all results in the left subtree, we could already call the right subtree with a supplied 'erg' that will fit the required result. Just need to handle the "return None" case then for impossible subtrees.