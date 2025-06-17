# CTFZone 2018 -- Help Mars!  
> **Category**: PPC, OSINT  
  
> **Description**:  
  
> Hello!  
  
> The Martians need your help. They are in contact with the H5N1 virus.  
> We know that there is a universal vaccine (locus HW306977) on our planet.  
> Find the substances on their planet that can be used to synthesize the
> vaccine.  
> A large sample database is at your disposal.  
  
> [mars_dna_samples.zip](./mars_dna_samples.zip).  
  
> Your task is to select the right combination of samples (recipe). Result is  
> the shortest (lowest count of samples used to synthesize the vaccine). If
> you  
> find more than one shortest recipe - select the one, which has the longest
> code  
> in each sample from start to end.  
  
> Example:  
  
> Code: 123456  
  
> Samples (id,code):  
  
> 1,4  
  
> 2,6  
  
> 3,12  
  
> 4,34  
  
> 5,56  
  
> 6,45  
  
> 7,123  
  
> Available combinations  
  
> 12-34-56  
  
> 123-45-6  
  
> 123-4-56  
  
> Solving: 123 + 45 + 6  
  
> Result: 7,6,2  
  
> Flag is ctfzone{md5(Result)}

# Writeup

## Googling  
To get the flag you first need to find genom sequence of H5N1 virus.
Unfortunately,  
there are lots of variants of this virus, and HW306977 hasn't been indexed by
google.

So it took some time to find data archive of biology things, and here we found  
a [record about HW306977](https://www.ncbi.nlm.nih.gov/nuccore/HW306977).

## Algorithm  
### Method  
The task is typical for [dynamic
programming](https://en.wikipedia.org/wiki/Dynamic_programming).

We have a target sequence and hashmap sample_seq -> sample_ind, lets write a
recursive function  
that returns the smallest sequence of samples (only theirs ids) for some
suffix of the  
sequence: `f(suffix)`.

### Cache  
The most important thing in dynamic programming is caching result of `f(..)`.
If you can cache them,  
your algorithm will be fast enoughh, if you don't it's polynomial asymptotic.

### Base case  
If the suffix is empty, then the answer is obvious: `[]`.

### Body of recursion  
After base case was checked, check that this prefix wasn't computed yet.  
If it was, return the cached answer. If it wasn't, do this:

```python  
def f(suffix):  
   # ... check for the base case  
   # ... look for a computed value in cache  
   best = None  
   for i in xrange(1, min(max_sample_len, len(suffix))+1):  
       if suffix[:i] not in sample_to_ind: continue  
       current = f(suffix[i:])  
       if (best is None and current is not None) or (best is not None and current is not None and len(best) > len(current)):  
           current.append(sample_to_its_ind[suffix[:i]])  
           best = current  
   # ... caching  
   return best  
```

## Solver  
[Here](./solve.py) you can take a look at my solver.  

Original writeup
(https://github.com/sibears/writeups/tree/master/CTFZone%202018/HelpMars).