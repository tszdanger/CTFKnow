**Description**

> Can you help this restaurant Stack the right amount of Eggs in their ML
> algorithms?  
>  
> Guest challenge by Tethys.  
>  
> Note that you need to send a shutdown(2) after you sent your solution. The
> nmap netcat will do so for you, e.g.: `ncat 35.246.237.11 1 < solution.xml`  
>  
> > `/usr/bin/ncat --help | grep -n 1 Ncat 7.60 ( https://nmap.org/ncat )`  
>  
> Files here:
> https://35c3ctf.ccc.ac/uploads/juggle-f6b6fa299ba94bbbbce2058a5ca698db.tar

**Files provided**

- [juggle.tar](https://35c3ctf.ccc.ac/uploads/juggle-f6b6fa299ba94bbbbce2058a5ca698db.tar)

**Solution**

At first I wanted to completely skip this challenge because I thought "ML" in
the description referred to Machine Learning, not an uncommon theme in
difficult CTF challenges. But I'm really glad I got back to it eventually!

In the archive we are given two files:

- `Dockerfile` - contains the script for deploying a Docker container for this challenge, and its run command, which invokes [Xalan](https://xalan.apache.org/)  
- `challenge.min.xslt` - an [XSLT (Extensible Stylesheet Language Transformations)](https://en.wikipedia.org/wiki/XSLT) file, minified

The first step is to tidy up the `challenge` file with some auto format.

[Auto-formatted
`challenge.xslt`](https://github.com/EmpireCTF/empirectf/blob/master/writeups/2018-12-27-35C3-CTF/files/challenge.xslt)

At this point we can start dissecting the file more comfortably, one bit at a
time. The root element, `<xsl:stylesheet>` specifies some XLST "libraries",
[`math`](http://exslt.org/math/) and
[`common`](http://exslt.org/exsl/index.html). It has two child nodes. The
first is a template that matches on `/meal` elements. Based on the description
we will have to send the challenge server an XML file, so it seems the root
element of our file will be `<meal>`. The other is a template with a name, but
no element match, so it will be invoked indirectly by the XSLT itself.

Let us have a closer look at the first template, matching on `/meal`. First,
there is an assertion:

```xml  
<xsl:if test="count(//plate) > 300">  
 <xsl:message terminate="yes">You do not have enough money to buy that much
food</xsl:message>  
</xsl:if>  
```

If we have more than 300 `<plate>` elements in our submission, the above
message is printed and the process is stopped (`terminate="yes"`). Note also
the fact that plates are counted with `//plate`, i.e. nested two levels deep
(including `<meal>`).

Next, a variable called `chef-drinks` is defined:

```xml  
<xsl:variable name="chef-drinks">  
 <value><xsl:value-of select="round(math:random() * 4294967296)"/></value>  
 <value><xsl:value-of select="round(math:random() * 4294967296)"/></value>  
 <value><xsl:value-of select="round(math:random() * 4294967296)"/></value>  
 <value><xsl:value-of select="round(math:random() * 4294967296)"/></value>  
 <value><xsl:value-of select="round(math:random() * 4294967296)"/></value>  
</xsl:variable>  
```

It seems to be an array of five randomly generated 32-bit unsigned integers
(`4294967296 = 0x100000000 = 2^32`).

Finally, the other template is "called", like a function:

```xml  
<xsl:call-template name="consume-meal">  
 <xsl:with-param name="chef-drinks" select="exsl:node-set($chef-
drinks)//value"/>  
 <xsl:with-param name="food-eaten" select="1"/>  
 <xsl:with-param name="course" select="course[position() = 1]/plate"/>  
 <xsl:with-param name="drinks" select="state/drinks"/>  
</xsl:call-template>  
```

The `chef-drinks` variables is given as-is. `food-eaten` is initialised at
`1`. `course` is set to all `<plate>` elements in the first `<course>` element
of our `<meal>` submission. And finally, `drinks` is initialised to the
`<drinks>` element in `<state>`.

Before looking into what `consume-meal` does, we already know / can guess our
submission will have this shape:

```xml  
<meal>  
 <course>  
   <plate>?</plate>  
   <plate>?</plate>  
   ...  
 </course>  
 <course>...</course>  
 ...  
 <state>  
   <drinks>  
     ?  
   </drinks>  
 </state>  
</meal>  
```

Now we can move onto `consume-meal`. Its first lines declare the parameters we
already know about – `chef-drinks`, `food-eaten`, `course`, and `drinks`. Then
there are two assertions:

```xml  
<xsl:if test="$food-eaten > 30000">  
 <xsl:message terminate="yes">You ate too much and died</xsl:message>  
</xsl:if>  
<xsl:if test="count($drinks) > 200">  
 <xsl:message terminate="yes">You cannot drink that much</xsl:message>  
</xsl:if>  
```

Both of these seem to be fatal errors. Since `food-eaten` was initialised at
`1`, the first assertion would only make sense if `consume-meal` was called
multiple times. And indeed, if we scroll a bit further, we will find that
`consume-meal` is called again from within itself, i.e. it is recursive. At
each step, it increases `food-eaten` by one. In other words, `food-eaten` is a
step counter that cannot go above 30000.

By similar logic, `drinks` must be modified within `consume-meal`, otherwise
this assertion could have been made before the initial call. Whatever `drinks`
are, we cannot have more than 200 of them.

Finally, we move on to the core of the XSLT. If we have any elements in
`$course`, we initialise a couple of variables:

```xml  
<xsl:if test="count($course) > 0">  
 <xsl:variable name="c" select="$course[1]"/>  
 <xsl:variable name="r" select="$course[position()>1]"/>  
 <xsl:choose>  
   ...  
 </xsl:choose>  
</xsl:if>  
```

`c` will refer to the first element of `$course` (since in XML land lists are
1-indexed), and `r` will refer to the remaining elements. Note at this point
that `$course` does NOT refer to our `<course>` elements. Recall that
`consume-meal` was invoked with `<xsl:with-param name="course"
select="course[position() = 1]/plate"/>`, so `$course` will contain the
`<plate>` elements of our first `<course>` (on the first iteration).

So with an input like:

```xml  
<meal>  
 <course>  
   <plate><foo/></plate>  
   <plate><bar/></plate>  
   <plate><baz/></plate>  
 </course>  
 ...  
</meal>  
```

During the first call to `consume-meal`, `$c` will be `<plate><foo/></plate>`,
and `$r` will be the list of `<plate><bar/></plate>` and
`<plate><baz/></plate>`.

After `$c` and `$r` are initialised, there is a large `<xsl:choose>` block,
equivalent to a `switch` statement in conventional programming languages. The
`<xsl:choose>` element checks to see what is "in" our plates, i.e. what
elements are contained in our `<plate>` element. Let us have a look at one of
these choices:

```xml  
<xsl:when test="count($c/paella) = 1">  
 <xsl:variable name="newdrinks">  
   <value>  
     <xsl:value-of select="$c/paella + 0"/>  
   </value>  
   <xsl:copy-of select="$drinks"/>  
 </xsl:variable>  
 <xsl:call-template name="consume-meal">  
   <xsl:with-param name="chef-drinks" select="$chef-drinks"/>  
   <xsl:with-param name="food-eaten" select="$food-eaten + 1"/>  
   <xsl:with-param name="course" select="$r"/>  
   <xsl:with-param name="drinks" select="exsl:node-set($newdrinks)//value"/>  
 </xsl:call-template>  
</xsl:when>  
```

In other words, if our `<plate>` contained a `<paella>` element, we will
invoke `consume-meal` again with slightly modified parameters:

- `chef-drinks` - `chef-drinks` (the 5 random numbers) remain the same  
- `food-eaten` - increased by one  
- `course` - `$r`, i.e. the remaining plates of this `<course>`  
- `drinks` - `$newdrinks`, created just above, consisting of some value (contained within our `<paella>` element) prepended to the original `$drinks`

By this point it should be pretty clear that this XSLT is in fact a virtual
machine! Each `<plate>` will contain an instruction which will modify the
state and pass that state onto the next invocation of `consume-meal`. The
`<course>` elements are blocks of instructions, in essence behaving like
labels. `drinks` are in fact our stack. With a `<paella>` instruction we can
push an immediate value to our stack. We can analyse all the instructions one
by one:

- `宫保鸡丁` - debug command, prints `chef-drinks` as well as `drinks`  
- `paella` - push immediate value to stack  
- `불고기` - duplicate a given element of the stack and push it  
- `Борщ` - pop top element of `chef-drinks` if it matches top of `drinks`  
- `दाल` - print the flag if no `chef-drinks` remain  
- `ラーメン` - push 1 if top of `drinks` is greater than top of `chef-drinks`, 0 otherwise  
- `stroopwafels` - push 1 if 2nd value in `drinks` is greater than top value in `drinks`  
- `köttbullar` - move a given element from `drinks` to the top  
- `γύρος` - remove a given element from `drinks`  
- `rösti` - add top elements of `drinks`  
- `לאַטקעס` - subtract top elements of `drinks`  
- `poutine` - multiply top elements of `drinks`  
- `حُمُّص` - integer divide top elements of `drinks`  
- `æblegrød` - jump to a given `<course>` if top of `drinks` is not 0

A limited instruction set, but Turing-complete nonetheless. Of particular note
is `दाल` - prints the flag if (and only if) there are no more `chef-drinks`.
In fact the 5 random numbers generated at the beginning form an additional
stack, one that we cannot directly manipulate. The debug command `宫保鸡丁` prints
out the values of `chef-drinks` (as well as our `drinks`), but this is indeed
only useful for debugging – each time we run our XML on the server, the
numbers are different, and we have no way to send what we saw from the debug
command back to the XML file we submitted.

So our XML needs to run instructions that will guess the `chef-drinks` (using
`Борщ`) one by one, without seeing their values. The only other instruction
dealing with `chef-drinks` is `ラーメン`, which compares the top of our stack
`drinks` with the top of the challenge stack `chef-drinks`.

In other words, we need to implement a binary search. We can adapt the pseudo-
code for [binary search from Rosetta
code](http://rosettacode.org/wiki/Binary_search):

   BinarySearch(A[0..N-1], value) {  
       low = 0  
       high = N - 1  
       while (low <= high) {  
           // invariants: value > A[i] for all i < low  
                          value < A[i] for all i > high  
           mid = (low + high) / 2  
           if (A[mid] > value)  
               high = mid - 1  
           else if (A[mid] < value)  
               low = mid + 1  
           else  
               return mid  
       }  
       return not_found // value would be inserted at index "low"  
   }

Since we only have `>`, the code we will implement is:

   high = 0x100000000;  
   low = 0;  
   while (high > low) {  
     var mid = (low + high) >> 1; // integer divide by two  
     if (mid + 1 > number) {  
       high = mid;  
     } else {  
       low = mid + 1;  
     }  
   }

During the CTF, I chose to implement a simple assembler. I was particularly
worried about Unicode messing up my instructions (RTL marks, non-canonical
ordering, bad copypaste), but of course labels and a minimum of type safety
was a plus. Debugging wasn't particularly easy with the remote server, so at
some point I also implemented an emulator to test my code.

[Full assembler/emulator script
here](https://github.com/EmpireCTF/empirectf/blob/master/writeups/2018-12-27-35C3-CTF/scripts/Juggle.hx)

```bash  
$ haxe -D EMULATE --run Juggle  
ins(0): PUSHI(0); stack: 0  
ins(1): PUSHI(8388608); stack: 8388608,0  
ins(2): PUSHI(1); stack: 1,8388608,0  
ins(3): PUSHI(1); stack: 1,1,8388608,0  
ins(4): JMP; stack: 8388608,0  
ins(0): PUSHI(2); stack: 2,8388608,0  
ins(1): PUSHI(1); stack: 1,2,8388608,0  
ins(2): DUPN; stack: 8388608,2,8388608,0  
ins(3): PUSHI(3); stack: 3,8388608,2,8388608,0  
ins(4): DUPN; stack: 0,8388608,2,8388608,0  
...  
... etc etc  
...  
ins(0): PUSHI(0); stack: 0,6830991,6830991  
ins(1): DROP; stack: 6830991  
ins(2): CHECK; checking 6830991 against 6830991 ... OK!  
stack:  
ins(3): END; flag!  
```

The submission generated is available
[here](https://github.com/EmpireCTF/empirectf/blob/master/writeups/2018-12-27-35C3-CTF/scripts/sol.xml).
After running it on the server, we get the flag:

`35C3_The_chef_gives_you_his_compliments`

Original writeup
(https://github.com/EmpireCTF/empirectf/blob/master/writeups/2018-12-27-35C3-CTF/README.md#97-rev
--juggle).