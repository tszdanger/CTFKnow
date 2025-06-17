## Overview  
Elgyem's Password is a challenge from the ML category of UMDCTF 2023.  
Personally, I'm appreciate unique CTF chals, as long as they are well designed
(see [The Many Maxims of Maximally Effective
CTFs](https://web.archive.org/web/20220702025238/http://54.212.176.14/maxims.html)),
which this one was.  
That said, I myself wrote a ML challenge for Pico several years ago, so I'm
definitely biased.

In this challenge, we're provided a very simple ML model in Pytorch, its
parameters, and the output of a single sample.  
We're to figure out the associated input, in what Google says is a "model
inversion attack".

## Getting Things Running  
The first step is properly load the weights from [`model.txt`](model.txt) and
the calculated output from [`outputs.txt`](outputs.txt).  
During this process, two things stood out.

First, the model is very simple, consisting solely of linear layers.  
I've been working through [fast.ai](fast.ai) recently, and I remember that
linear layers consist of a matrix multiplication against a weight matrix, and
then the addition of a bias value.  
Normally, one has some sort of non-linear function between each layer, such as
sigmoid or ReLU.  
This allows the network to calculate more complex things, as multiple stacked
linear layers are mathematically equivalent to just a single layer.  
At the time, this struck me as odd, but without a clear reason as to why it'd
be designed this way.

```python  
model = nn.Sequential(  
   nn.Linear(22, 69),  
   nn.Linear(69, 420),  
   nn.Linear(420, 800),  
   nn.Linear(800, 85),  
   nn.Linear(85, 13),  
   nn.Linear(13, 37)  
)  
```

Second, the weights and output were given as fractions, with the output in
particular being given to high precision.  
PyTorch models normally have easier ways of passing models around, using
pickle (with associated security issues :O ), so this was also odd.  
Just like the model design however, I wasn't able to immediately think of a
reason why the challenge would be designed this way.  
There was some minor frustration with PyTorch not seemingly validating whether
or not the dimensions of each weight matrix was correct.

## Attempt 1: Fast Gradient Sign Method (FGSM)  
The first thing my team tried was using the [Fast Gradient Sign
Method](https://pytorch.org/tutorials/beginner/fgsm_tutorial.html).  
In short, FGSM is an adversarial example attack, used to craft inputs to a
neural network that produce a specified output.  
The classical FGSM example is attacking an image classifier, producing images
that appear to a human to be of one type, but the ML model classifies as
another.  
This is implemented by doing multiple rounds of back-propagation, but using
the produced gradient to update the input, rather than the model itself.a

Starting out, I naively expected that this would get us pretty close, and that
while the produced input would not be exactly an ASCII string, I'd be able to
manually adjust to get the flag.

However, our initial attempts at this didn't work. My teammate's
implementation got very close in the calculated error (using MSE, with an
error just above 10), the resulting input was not a flag, including several
negative numbers.  
From there, we both tried various methods of forcing the input to be in [0,
127), but that resulting in each input value saturating at 0 or 127, with
large error.

At this point, I decided to see if I could solve this using linear algebra on
its own, due to the model being entirely linear.

## Attempt 2: Pure Linear Algebra  
In considering what tool to use here, there were two requirements:  
- Proper numeric accuracy, with arbitrary precision rational numbers.  
- Linear algebra libraries, so I didn't have to implement things by hand.

[SageMath](https://www.sagemath.org/) supports both.  For handling rationals,
Sage has
[QQ](https://doc.sagemath.org/html/en/reference/rings_standard/sage/rings/rational_field.html),
which is arbitrary precision rational numbers.  
Additionally, it has the normal linear algebra support.  
My Sage Jupyter notebook for this section is
[here](https://doc.sagemath.org/html/en/reference/rings_standard/sage/rings/rational_field.html).

First, I needed to load all the values from the provided model and output
files, which is mostly the same as the first Python version.  
While I'm pretty sure that everything got loaded in QQ, I manually specified
this on all loading code, to avoid any inadvertent imprecise types  
Thankfully, since I'm doing all the matrix math here by hand, it'll complain
if the dimensions don't line up, unlike manual loading in PyTorch!

The next step is to figure out how to combine each linear layer.  
While there are multiple sources out there that say linear layers can be
combined, I didn't find something that actually had the math.  
Since my linear algebra background is rusty/non-existent, here it is by hand:

A single linear layer is  
$$  
a_{i-1} w_i + b_i = a_i  
$$  
where $a_i$ is the activation of layer $i$, and $a_0$ is the initial input.
$w_i$ is the weight matrix at layer $i$, and $b_i$ is the bias.

We can combine two layers with  
$$  
a_{i+2} = (a_{i-1} w_i + b_i) w_{i+1} + b_{i+1} = a_{i-1} w_i w_{i+1} + b_i
w_{i+1} + b_{i+1}  
$$

And thus combining multiple layers is

$$  
a_{j} = a_0 \prod_{i=0}^{j-1} w_i    + \sum_{i=0}^{j-1} b_i
\prod_{k=i+1}^{j-1} w_k  
$$

With some simple loops in Sage, I was able to calculate `W` and `B` (`big_w`
and `big_b` in the code), which are the combined weight and biases matrices.  
Note that `big_w` is a 22 x 37 matrix, which is notable more compact than the
original model, which had one layer of 420 x 800!

From there, we have a single, sort equation that we need to solve $aW + B =
o$, where $o$ is the provided output value, and $a$ is the original input.  
However, trying to use Sage's `solve_left` function here provided incorrect
answers. I made a test sample with inputs of $[0, \frac{1}{2}, 1,
1\frac{1}{2}...]$.  
Forward propagating it, and trying to solve, I was able to produce an input
and produced the same output, but was significantly off from the original
input.  
Furthermore, trying to do this with the actual provided output was wildly off!  
Looking under the hood, the Sage calculated inputs all had a bunch of $0$ s
fro the final 8 or so values in the input vector.

Having never formally taken linear algebra, this is where my skills personally
ran out on the math side.  
I do remember learning that not matrices are invertible (none of these were
square), and not all system of equations have exactly one solution.  
Figuring this was the case (confirmed after the competition), I needed another
solution.

## Attempt 3: Solving With Z3  
One potential issue with the linear algebra solution is that I was not able to
provide the solver with knowledge I have about the solution.  
In this case, I likely already know that the input should start with
`UMDCTF{`, and that each value likely is an integer.  
Enter Z3!  
Z3 allows us to set a number of constraints, and then solve.  Thus, we can
enter the simplified single equation we got from Sage, provide it the
additional guidance of the known starting values, and hit go!

After a couple of seconds, the flag appears: `UMDCTF{n3uR4Ln37w0rk5}`  

Original writeup
(https://github.com/WilliamParks/ctf_writeups/tree/master/umd_ctf_2023/Elgyems_Password).