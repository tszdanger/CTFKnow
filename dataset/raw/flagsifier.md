Flagsifier  
----------  
This challenge consisted in finding the correct input for a Deep Neural
Network  
that classifies images (size: `1064x28`) and has 40 output neurons.

There were some example images, composed of 38 letters from what looked like
the EMNIST dataset.  
All of them activated the fourth neuron, therefore being classified as the
fourth class.

Some quick tests by moving around random letters and removing some others
(plus, the structure  
of the network) hinted us that there was a softmax and the classes were
represented as one-hot  
encoding. Therefore, the network classifies images into 40 classes. Time to
discover what they are!

So, at first we transcribed the sample images and used the combination  
of tile + corresponding text as dataset.

```python  
dataname=["RUNNEISOSTRICHESOWNINGMUSSEDPURIMSCIVI",  
       "MOLDERINGIINTELSDEDUCINGCOYNESSDEFIECT",  
       "AMADOFIXESINSTIIIINGGREEDIIVDISIOCATIN",  
       "HAMIETSENSITIZINGNARRATIVERECAPTURINGU",  
       "ELECTROENCEPHALOGRAMSPALATECONDOIESPEN",  
       "SCHWINNUFAMANAGEABLECORKSSEMICIRCLESSH",  
       "BENEDICTTURGIDITYPSYCHESPHANTASMAGORIA",  
       "TRUINGAIKALOIDSQUEILRETROFITBIEARIESTW",  
       "KINGFISHERCOMMONERSUERIFIESHORNETAUSTI",  
       "LIQUORHEMSTITCHESRESPITEACORNSGOALREDI"]  
```  
(Finding typos in this transcription is left as an exercise to the reader  
:smile: )

After that we divided all the sample images in 38 28x28-tiles (one tile per  
letter).  
We have done that using this script:

```python  
dataset=[]  
datalet=[]  
datax={}

for i in range(0,8):  
   img = Image.open('./sample_%d.png'%i)  
   for j in range(0,38):  
       x=img.crop((j*28,0,(j+1)*28,28))  
       dataset.append(x)  
       datalet.append(dataname[i][j])  
       let=dataname[i][j]  
       if let not in datax:  
           datax[let] = []  
       datax[let].append(len(dataset)-1)  
```

* `dataset` contains the images.  
* `datalet[i]` contains the corresponding text of `dataset[i]`.  
* `datax` contains the  mapping between letters and array of samples. Basically  
it answers to questions like: "which dataset entries correspond to a
particular  
letter?"

Then, we experimented as follows: for each letter, starting from a black
image,  
put the letter in position 0...38, and classify these images. We saved all the  
predictions, and then averaged them to see the most likely class for each
letter.

We discovered that neurons 14...40 clasified letters: neuron 14 activated for
A,  
neuron 15 for B, up to neuron 40 for Z.

We then need to discover what the neurons 1...14 classify, as some of them
probably  
classify the flag.  
To do that, we need to try to find inputs that maximize the activation of
these, one at  
a time. Another thing that we can leverage is that the flag likely starts by
`OOO`.

So, what would one usually do here, with a "real" network? Decide which neuron
(e.g.,  
the first) to try to activate, then create random 38-letters inputs, and then
use the  
log-likelihood of that neuron for that input as the fitness function for his
favourite  
optimization algorithm (e.g., this problem looked perfect for genetic
algorithms).

But before throwing cannons to the problem, let's try something simpler (and
if it fails,  
move to more advanced but computationally intensive stuff).  
The suspect here is that the network is trained on a small dataset, and is
strongly  
overfitting the flag on some of the "low" neurons. This could maybe mean that  
the function we need to optimize is not crazily non-linear and with tons of
local optima  
that require complex optimization algorithms to escape from. Therefore we
tried with  
a simple greedy strategy: for each of the 38 positions, pick the letter that
maximizes the  
output of the target neuron. And it worked!

Trying `OOO` as a test string showed activation of neurons 2 and 3 - let's
focus on them.

### Results

Neuron 2 has been our first guess, which gave us these (highly noisy) strings,  
with the greedy strategy:  
```  
OOOOTHISISBYKCOZMEKKAGETONASTEYOUATIMW  
OOOOTHISISBYKCOZMKYKAGZTONBSTWVOUATIWM  
OOOOTNISISBDKCOZMKSGBGETONMSTXVOUWTIRR  
OOOOTOISISOYECOIUEYSOGETONOSTNVOUOTIWW  
```

We tried (failing) to submit some flags like  
* `OOOOTHISISBYKCOZMESSAGETOHASTEYOLATINE`  
* `OOOOTHISISBYKCOZMESSAGETOHASTEYOLATINW`  
* ...

After realizing that neuron 2 was just a test-neuron, we changed output neuron  
from 2nd to 3rd and we got sentences like:

```  
OGOSOMEAUTHTNTICINTEIXIGXNCCISVEGUIWEG  
OOOSOMRAUTHGNTICINTGIIIGGNGGISMRGUIWEG  
OOOSOMXAUTHENTICINTEKXIGXNCRISRRRRIRER  
OOOSOYEOLTUTNTICINTEIIIGCNCEIIETOLIRTI  
RROSOMEAUTHTNTICINTEIXIGXNCCISVEGUIWEG  
```

We obtained `OOOSOMEAUTHENTICINTELLIGENCEIS........` by averaging (and
manually  
correcting) them and after few tries of guessing ( :bowtie: ) the last word we  
obtained the correct flag: `OOOSOMEAUTHENTICINTELLIGENCEISREQUIRED`.

### Python script  
You can find here the full python script we have used (keras + tensorflow-
gpu):

```python  
#!/usr/bin/env python

import numpy as np  
from keras.models import load_model  
from keras.preprocessing import image  
from keras.datasets import mnist  
from keras.applications.resnet50 import preprocess_input, decode_predictions

from PIL import Image, ImageDraw, ImageFont  
import string, random, sys

dataset=[]  
datalet=[]  
datax={}  
dataname=["RUNNEISOSTRICHESOWNINGMUSSEDPURIMSCIVI",  
       "MOLDERINGIINTELSDEDUCINGCOYNESSDEFIECT",  
       "AMADOFIXESINSTIIIINGGREEDIIVDISIOCATIN",  
       "HAMIETSENSITIZINGNARRATIVERECAPTURINGU",  
       "ELECTROENCEPHALOGRAMSPALATECONDOIESPEN",  
       "SCHWINNUFAMANAGEABLECORKSSEMICIRCLESSH",  
       "BENEDICTTURGIDITYPSYCHESPHANTASMAGORIA",  
       "TRUINGAIKALOIDSQUEILRETROFITBIEARIESTW",  
       "KINGFISHERCOMMONERSUERIFIESHORNETAUSTI",  
       "LIQUORHEMSTITCHESRESPITEACORNSGOALREDI"]

for i in range(0,8):  
   img = Image.open('./sample_%d.png'%i)  
   for j in range(0,38):  
       x=img.crop((j*28,0,(j+1)*28,28))  
       dataset.append(x)  
       datalet.append(dataname[i][j])  
       let=dataname[i][j]  
       if let not in datax:  
           datax[let] = []  
       datax[let].append(len(dataset)-1)

def genImg(n):  
   img = Image.new('1', (1064,28), color='black')  
   #for i in range(max(0,len(n)-1),len(n)): # only this letter and everything
else black  
   for i in range(0,len(n)):  
       img.paste(dataset[n[i]], (i*28,0))  
   return img

model = load_model('model.h5')  
model.compile(loss='binary_crossentropy', optimizer='rmsprop',
metrics=['accuracy'])

def eeval2(a, op):  
   img = genImg(a)  
   x = image.img_to_array(img)  
   x = np.expand_dims(x, axis=0)  
   classes = model.predict(x)  
   score = float(classes[0][op])  
   return score

for oo in range(2,40): # start from 2, this one seems correct  
#   out=[datax[x][0] for x in 'OOOSOMEAUTHENTICINTELLIGENCEIS'] #do not start
from zero  
   out=[]  
   for i in range(len(out),38):  
       maxv=([], -99999)  
       for j in datax:  
           for k in datax[j]:  
               out.append(k)  
               score = eeval2(out, oo)  
               if score > maxv[1]:  
                   maxv = (0, score, j)  
               out.pop()

       sys.stdout.write("[%d] %38s : %.10lf      \r" % (oo, ''.join([datalet[x] for x in out]), maxv[1]))  
       sys.stdout.flush()  
       out.append(datax[maxv[2]][0])

   print("")  
   print("--Neuron %d: %s" % (oo, ''.join([datalet[x] for x in out])))  
```  

Original writeup
(https://mhackeroni.it/archive/2018/05/20/defconctfquals-2018-all-
writeups.html#flagsifier).