# Labyrinth

* Category: Dev  
* 150 points  
* Solved by JCTF Team

## Description

Given a remote server address

## Solution

As you can guess, it is a development challenge.  
  
In this challenge we get five links for images of [Where's
Wally?](https://en.wikipedia.org/wiki/Where%27s_Wally%3F) and should reply
with the coordinates of wally in the image within seconds.  
  
Obviously we don't have time to find him by eyes, so let's throw ML on him!  
  
LMGTFY - we found [HereIsWally](https://github.com/tadejmagajna/HereIsWally)
on GitHub.  
  
After some configuration and downloads, we managed to run
[find_wally.py](https://github.com/tadejmagajna/HereIsWally/blob/master/find_wally.py)
on one of the images and get the corret coordiates of Wally. Good work
tadejmagajna!

Now we just had to add a little automation to get the images, run the
detection function, normalize the coordinates and convert them to int, and
send them back to the server.  
  
This is the full script:

```python  
import numpy as np  
import sys  
import tensorflow as tf  
from PIL import Image  
from object_detection.utils import label_map_util  
from object_detection.utils import visualization_utils as vis_util

model_path = './trained_model/frozen_inference_graph.pb'

from pwn import *  
import requests # to get image from the web  
import shutil # to save it locally

conn = remote('labyrinth.ctf.bsidestlv.com',5000)  
for i in range(5):  
   conn.recvuntil('https', drop=True)  
   image_url  = 'https'+conn.recvuntil('jpg')  
   image_path = image_url.split("/")[-1]  
   print(image_path)  
   r = requests.get(image_url, stream = True)

   # Check if the image was retrieved successfully  
   if r.status_code == 200:  
       # Set decode_content value to True, otherwise the downloaded image file's size will be zero.  
       r.raw.decode_content = True

       # Open a local file with wb ( write binary ) permission.  
       with open(image_path,'wb') as f:  
           shutil.copyfileobj(r.raw, f)

       print('Image sucessfully Downloaded: ',image_path)  
   else:  
       print('Image Couldn\'t be retreived')

   detection_graph = tf.Graph()  
   with detection_graph.as_default():  
       od_graph_def = tf.GraphDef()  
       with tf.gfile.GFile(model_path, 'rb') as fid:  
           serialized_graph = fid.read()  
           od_graph_def.ParseFromString(serialized_graph)  
           tf.import_graph_def(od_graph_def, name='')

   def load_image_into_numpy_array(image):  
     (im_width, im_height) = image.size  
     return np.array(image.getdata()).reshape(  
         (im_height, im_width, 3)).astype(np.uint8)

   label_map = label_map_util.load_labelmap('./trained_model/labels.txt')  
   categories = label_map_util.convert_label_map_to_categories(label_map,
max_num_classes=1, use_display_name=True)  
   category_index = label_map_util.create_category_index(categories)

   with detection_graph.as_default():  
     with tf.Session(graph=detection_graph) as sess:  
       image_np = load_image_into_numpy_array(Image.open(image_path))  
       image_tensor = detection_graph.get_tensor_by_name('image_tensor:0')  
       boxes = detection_graph.get_tensor_by_name('detection_boxes:0')  
       scores = detection_graph.get_tensor_by_name('detection_scores:0')  
       classes = detection_graph.get_tensor_by_name('detection_classes:0')  
       num_detections = detection_graph.get_tensor_by_name('num_detections:0')  
       # Actual detection.  
       (boxes, scores, classes, num_detections) = sess.run(  
           [boxes, scores, classes, num_detections],  
           feed_dict={image_tensor: np.expand_dims(image_np, axis=0)})

       if scores[0][0] < 0.1:  
           sys.exit('Wally not found :(')

       width, height = Image.open(image_path).size  
       print('Wally found')  
       vis_util.visualize_boxes_and_labels_on_image_array(  
           image_np,  
           np.squeeze(boxes),  
           np.squeeze(classes).astype(np.int32),  
           np.squeeze(scores),  
           category_index,  
           use_normalized_coordinates=True,  
           line_thickness=8)  
       resp = '{},{}'.format(int(round(np.squeeze(boxes)[0][1]*width)), int(round(np.squeeze(boxes)[0][0]*height)))

   print(conn.recvline())  
   conn.sendline(bytearray(resp, 'utf8'))  
print(conn.recvrepeat(timeout=2))  
```  
After five images we got:

flag: **BSidesTLV2021{Here_1s_wally_lets_throw_ML_on_him}**

#### P.S.  
It was also possible to solve it manually. We know of another team who
downloaded all the images, and solved them "by hand" (well, by eye).

Original writeup (https://jctf.team/).