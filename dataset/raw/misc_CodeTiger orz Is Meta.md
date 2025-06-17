We get an image which doesn't have much information if you look at it
directly. So let's try to find information hidden inside the image. If we
upload the photo to [https://fotoforensics.com/](https://fotoforensics.com/),
we find that the title is `LITCTF{c0de_`, the description is `t1g2r_`, and
that the rights are `orz}` from the XMP metadata. We can assume that these are
the first, second, and third/last parts respectively, and we get that the flag
is `LITCTF{c0de_t1g2r_orz}`.

Alternatively, we can use the Unix (or Unix-like) utility `strings` to find
the XMP metadata itself in the image as XML:  
```xml

<x:xmpmeta xmlns:x='adobe:ns:meta/' x:xmptk='Image::ExifTool 12.36'>  
<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>  
<rdf:Description rdf:about=''  
 xmlns:dc='http://purl.org/dc/elements/1.1/'>  
 <dc:description>  
  <rdf:Alt>  
   <rdf:li xml:lang='x-default'>t1g2r_</rdf:li>  
  </rdf:Alt>  
 </dc:description>  
 <dc:rights>  
  <rdf:Alt>  
   <rdf:li xml:lang='x-default'>orz}</rdf:li>  
  </rdf:Alt>  
 </dc:rights>  
 <dc:title>  
  <rdf:Alt>  
   <rdf:li xml:lang='x-default'>LITCTF{c0de_</rdf:li>  
  </rdf:Alt>  
 </dc:title>  
</rdf:Description>  
</rdf:RDF>  
</x:xmpmeta>

```  
Note that I have replaced the place where there was binary data with `[BINARY
DATA]`. Also, note that we could have also used a text or hex editor to find
the XMP metadata too.

We can proceed in a similar fashion as the first way to find the flag.