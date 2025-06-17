# Admin CLI

* remote

## Description

> A (very) early version of the administration tool used for FE-CTF was found.
> Looks like they only just started making  
> it, but maybe it's already vulnerable?

```shell  
nc admin-cli.hack.fe-ctf.dk 1337  
```

---

## Challenge

We are given a Java class file, `Main.class`, a Dockerfile that runs the class
file, and a netcat command to connect to  
the server where the Docker container is running.

Looking at the Dockerfile, the first intention is that it seems to be a
Log4shell challenge, since it uses the  
vulnerable Log4j version 2.14.1.

```dockerfile  
RUN wget http://archive.apache.org/dist/logging/log4j/2.14.1/apache-
log4j-2.14.1-bin.zip  
RUN unzip apache-log4j-2.14.1-bin.zip  
```

However, looking at the Java class file, it seems not necessary to exploit the
Log4j vulnerability, since the class file  
simply replaces ``API_KEY`` with the flag.

```java  
public class Main {

	/* flag{....} */  
	private static String API_KEY = Base64.getUrlEncoder().encodeToString(System.getenv("FLAG").getBytes());  
  
	/* Doesn't seem to be authorized, I don't know why... */  
	/* https://backend.fe-ctf.local/removePoints?teamId=0&amount=1000&key=api_key */  
	private static int HASH_CODE = -615519892;

	/* Should be safe, right? */  
	private static Logger logger = LogManager.getLogger(Main.class);  
  
	public static void main(String[] args) {  
		Configurator.setLevel(Main.class.getName(), Level.INFO);  
		Scanner s = new Scanner(System.in);  
		System.out.print("Enter URL: ");  
		String input = s.nextLine();  
		s.close();  
		try {  
			URL url = new URL(input.replaceAll("API_KEY", API_KEY));  
			if (url.hashCode() == HASH_CODE && url.getHost().equals("backend.fe-ctf.local")) {  
logger.info("URLs Matched, sending request to {}", url);  
				/* TODO: Figure out how to send request  
				HttpURLConnection con = (HttpURLConnection) url.openConnection();  
				con.setRequestMethod("GET")  
				*/  
			} else {  
				logger.warn("URLs are not equal!");  
			}  
		} catch (MalformedURLException e) {  
			logger.error("Invalid URL");  
			System.exit(1);  
		}  
	}  
}  
```

At a second glance it looks more like a hash collision challenge. The class
file takes a URL as input,  
replaces ``API_KEY`` with the flag, and then checks if the hash code of the
URL is equal to ``-615519892`` and if the  
host is ``backend.fe-ctf.local``. If both conditions are true, it will log the
URL.

So the goal is to create a URL that has the same hash code as ``-615519892``
and has ``backend.fe-ctf.local`` as host.  
The URL also needs to contain the flag, so we can see it in the logging
message.

The hash code is taken from the ``java.net.URL`` class, which uses the
following hash function:

```java  
protected int hashCode() {  
   int h = 0;

   // Generate the protocol part.  
   String protocol = u.getProtocol();  
   if (protocol != null) h += protocol.hashCode();

   // Generate the host part.  
   String host = u.getHost();  
   if (host != null) h += host.toLowerCase().hashCode();

   // Generate the file part.  
   String file = u.getFile();  
   if (file != null) h += file.hashCode();

   // Generate the port part.  
   if (u.getPort() == -1) h += u.getDefaultPort();  
   else h += u.getPort();

   // Generate the ref part.  
   String ref = u.getRef();  
   if (ref != null) h += ref.hashCode();

   return h;  
}  
```

After some testing around with the hash function, we realized that the hash
code function does not take the authority  
part of the URL into account.

By simply setting the authority part of the URL to ``API_KEY``, we can create
a URL with a hash code independent of the  
flag.

Luckily in the comments of the class file, we can find a URL that has the hash
code ``-615519892``:

```java  
/* https://backend.fe-ctf.local/removePoints?teamId=0&amount=1000&key=api_key
*/  
```

So by just taking that URL and adding the authority we can get the flag.

```  
https://[email protected]/removePoints?teamId=0&amount=1000&key=api_key  
```

## Useful links

* https://en.wikipedia.org/wiki/Uniform_Resource_Identifier

## Alternative solutions

## Option 1

During the CTF we also realized that the port changes the hash code by its
exact value.

```java  
// Generate the port part.  
if (u.getPort() == -1) h += u.getDefaultPort();  
else h += u.getPort();  
```

So it would be possible to just calculate the difference between the url hash
code and the target hash code and then add  
the difference as the port. This opens up the possibility to craft a URL that
abuses the Log4j vulnerability.

## Option 2

After the CTF we came across a writeup that used the fact that apparently
already when creating the URL object, a DNS  
lookup is performed. So it is possible to create a URL that contains
``API_KEY`` as a subdomain which will be replaced  
by the flag and then the DNS request will just leak the flag in the subdomain
as the hostname ist first checked after  
the URL object is created.

```java  
URL url = new URL(input.replaceAll("API_KEY", API_KEY));  
if (url.hashCode() == HASH_CODE && url.getHost().equals("backend.fe-
ctf.local")) {  
```