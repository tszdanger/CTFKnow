Hackover CTF 2018: Holy Graal  
=============================

## Description

Everybody keeps talking about this new JIT. I think it is more secure,
wouldn't you agree?

compiled with: `native-image -H:+ReportUnsupportedElementsAtRuntime`

Try our service at:

`nc holy-graal.ctf.hackover.de 1337`

`main.clj`:  
```clojure  
(ns main  
 (:require [clojure.java.shell :as shell])  
 (:gen-class))

;; We want to be sure none of our calls relies on reflection.  
(set! *warn-on-reflection* 1)

(defmulti option identity)  
(defmethod option "1" [_]  
 (try  
   (-> (read-line)  
       (read-string))  
   (println "Good job, you know how to balance brackets. Now go, get the
flag.")  
   (catch Exception e  
     (println "You need to work on your balancing skills."))))

(defmethod option "2" [_]  
 (println "Exiting.")  
 (System/exit 0))

(defmethod option :default [_]  
 (println "Invalid choice."))

(defn- print-options []  
 (println "1: Send string")  
 (println "2: Exit"))

(defn- get-graal-version []  
 (->> (clojure.java.shell/sh "native-image" "--version")  
      :out  
      clojure.string/trim-newline  
      (re-find #"\d.\d.\d-\w+")))

(defn -main []  
 (println "Welcome to HolyGraal version" (get-graal-version))  
 (println "Everybody knows that keeping track of brackets is hard in LISP
languages.")  
 (println "We now introduce: verify brackets as a service.")  
 (print-options)  
 (loop [input (read-line)]  
   (option input)  
   (print-options)  
   (recur (read-line))))  
```

## Solution

The server is running a Clojure script that checks that the input has balanced  
brackets. The script works by reading a line and then passing the result to  
`read-string`, then reporting an error if any exceptions are thrown.

From [the documentation of read-
string](https://clojuredocs.org/clojure.core/read-string):

```  
Reads one object from the string s. Optionally include reader  
options, as specified in read.

Note that read-string can execute code (controlled by *read-eval*),  
and as such should be used only with trusted sources.  
```

It appears that the server is evaluating our input, which will raise an  
exception if the brackets are unbalanced (because it's a syntax error).

By googling a bit we found an exploit POC which we adapted to execute shell  
commands and show us their output.

Final exploit code: `#=(println #=(clojure.java.shell/sh "cat" "flag.txt"))`

Flag: `hackover18{n3v3r_tru5s7_u53r_1npu7}`  

Original writeup (https://github.com/ctf-
epfl/writeups/tree/master/hackover18/holy-graal).