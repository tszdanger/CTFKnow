# Hash My Awesome Commands

## Task

I found this strange server that only has two commands. Looks like there's a
command to get the  
flag, but I can't figure out how to get it to work. It did come with a strange
note that had  
**9W5iVNkvnM6igjQaWlcN0JJgH+7pComiQZYdkhycKjs=** written on it. Maybe that's
important?

nc challenges.2020.squarectf.com 9020

File: hmac.go

## Solution

We are given this file (I have removed some parts to make it shorter):

```golang  
type HmacVerifier struct {  
       codes map[string][]byte  
}

func (h *HmacVerifier) verifyHmac(message string, check []byte) bool {  
       start := time.Now()  
       match := compare(h.codes[message], check)  
       verifyTime := time.Since(start).Nanoseconds()

       if debug {  
               fmt.Printf("took %d nanoseconds to verify hmac\n", verifyTime)  
       }

       return match  
}

func newHmacWrapper(key []byte) HmacVerifier {  
       codes := map[string][]byte{}

       h := hmac.New(sha256.New, key)  
       for _, command := range commands {  
               h.Write([]byte(command))  
               codes[command] = h.Sum(nil)  
               h.Reset()  
       }

       return HmacVerifier{codes: codes}  
}

func main() {  
       key, err := ioutil.ReadFile("data/hmac_key")  
       if err != nil {  
               fmt.Printf("unable to load key: %v", err)  
               return  
       }  
       hmacWrapper := newHmacWrapper(key)

       reader := bufio.NewReader(os.Stdin)

       for {  
               fmt.Print("Enter command: ")  
               input, err := reader.ReadString('\n')  
               if err != nil {  
                       fmt.Printf("unable to read input: %v\n", err)  
                       return  
               }

               input = strings.TrimSpace(input)  
               components := strings.Split(input, "|")  
               if len(components) < 2 {  
                       fmt.Println("command must contain hmac signature")  
                       continue  
               }

               command := components[0]  
               check, err := base64.StdEncoding.DecodeString(components[1])  
               if err != nil {  
                       fmt.Println("hmac must be base64")  
                       continue  
               }

               if debug {  
                       fmt.Printf("command: %s, check: %s\n", command, components[1])  
               }

               if !contains(commands, command) {  
                       fmt.Println("invalid command")  
                       continue  
               }

               if !hmacWrapper.verifyHmac(command, check) {  
                       fmt.Println("invalid hmac")  
                       continue  
               }

               switch command {  
               case "debug":  
                       debug = !debug  
               case "flag":  
                       flag, _ := ioutil.ReadFile("data/flag")  
                       fmt.Println(string(flag))  
               }  
       }  
}

func compare(s1, s2 []byte) bool {  
       if len(s1) != len(s2) {  
               return false  
       }

       c := make(chan bool)

       // multi-threaded check to speed up comparison  
       for i := 0; i < len(s1); i++ {  
               go func(i int, co chan<- bool) {  
                       // avoid race conditions  
                       time.Sleep(time.Duration(((500*math.Pow(1.18, float64(i+1)))-500)/0.18) * time.Microsecond)  
                       co <- s1[i] == s2[i]  
               }(i, c)  
       }

       for i := 0; i < len(s1); i++ {  
               if <-c == false {  
                       return false  
               }  
       }

       return true  
}  
```

We can enter as many commands as we want, but we need to provide
`command|base64(hmac(command))`. Since the task mentions a base64-string we
try to use that to enable debug-mode.

After that we get the output from `verifyHmac` like `took 700234 nanoseconds
to verify hmac`.

The verification uses the compare function.

Inside there for each byte a goroutine is started and delay by a specific
amount, to `avoid race conditions`.

That's not how you avoid race conditions and additionally: If we provide a
`base64(hmac("flag"))` whose first byte is wrong, we will get the debug output
earlier together with the time it took. So we just need to calculate the delay
for each position and bruteforce it one-by-one.

```golang  
package main

import (  
       "bufio"  
       "encoding/base64"  
       "log"  
       "math"  
       "net"  
       "strconv"  
       "strings"  
)

var (  
       cReader *bufio.Reader  
       conn    net.Conn  
)

const (  
       enableDebug = "debug|9W5iVNkvnM6igjQaWlcN0JJgH+7pComiQZYdkhycKjs="  
)

func check(err error) {  
       if err != nil {  
               log.Fatal(err)  
       }  
}

func readPrompt(c byte) {  
       line, err := cReader.ReadString(c)  
       check(err)  
       log.Println(line)  
}

func writeCommand(c string) {  
       _, err := conn.Write([]byte(c + "\n"))  
       check(err)  
}

func baseCommand(c string, b []byte) {  
       writeCommand(c + "|" + base64.StdEncoding.EncodeToString(b))  
}

func main() {  
       // calculate all delays  
       times := make([]float64, 33)  
       for i := 0; i < 33; i++ {  
               times[i] = ((500*math.Pow(1.18, float64(i+1)) ) - 500) / 0.18  
       }

       var err error  
       conn, err = net.Dial("tcp", "challenges.2020.squarectf.com:9020")  
       check(err)

       cReader = bufio.NewReader(conn)  
       // the base64-decoded byte-string is 32 bytes long  
       attempt := make([]byte, 32)  
       // we start at position 0  
       pos := 0

       readPrompt(':')  
       writeCommand(enableDebug + "\n")  
       readPrompt(':')  
       baseCommand("flag", attempt)

       for {  
               line, _, err := cReader.ReadLine()  
               check(err)

               lineStr := string(line)

               // these are the lines with the timing debug  
               if strings.HasPrefix(lineStr, "took ") {  
                       timeStr := strings.TrimSuffix(strings.TrimPrefix(lineStr, "took "), " nanoseconds to verify hmac")

                       timeInt, err := strconv.Atoi(timeStr)  
                       check(err)

                       timeMicro := float64(timeInt) / 1000

                       // sometimes it takes longer without a reason  
                       if timeMicro < times[pos] {  
                               log.Println("Went on too quickly!")  
                               pos -= 1  
                       } else if timeMicro < times[pos + 1] {  
                               attempt[pos] += 1  
                               baseCommand("flag", attempt)  
                               log.Println("Trying", attempt[pos], "at pos", pos, "with", attempt)  
                       } else {  
                               log.Println("I think I've found it! At:", pos, attempt)  
                               pos += 1  
                               baseCommand("flag", attempt)  
                       }

                       // this is just to verify it's operation normally  
                       log.Println(int(times[pos]), int(timeMicro), int(times[pos+1]))  
               } else {  
                       // after bruteforcing all 32 bytes, this prints the flag  
                       log.Println(lineStr)  
               }  
       }  
}  
```

Running it:

```bash  
...  
2020/11/14 03:04:49 Trying 162 at pos 31 with [157 208 40 75 60 127 9 184 179
78 163 65 7 151 51 222 222 151 24 81 6 109 12 8 115 216 187 73 172 32 76 162]  
2020/11/14 03:04:49 551747 551928 651562  
2020/11/14 03:04:49 flag{d1d_u_t4k3_the_71me_t0_appr3c14t3_my_c0mm4nd5}  
```  

Original writeup (https://github.com/klassiker/ctf-
writeups/blob/master/2020/square/hash-my-awesome-commands.md).