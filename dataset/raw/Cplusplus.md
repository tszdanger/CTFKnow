[中文](./README_zh.md) [English](./README.md)  
## Cplusplus

> source code : `Cplusplus.exe`  
>  
> problem : `Cplusplus.exe`  
>  
> compile : `compile.txt`  

### analyze

```C++  
struct st {  
	unsigned short num1;  
	unsigned short num2;  
	unsigned short num3;  
};

st boostFn(const std::string& s) {  
	using boost::spirit::qi::_1;  
	using boost::spirit::qi::ushort_;  
	using boost::spirit::qi::char_;  
	using boost::phoenix::ref;

	struct st res;  
	const char* first = s.data();  
	const char* const end = first + s.size();  
	bool success = boost::spirit::qi::parse(first, end,  
		ushort_[ref(res.num1) = _1] >> char('@')  
		>> ushort_[ref(res.num2) = _1] >> char('#')  
		>> ushort_[ref(res.num3) = _1]  
	);

	if (!success || first != end) {  
		//throw std::logic_error("Parsing failed");  
		_exit(0);  
	}  
	return res;  
}  
```

This code is related to `boost::spirit`. The input is such as
`num1@num2#num3`, and the three `unsigned short` values are separated by `@
#`.

```C++  
void boostFunc(unsigned short& num) {  
	//random number check  
	//The expected num is 78  
	if (num > 111) {  
		_exit(0);  
	}  
	boost::mt19937 rng(num);  
	rng.discard(num % 12);  
	//Copy Construction, retain all the state  
	boost::mt19937 rng_(rng);  
	rng_.discard(num / 12);  
	//discarding num random results  
	if (rng_() != 3570126595) {  
		_exit(0);  
	}  
	num -= (rng_() % 45);	// 45  
}  
```

An `unsigned short` is passed in, less than or equal to 111. It is used as the
seed of the random engine, discarding `num % 12` random numbers, and then
constructing a random engine copy.

> Note that the copy construct here completely preserves the state of the
> random engine, not the initial state.  
>  
> In IDA, it behaves as a direct memcpy

Then discard the `num/12` random numbers.

Then output a random number requirement equal to `3570126595`, and finally the
value passed in is changed because it is a reference.

There is nothing to say in the second check .

The third check is my mistake

```C++  
if ((res.num3 % res.num1 != 12) && (res.num3 / res.num1) != 3) {  
		//3 * 34 + 12 == 114  
		std::cout << "You failed...again";  
		_exit(0);  
	}  
```

There have been many solutions here, and later I found out that `||` was
mistakenly written as `&&`, so as long as the formula on the right is
satisfied, the flag will be output, and finally `md5` will be guaranteed to
guarantee the unique solution.

This is my mistake, I am sincerely sorry.  

Original writeup (https://github.com/De1ta-
team/De1CTF2019/tree/master/writeup/re/Cplusplus).