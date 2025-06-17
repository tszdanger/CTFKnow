[中文](./README_zh.md) [English](./README.md)  
## evil_boost

> source code : `evil_boost.cpp`  
>  
> problem : `evil_boost.exe`  
>  
> compile : `compile.txt`

### analyze

```C++  
#include<boost/phoenix/phoenix.hpp>  
#include<iostream>  
#include<string>  
#include<string.h>

namespace opt = boost::program_options;

using namespace std;  
using namespace boost::spirit;  
using namespace phoenix;

int main(int argc, char** argv) {  
	std::cout << "Have you input your name??" << std::endl;  
	opt::options_description desc("All options");  
	desc.add_options()  
		("cplusplus,cpp", opt::value<int>()->default_value(99), "your C++ grades")  
		("python,py", opt::value<int>()->default_value(88), "your python grades")  
		("javascript,js", opt::value<int>()->default_value(77), "your javascript grades")  
		("name", opt::value<std::string>(), "your name")  
		("help", "produce help message");  
	opt::variables_map vm;  
	//Parse command line options and store values to "vm"  
	opt::store(opt::parse_command_line(argc, argv, desc), vm);  
	opt::notify(vm);  
```

Parse command line options and store values to "vm"

```C++  
if (vm.count("name")) {  
		std::string __name = vm["name"].as<std::string>();  
		char c1 = vm["cplusplus"].as<int>();  
		char c2 = vm["python"].as<int>();  
		char c3 = vm["javascript"].as<int>();

		if (vm["cplusplus"].as<int>() == 999) {  
			if (vm["python"].as<int>() == 777) {  
				if (vm["javascript"].as<int>() == 233) {  
					unsigned char enc_false_flag[25] = {  
						0x4c,0x70,0x71,0x6b,0x38,0x71,0x6b,0x38,0x6c,  
						0x70,0x7d,0x38,0x6f,0x6a,0x77,0x76,0x7f,0x38,  
						0x7e,0x74,0x79,0x7f,0x36,0x36,0x36  
					};  
					for (int i = 0; i < 25; i++) {  
						if (((unsigned char)__name[i] ^ (char)(c1 + c2 * c3)) != enc_false_flag[i]) {  
							std::cout << "error" << std::endl;  
							_exit(i);  
						}  
					}  
				}  
				std::cout << "You get the flag! flag{" << __name << "}" << std::endl;  
				//flag{This is the wrong flag...}  
			}  
		}  
	}  
```

If you input the "name", you will get cpp, python, JavaScript scores, then
decrypt the flag, and finally output a fake flag

```C++  
/* Calculate expression related */  
	//Prepare a val variable for rule, type is double  
	//Accurately say: is a phoenix class, it and other phoenix class constitute a lambda expression, can be seen as a double in the lambda  
	struct calc_closure :boost::spirit::closure<calc_closure, double> {  
		member1 val;  
	};  
	//Define the ContextT policy as calc_closure::context_t  
	rule<phrase_scanner_t, calc_closure::context_t> factor, term, exp;  
	//Directly use phoenix lambda expression as an actor  
	factor = real_p[factor.val = arg1] | ('(' >> exp[factor.val = arg1] >> ')');  
	term = factor[term.val = arg1] >> *(('*' >> factor[term.val *= arg1]) | ('/' >> factor[term.val /= arg1]));  
	exp = term[exp.val = arg1] >> *(('+' >> term[exp.val += arg1]) | ('-' >> term[exp.val -= arg1]));

	const char* szExp = vm["name"].as<std::string>().c_str();  
	double result;  
	parse_info<>r = parse(szExp, exp[assign_a(result)], space_p);  
```

The key code is as above, calculate the value of the expression in name

```C++  
// 5e0*(5-1/5)==24

	if (strlen(szExp) != 11) {  
		_exit(strlen(szExp));  
	}

	int count_num = 0;  
	int count_alpha = 0;

	for (int i = 0; i < strlen(szExp); i++) {  
		if ((szExp[i] < '9') && (szExp[i] >= '0')) {  
			count_num++;  
		}  
		else if ((szExp[i] > 'a') && (szExp[i] < 'z')) {  
			count_alpha++;  
		}  
		else if ((szExp[i] > 'A') && (szExp[i] < 'Z')) {  
			std::cout << "GG..." << std::endl;  
			Sleep(100000000);  
		}  
		else if ((szExp[i] != '-') && (szExp[i] != '*') && (szExp[i] != '(')  
			&& (szExp[i] != ')') && (szExp[i] != '/')) {  
			_exit(-1);  
		}  
	}

	//Can only have 5 numbers and 1 lowercase letter, which is 'e'  
	if ((count_num != 5) || (count_alpha != 1)) {  
		_exit(count_num);  
	}  
	else {  
		if ((szExp[1] < 'a') || (szExp[1] > 'z')) {  
			Sleep(10000000);  
			std::cout << "You failed!" << std::endl;  
		}  
	}

	if (result - 24 < 0.0000001 || result - 24 > 0.0000001) {  
		std::cout << "You finally get sth." << std::endl;  
		std::cout << "Maybe you missed a code branch..." << std::endl;  
		std::cout << "MD5 is 293316bfd246fa84e566d7999df88e79,You should check it!" << std::endl;  
		std::cout << "de1ctf{" << vm["name"].as<std::string>() << "}" << std::endl;  
	}  
```

Length is 11,5 digits, 1 lowercase letter (only e)

Because only multiplication,minus and division can be used, 5551 is relatively
easy to think of, but it is not excluded that there may be other solutions,so
give md5  

According to the calculation of the floating point number `(result - 24 <
0.0000001 || result - 24 > 0.0000001)` it is easy to reverse the calculation
is to calculate 24 points, the "name" is flag  

Original writeup (https://github.com/De1ta-
team/De1CTF2019/tree/master/writeup/re/Evil_boost).