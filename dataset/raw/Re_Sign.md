# problem  
[Re_Sign.zip](./Re_Sign.zip)  
# exp  
```  
int main()  
{  
	int int32_41E3D0[] = { 8, 59, 1, 32, 7, 52, 9, 31, 24, 36, 19, 3, 16, 56, 9, 27, 8, 52, 19, 2, 8, 34, 18, 3, 5, 6, 18, 3, 15, 34, 18, 23, 8, 1, 41, 34, 6, 36, 50, 36, 15, 31, 43, 36, 3, 21, 65, 65 };  
	char str_41E499[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";  
	char base64_C[49] = {0};  
	for (int i = 0; i < 48; i++)  
	{  
		int temp_index = int32_41E3D0[i];  
		base64_C[i] = str_41E499[temp_index - 1];

	}  
	cout <<"base64_C:"<< base64_C << endl;

	char psss_list[65] = { 0 };  
	char list_41E380[] = { 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 91, 92, 73, 95, 90, 86, 69, 88, 93, 67, 85, 70, 82, 81, 95, 81, 80, 80, 80, 71, 70, 92, 118, 99, 108, 110, 85, 82, 67, 85, 92, 80, 95, 66, 67, 93, 79, 92, 84, 87, 85, 91, 94, 94, 90, 77, 64, 90, 76, 89, 82, 80, 21, 16 };  
	for (int i = 0; i <64; i++)  
	{  
		psss_list[i] = list_41E380[i] ^ i;  
	}  
	cout << "psss_list:" << psss_list << endl;  
  
	char str_re[100] = {0};  
	Base64_decode(base64_C, psss_list, str_re);  
	cout << "flag:" << str_re << endl;

  
	getchar();

	return 0;  
}  
```

# output  
```  
base64_C:H6AfGzIeXjSCP3IaHzSBHhRCEFRCOhRWHAohFjxjOeqjCU==  
psss_list:0123456789QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm+/  
flag:de1ctf{E_L4nguag3_1s_K3KeK3_N4Ji4}

```  

Original writeup (https://github.com/De1ta-
team/De1CTF2019/tree/master/writeup/re/Re_Sign).