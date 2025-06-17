# warmup-rev

## Description:  
```  
Time to get warmed up!  
```

## Files:  
- [WarmupRev.java](WarmupRev.java)

We are given a Java source code, the main function:  
```java  
public static void main(String[] args) {  
	Scanner in = new Scanner(System.in);  
	System.out.print("Let's get warmed up! Please enter the flag: ");  
	String flag = in.nextLine();  
	String match = "4n_3nd0th3rm1c_rxn_4b50rb5_3n3rgy";  
	if (flag.length() == 33 && hot(warm(cool(cold(flag)))).equals(match))  
		System.out.println("You got it!");  
	else  
		System.out.println("That's not correct, please try again!");  
	in.close();  
}  
```  
Hmm.. looks like our input is passed into 4 different function

If the output matches the `match` string then is the correct flag

We gonna try to reverse the four function first

## Reverse functions  
1. The `hot` function just change `+` to `-`:

Before | After  
--- | ---  
`s += (char) (t.charAt(i) + adj[i]);` | `s += (char) (t.charAt(i) - adj[i]);`

2. The `cool` function just also change `+` to `-`:

Before | After  
--- | ---  
`s += (char) (t.charAt(i) + 3 * (i / 2));` | `s += (char) (t.charAt(i) - 3 * (i / 2));`

3. The `cold` function just swapping the text, we still need to change the index number because the flag character is the even (total 33)

Before | After  
--- | ---  
`return t.substring(17) + t.substring(0, 17);` | `return t.substring(16) + t.substring(0, 16);`

4. The `warm` function abit tricky, it search for the two `l` character index then take the substring and reverse the order (end + `l` to 2nd `l` + start to `l`)  
- We have no idea what is the index of `l` after it pass `cold` and `cool` function.  
- So I decide to brute force the index, I change the function to brute force:  
```java  
public static String warm(String t,int x,int y) {  
	String a = t.substring(0, x + 1);  
	String t1 = t.substring(x + 1);  
	String b = t1.substring(0, y + 1);  
	String c = t1.substring(y + 1);  
	return c + b + a;  
}  
```

## Solve  
I make a copy of the program and name it [Solve.java](Solve.java)

Then change the class name to `Solve` then u can compile and execute it:  
```sh  
javac Solve.java && java Solve  
```  
Then after reverse those functions, change main to execute the function
reversely and brute force the index in `warm`:  
```java  
public static void main(String[] args) {  
	String match = "4n_3nd0th3rm1c_rxn_4b50rb5_3n3rgy";  
	for (int i=0;i<=17 ;i++ ) {  
		for (int j=0;j<=17 ;j++ ) {  
			System.out.println(cold(cool(warm(hot(match),i,j))));  
		}  
	}  
}  
```  
Compile and run it!

Search for flag in the output:  
```  
?uDG[J\~H3Gw>:?gL1c3RsQ_On}ydk  
]_,y,}]l?nPh?l:L1`-[j]S^_gyV0  
GG^J_~K3JwA:Bgl1Lc3UsT_Rnygk?u  
/y/}`l?nSh?l=?Lc0[m]V^bjyY0`_  
...  
...  
2}ag{1ncr34s3_1n_~l0nqh1lmy\0c_2y  
e~ag{1ncr34s3_1n_l3kwb:cymk!uMGdJ  
flag{1ncr34s3_1n_3nth4lpy_0f_5y5}  
```  
Thats the flag! Easy reverse challenege!

Verify the flag:  
```bash  
javac WarmupRev.java && java WarmupRev  
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true  
Let's get warmed up! Please enter the flag: flag{1ncr34s3_1n_3nth4lpy_0f_5y5}  
You got it!  
```  
## Flag  
```  
flag{1ncr34s3_1n_3nth4lpy_0f_5y5}  
```

Original writeup (https://github.com/Hong5489/hsctf2021/tree/main/warmup).